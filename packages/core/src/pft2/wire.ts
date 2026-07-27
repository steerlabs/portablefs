/**
 * Strict deterministic wire primitives for PFT2 — the TypeScript mirror of
 * the Go `pfwire` package. The encoding is protowire-shaped (field numbers +
 * wire types, varints, length-delimited bytes) but deliberately stricter than
 * protobuf: there is EXACTLY ONE valid byte representation for any value.
 *
 * Rules (identical to Go):
 * - Fields are emitted in strictly ascending field-number order; repeated
 *   fields re-present the same number contiguously.
 * - Defaults are never emitted (integer 0, false, empty bytes/string); an
 *   explicit default is rejected on decode.
 * - Varints are minimal, at most 10 bytes, and bounded to 64 bits.
 * - Signed integers use zigzag encoding.
 * - Booleans encode as varint 1 only.
 * - Only wire types 0 (varint) and 2 (length-delimited) exist.
 * - Unknown fields and trailing bytes are rejected.
 *
 * Every 64-bit value is a bigint; JavaScript numbers never carry wire
 * integers.
 */

export const WIRE_TYPE_VARINT = 0;
export const WIRE_TYPE_BYTES = 2;

const U64_MAX = (1n << 64n) - 1n;
const U32_MAX = 0xffffffffn;

/** Root classification for every strict-decode rejection. */
export class Pft2WireError extends Error {
  constructor(message: string) {
    super(`pft2 wire: ${message}`);
    this.name = "Pft2WireError";
  }
}

function wireError(what: string, message: string): Pft2WireError {
  return new Pft2WireError(`${what}: ${message}`);
}

/** Growable byte sink used by the encoders. */
export class ByteWriter {
  private buffer = new Uint8Array(256);
  private length = 0;

  private ensure(extra: number): void {
    if (this.length + extra <= this.buffer.length) {
      return;
    }
    let next = this.buffer.length * 2;
    while (next < this.length + extra) {
      next *= 2;
    }
    const grown = new Uint8Array(next);
    grown.set(this.buffer.subarray(0, this.length));
    this.buffer = grown;
  }

  pushByte(value: number): void {
    this.ensure(1);
    this.buffer[this.length] = value;
    this.length += 1;
  }

  pushBytes(bytes: Uint8Array): void {
    this.ensure(bytes.length);
    this.buffer.set(bytes, this.length);
    this.length += bytes.length;
  }

  finish(): Uint8Array {
    return this.buffer.slice(0, this.length);
  }

  get size(): number {
    return this.length;
  }
}

/** Appends v as a minimal varint. v must be 0..2^64-1. */
export function appendVarint(out: ByteWriter, v: bigint): void {
  if (v < 0n || v > U64_MAX) {
    throw new Pft2WireError(`varint value ${v} outside uint64`);
  }
  let rest = v;
  while (rest >= 0x80n) {
    out.pushByte(Number(rest & 0x7fn) | 0x80);
    rest >>= 7n;
  }
  out.pushByte(Number(rest));
}

/** Encoded size of v as a minimal varint. */
export function sizeVarint(v: bigint): number {
  let size = 1;
  let rest = v;
  while (rest >= 0x80n) {
    rest >>= 7n;
    size += 1;
  }
  return size;
}

/** Size of a length-delimited field with payload length n. */
export function sizeTagged(field: number, n: number): number {
  return sizeVarint((BigInt(field) << 3n) | BigInt(WIRE_TYPE_BYTES)) + sizeVarint(BigInt(n)) + n;
}

/** Maps a signed 64-bit value onto the unsigned varint space. */
export function zigzag(v: bigint): bigint {
  const signed = BigInt.asIntN(64, v);
  return BigInt.asUintN(64, (signed << 1n) ^ (signed >> 63n));
}

/** Inverts zigzag. */
export function unzigzag(u: bigint): bigint {
  return BigInt.asIntN(64, (u >> 1n) ^ -(u & 1n));
}

export function appendTag(out: ByteWriter, field: number, wireType: number): void {
  appendVarint(out, (BigInt(field) << 3n) | BigInt(wireType));
}

/** Emits field=v when v != 0 (default omission). */
export function appendUint(out: ByteWriter, field: number, v: bigint): void {
  if (v === 0n) {
    return;
  }
  appendTag(out, field, WIRE_TYPE_VARINT);
  appendVarint(out, v);
}

/** Emits field=v (zigzag) when v != 0. */
export function appendSint(out: ByteWriter, field: number, v: bigint): void {
  if (v === 0n) {
    return;
  }
  appendTag(out, field, WIRE_TYPE_VARINT);
  appendVarint(out, zigzag(v));
}

/** Emits field=b when b is non-empty. */
export function appendBytes(out: ByteWriter, field: number, b: Uint8Array): void {
  if (b.length === 0) {
    return;
  }
  appendTag(out, field, WIRE_TYPE_BYTES);
  appendVarint(out, BigInt(b.length));
  out.pushBytes(b);
}

const utf8Encoder = new TextEncoder();
const utf8StrictDecoder = new TextDecoder("utf-8", { fatal: true });

/** Canonical UTF-8 bytes of a string. */
export function utf8Encode(value: string): Uint8Array {
  return utf8Encoder.encode(value);
}

/** Strictly decodes UTF-8 (throws on invalid sequences). */
export function utf8DecodeStrict(bytes: Uint8Array): string {
  return utf8StrictDecoder.decode(bytes);
}

/** Raw byte-order comparison (the canonical PFT2 key order). */
export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const shared = Math.min(a.length, b.length);
  for (let i = 0; i < shared; i += 1) {
    if (a[i]! !== b[i]!) {
      return a[i]! < b[i]! ? -1 : 1;
    }
  }
  return a.length === b.length ? 0 : a.length < b.length ? -1 : 1;
}

/**
 * Strict sequential decoder over one message's bytes. Mirrors the Go
 * pfwire.Reader exactly, including ascending-field enforcement.
 */
export class WireReader {
  private pos = 0;
  private last = 0;

  constructor(
    private readonly what: string,
    private readonly buf: Uint8Array
  ) {}

  done(): boolean {
    return this.pos >= this.buf.length;
  }

  remaining(): number {
    return this.buf.length - this.pos;
  }

  malformed(message: string): Pft2WireError {
    return wireError(this.what, message);
  }

  private varint(): bigint {
    const start = this.pos;
    let value = 0n;
    let shift = 0n;
    for (;;) {
      if (this.pos >= this.buf.length) {
        throw this.malformed(`truncated varint at ${start}`);
      }
      const byte = this.buf[this.pos]!;
      this.pos += 1;
      if (shift === 63n && byte > 1) {
        throw this.malformed(`varint overflows 64 bits at ${start}`);
      }
      if (shift > 63n) {
        throw this.malformed(`varint too long at ${start}`);
      }
      value |= BigInt(byte & 0x7f) << shift;
      if (byte < 0x80) {
        if (byte === 0 && shift > 0n) {
          throw this.malformed(`non-minimal varint at ${start}`);
        }
        return value;
      }
      shift += 7n;
    }
  }

  /** Reads the next field header, or null at end of message. */
  next(): { field: number; wireType: number } | null {
    if (this.done()) {
      return null;
    }
    const tag = this.varint();
    const wireType = Number(tag & 7n);
    const field = tag >> 3n;
    if (field === 0n || field > U32_MAX) {
      throw this.malformed(`invalid field number ${field}`);
    }
    if (wireType !== WIRE_TYPE_VARINT && wireType !== WIRE_TYPE_BYTES) {
      throw this.malformed(`field ${field} has unsupported wire type ${wireType}`);
    }
    return { field: Number(field), wireType };
  }

  /** Enforces strictly ascending order for a singular field. */
  require(field: number): void {
    if (field <= this.last) {
      throw this.malformed(`field ${field} out of order or duplicated (last ${this.last})`);
    }
    this.last = field;
  }

  /** Enforces ordering for a repeated field (contiguous continuation). */
  requireRepeated(field: number): void {
    if (field === this.last) {
      return;
    }
    this.require(field);
  }

  /** Decodes a varint field value, rejecting the non-canonical explicit 0. */
  uint(field: number): bigint {
    const value = this.varint();
    if (value === 0n) {
      throw this.malformed(`field ${field} explicitly encodes default 0`);
    }
    return value;
  }

  /** Decodes a varint bounded to 32 bits, as a number. */
  uint32(field: number): number {
    const value = this.uint(field);
    if (value > U32_MAX) {
      throw this.malformed(`field ${field} value ${value} overflows uint32`);
    }
    return Number(value);
  }

  /** Decodes a zigzag varint, rejecting explicit 0. */
  sint(field: number): bigint {
    return unzigzag(this.uint(field));
  }

  /** Decodes a length-delimited field, rejecting the empty form. */
  bytes(field: number, max: number): Uint8Array {
    const length = this.varint();
    if (length === 0n) {
      throw this.malformed(`field ${field} explicitly encodes empty bytes`);
    }
    if (length > BigInt(max)) {
      throw this.malformed(`field ${field} length ${length} exceeds bound ${max}`);
    }
    const n = Number(length);
    if (this.remaining() < n) {
      throw this.malformed(`field ${field} truncated (${this.remaining()} of ${n} bytes)`);
    }
    const out = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  /** Decodes a UTF-8, NUL-free string field. */
  string(field: number, max: number): string {
    const raw = this.bytes(field, max);
    let value: string;
    try {
      value = utf8DecodeStrict(raw);
    } catch {
      throw this.malformed(`field ${field} is not valid UTF-8`);
    }
    for (const byte of raw) {
      if (byte === 0) {
        throw this.malformed(`field ${field} contains NUL`);
      }
    }
    return value;
  }

  rejectUnknown(field: number): Pft2WireError {
    return this.malformed(`unknown field ${field}`);
  }
}
