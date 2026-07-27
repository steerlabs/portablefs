// Minimal PFR1 record-op sniffer for journal row CLASSIFICATION only.
//
// The exec/grep cut-reuse decision needs one bit per journal row — does the
// row change user-visible content, or is it control-only coordination
// (session establishment, flush watermarks, open pins, sync barriers)? The
// full PFR1 codec lives in Go; TypeScript deliberately never decodes record
// BODIES. The op, however, sits at a fixed early position in the canonical
// encoding — magic "PFR1", field 1 varint (seq), field 2 varint (op) — so a
// bounded prefix is enough. Anything unparseable classifies as CONTENT: the
// conservative direction, which can only cost a redundant cut, never a stale
// reuse.

/** wal.OpControl: replicated control metadata, never part of the user tree. */
export const PFR1_OP_CONTROL = 13;

const PFR1_MAGIC = [0x50, 0x46, 0x52, 0x31]; // "PFR1"
const TAG_FIELD1_VARINT = 0x08;
const TAG_FIELD2_VARINT = 0x10;

/**
 * Extracts the record op from a canonical PFR1 prefix (>= 27 bytes covers the
 * worst case: 4 magic + 1 tag + 10 varint + 1 tag + 10 varint). Returns null
 * when the prefix does not parse as expected.
 */
export function pfr1RecordOp(prefix: Uint8Array): number | null {
  if (prefix.length < 6) {
    return null;
  }
  for (let i = 0; i < 4; i += 1) {
    if (prefix[i] !== PFR1_MAGIC[i]) {
      return null;
    }
  }
  let offset = 4;
  if (prefix[offset] !== TAG_FIELD1_VARINT) {
    return null;
  }
  offset += 1;
  const seq = readVarint(prefix, offset);
  if (seq === null) {
    return null;
  }
  offset = seq.next;
  if (prefix[offset] !== TAG_FIELD2_VARINT) {
    return null;
  }
  offset += 1;
  const op = readVarint(prefix, offset);
  if (op === null || op.value > 0xffn) {
    return null;
  }
  return Number(op.value);
}

/** True when the row is control-only and cannot change user-visible content. */
export function pfr1ControlOnly(prefix: Uint8Array): boolean {
  return pfr1RecordOp(prefix) === PFR1_OP_CONTROL;
}

function readVarint(bytes: Uint8Array, start: number): { value: bigint; next: number } | null {
  let value = 0n;
  let shift = 0n;
  for (let i = start; i < bytes.length && i < start + 10; i += 1) {
    const b = bytes[i]!;
    value |= BigInt(b & 0x7f) << shift;
    if ((b & 0x80) === 0) {
      return { value, next: i + 1 };
    }
    shift += 7n;
  }
  return null;
}
