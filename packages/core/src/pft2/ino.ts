/**
 * Stable inode allocation helpers — the TypeScript mirror of
 * vcs/internal/pft2/ino.go. Inode and allocator values are bigint end to end
 * and cross JSON boundaries as canonical ASCII decimal strings, never as
 * JavaScript numbers.
 */
import {
  PFT2_MAX_INO,
  PFT2_MAX_INODE_LOCAL_COUNTER,
  PFT2_MAX_INODE_NAMESPACE,
  Pft2InodeCounterExhaustedError,
  Pft2InodeNamespaceExhaustedError,
  invalidNode,
} from "./types.js";

const LOCAL_MASK = (1n << 32n) - 1n;

/**
 * Composes a stable inode id: ino = (namespace << 32) | localCounter.
 * namespace is 1..PFT2_MAX_INODE_NAMESPACE (0 is reserved for inode 1 and
 * verified legacy ids); localCounter is 1..PFT2_MAX_INODE_LOCAL_COUNTER. The
 * result is positive and fits a PostgreSQL signed BIGINT. Out-of-range
 * inputs throw the typed terminal exhaustion errors; nothing wraps.
 */
export function composeIno(namespace: number, localCounter: bigint): bigint {
  if (!Number.isInteger(namespace) || namespace < 1 || namespace > PFT2_MAX_INODE_NAMESPACE) {
    throw new Pft2InodeNamespaceExhaustedError(
      `namespace ${namespace} outside 1..${PFT2_MAX_INODE_NAMESPACE}`
    );
  }
  if (localCounter < 1n || localCounter > PFT2_MAX_INODE_LOCAL_COUNTER) {
    throw new Pft2InodeCounterExhaustedError(
      `namespace ${namespace} local counter ${localCounter} outside 1..${PFT2_MAX_INODE_LOCAL_COUNTER}`
    );
  }
  return (BigInt(namespace) << 32n) | localCounter;
}

/**
 * Decomposes an inode id into { namespace, localCounter }. Namespace 0
 * identifies inode 1 and verified legacy inode ids.
 */
export function splitIno(ino: bigint): { namespace: number; localCounter: bigint } {
  if (ino < 1n || ino > PFT2_MAX_INO) {
    throw invalidNode(`ino ${ino} outside 1..${PFT2_MAX_INO}`);
  }
  const namespace = Number(ino >> 32n);
  const localCounter = ino & LOCAL_MASK;
  if (namespace !== 0 && localCounter === 0n) {
    throw invalidNode(`ino ${ino} has namespace ${namespace} with local counter 0`);
  }
  return { namespace, localCounter };
}

/**
 * Sequential inode allocator for one branch namespace. Pure counter helper:
 * durability of nextLocal is the caller's problem.
 */
export class Pft2InodeAllocator {
  private readonly allocNamespace: number;
  private nextLocalCounter: bigint;

  constructor(namespace: number, nextLocal: bigint) {
    if (!Number.isInteger(namespace) || namespace < 1 || namespace > PFT2_MAX_INODE_NAMESPACE) {
      throw new Pft2InodeNamespaceExhaustedError(
        `namespace ${namespace} outside 1..${PFT2_MAX_INODE_NAMESPACE}`
      );
    }
    if (nextLocal < 1n || nextLocal > PFT2_MAX_INODE_LOCAL_COUNTER + 1n) {
      throw invalidNode(
        `namespace ${namespace} next local counter ${nextLocal} outside 1..${PFT2_MAX_INODE_LOCAL_COUNTER + 1n}`
      );
    }
    this.allocNamespace = namespace;
    this.nextLocalCounter = nextLocal;
  }

  get namespace(): number {
    return this.allocNamespace;
  }

  /** Next unassigned local counter (max+1 once exhausted), for persistence. */
  get nextLocal(): bigint {
    return this.nextLocalCounter;
  }

  /** Returns the next inode id; throws typed terminal error once exhausted. */
  allocate(): bigint {
    const ino = composeIno(this.allocNamespace, this.nextLocalCounter);
    this.nextLocalCounter += 1n;
    return ino;
  }
}

/**
 * Parses a canonical ASCII decimal uint64: digits only, no sign/whitespace,
 * no leading zeros (except exactly "0"), no overflow.
 */
export function parseUint64Decimal(value: string): bigint {
  if (value.length === 0 || value.length > 20) {
    throw invalidNode(`decimal ${JSON.stringify(value)} has invalid length`);
  }
  if (value.length > 1 && value.startsWith("0")) {
    throw invalidNode(`decimal ${JSON.stringify(value)} has a leading zero`);
  }
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code < 0x30 || code > 0x39) {
      throw invalidNode(`decimal ${JSON.stringify(value)} contains a non-digit`);
    }
  }
  const parsed = BigInt(value);
  if (parsed > (1n << 64n) - 1n) {
    throw invalidNode(`decimal ${JSON.stringify(value)} overflows uint64`);
  }
  return parsed;
}

/** Renders the canonical ASCII decimal form. */
export function formatUint64Decimal(value: bigint): string {
  if (value < 0n || value > (1n << 64n) - 1n) {
    throw invalidNode(`value ${value} outside uint64`);
  }
  return value.toString(10);
}
