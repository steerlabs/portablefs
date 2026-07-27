import { describe, expect, it } from "vitest";
import {
  Pft2InodeAllocator,
  composeIno,
  formatUint64Decimal,
  parseUint64Decimal,
  splitIno,
} from "./ino.js";
import {
  PFT2_MAX_INO,
  PFT2_MAX_INODE_LOCAL_COUNTER,
  PFT2_MAX_INODE_NAMESPACE,
  Pft2InodeCounterExhaustedError,
  Pft2InodeNamespaceExhaustedError,
  Pft2InvalidNodeError,
} from "./types.js";

describe("pft2 inode namespace helpers", () => {
  it("composes and splits without ever using JS numbers for the id", () => {
    expect(composeIno(1, 1n)).toBe((1n << 32n) | 1n);
    const max = composeIno(PFT2_MAX_INODE_NAMESPACE, PFT2_MAX_INODE_LOCAL_COUNTER);
    expect(max).toBe(PFT2_MAX_INO);
    expect(splitIno(max)).toEqual({
      namespace: PFT2_MAX_INODE_NAMESPACE,
      localCounter: PFT2_MAX_INODE_LOCAL_COUNTER,
    });
    expect(splitIno(1n)).toEqual({ namespace: 0, localCounter: 1n });

    expect(() => composeIno(0, 1n)).toThrow(Pft2InodeNamespaceExhaustedError);
    expect(() => composeIno(PFT2_MAX_INODE_NAMESPACE + 1, 1n)).toThrow(
      Pft2InodeNamespaceExhaustedError
    );
    expect(() => composeIno(1, 0n)).toThrow(Pft2InodeCounterExhaustedError);
    expect(() => composeIno(1, PFT2_MAX_INODE_LOCAL_COUNTER + 1n)).toThrow(
      Pft2InodeCounterExhaustedError
    );
    expect(() => splitIno(0n)).toThrow(Pft2InvalidNodeError);
    expect(() => splitIno(PFT2_MAX_INO + 1n)).toThrow(Pft2InvalidNodeError);
    expect(() => splitIno(5n << 32n)).toThrow(Pft2InvalidNodeError);
  });

  it("allocates sequentially and fails typed and terminal on exhaustion", () => {
    const alloc = new Pft2InodeAllocator(9, 1n);
    expect(alloc.allocate()).toBe((9n << 32n) | 1n);
    expect(alloc.allocate()).toBe((9n << 32n) | 2n);
    expect(alloc.nextLocal).toBe(3n);

    const brink = new Pft2InodeAllocator(9, PFT2_MAX_INODE_LOCAL_COUNTER);
    expect(brink.allocate()).toBe((9n << 32n) | PFT2_MAX_INODE_LOCAL_COUNTER);
    expect(() => brink.allocate()).toThrow(Pft2InodeCounterExhaustedError);
    expect(() => brink.allocate()).toThrow(Pft2InodeCounterExhaustedError);
    expect(brink.nextLocal).toBe(PFT2_MAX_INODE_LOCAL_COUNTER + 1n);

    const resumed = new Pft2InodeAllocator(9, brink.nextLocal);
    expect(() => resumed.allocate()).toThrow(Pft2InodeCounterExhaustedError);

    expect(() => new Pft2InodeAllocator(0, 1n)).toThrow(Pft2InodeNamespaceExhaustedError);
    expect(() => new Pft2InodeAllocator(1, 0n)).toThrow(Pft2InvalidNodeError);
    expect(() => new Pft2InodeAllocator(1, PFT2_MAX_INODE_LOCAL_COUNTER + 2n)).toThrow(
      Pft2InvalidNodeError
    );
  });

  it("round-trips canonical decimals and rejects non-canonical forms", () => {
    const cases: [string, bigint][] = [
      ["0", 0n],
      ["7", 7n],
      ["4294967296", 1n << 32n],
      ["9223372036854775807", PFT2_MAX_INO],
      ["18446744073709551615", (1n << 64n) - 1n],
    ];
    for (const [text, value] of cases) {
      expect(parseUint64Decimal(text)).toBe(value);
      expect(formatUint64Decimal(value)).toBe(text);
    }
    for (const bad of [
      "",
      "00",
      "01",
      "-1",
      "+1",
      " 1",
      "1 ",
      "1.5",
      "1a",
      "0x10",
      "18446744073709551616",
      "184467440737095516150",
    ]) {
      expect(() => parseUint64Decimal(bad), bad).toThrow();
    }
    expect(() => formatUint64Decimal(-1n)).toThrow(Pft2InvalidNodeError);
    expect(() => formatUint64Decimal(1n << 64n)).toThrow(Pft2InvalidNodeError);
  });
});
