import { describe, expect, it } from "vitest";
import {
  ByteWriter,
  WIRE_TYPE_VARINT,
  appendBytes,
  appendTag,
  appendUint,
} from "./wire.js";
import { decodePft2Node, decodePft2NodeKind, encodePft2Node } from "./codec.js";
import {
  PFT2_MAGIC,
  PFT2_MAX_NODE_BYTES,
  PFT2_MIN_NODE_BYTES,
  Pft2CorruptError,
  Pft2FileKind,
  Pft2InvalidNodeError,
  Pft2NodeKind,
  pft2RefOf,
  validateEntryName,
  verifyObjectBytes,
  type Pft2Node,
} from "./types.js";
import { labelDigest, labelRef, sampleNodes } from "./golden-shared.js";

function nodeBody(fields: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + fields.length);
  out.set(PFT2_MAGIC);
  out.set(fields, 4);
  return out;
}

describe("pft2 codec", () => {
  it("round-trips every node kind with re-encode exactness", () => {
    const seen = new Set<number>();
    for (const [name, node] of sampleNodes()) {
      const encoded = encodePft2Node(node);
      expect(encoded.subarray(0, 4), name).toEqual(PFT2_MAGIC);
      const decoded = decodePft2Node(encoded);
      const reencoded = encodePft2Node(decoded);
      expect(Buffer.from(reencoded).toString("hex"), name).toBe(Buffer.from(encoded).toString("hex"));
      expect(() => decodePft2NodeKind(encoded, node.kind), name).not.toThrow();
      const wrongKind = ((node.kind % 13) + 1) as Pft2Node["kind"];
      expect(() => decodePft2NodeKind(encoded, wrongKind), name).toThrow(Pft2CorruptError);
      seen.add(node.kind);
    }
    expect(seen.size).toBe(14);
  });

  it("accepts legacy roots without field 8 and preserves new root xattr leaves", () => {
    const legacy = sampleNodes().get("root")!;
    expect(legacy.kind).toBe(Pft2NodeKind.Root);
    if (legacy.kind !== Pft2NodeKind.Root) {
      throw new Error("fixture is not a root");
    }
    const legacyBytes = encodePft2Node(legacy);
    const legacyDecoded = decodePft2NodeKind(legacyBytes, Pft2NodeKind.Root);
    expect(legacyDecoded.kind).toBe(Pft2NodeKind.Root);
    if (legacyDecoded.kind !== Pft2NodeKind.Root) {
      throw new Error("decoded fixture is not a root");
    }
    expect(legacyDecoded.root.xattrLeaves).toBeUndefined();
    expect(encodePft2Node(legacyDecoded)).toEqual(legacyBytes);

    const xattrLeaves = [labelRef("root-xattr-leaf-0", 300n), labelRef("root-xattr-leaf-1", 301n)];
    const current: Pft2Node = {
      kind: Pft2NodeKind.Root,
      root: { ...legacy.root, xattrLeaves },
    };
    const decoded = decodePft2NodeKind(encodePft2Node(current), Pft2NodeKind.Root);
    expect(decoded.kind).toBe(Pft2NodeKind.Root);
    if (decoded.kind !== Pft2NodeKind.Root) {
      throw new Error("decoded current fixture is not a root");
    }
    const normalized = (refs: typeof xattrLeaves | undefined) =>
      refs?.map((ref) => ({ digest: Buffer.from(ref.digest).toString("hex"), size: ref.size }));
    expect(normalized(decoded.root.xattrLeaves)).toEqual(normalized(xattrLeaves));
  });

  it("rejects wrong magic, trailing bytes, truncation, and size bounds", () => {
    const encoded = encodePft2Node(sampleNodes().get("directory-leaf")!);
    const wrongMagic = new Uint8Array(encoded);
    wrongMagic[0] = 0x51;
    expect(() => decodePft2Node(wrongMagic)).toThrow(Pft2InvalidNodeError);

    const trailing = new Uint8Array(encoded.length + 1);
    trailing.set(encoded);
    expect(() => decodePft2Node(trailing)).toThrow();

    for (let cut = PFT2_MIN_NODE_BYTES; cut < encoded.length; cut += 1) {
      expect(() => decodePft2Node(encoded.subarray(0, cut))).toThrow();
    }
    expect(() => decodePft2Node(encoded.subarray(0, PFT2_MIN_NODE_BYTES - 1))).toThrow(
      Pft2InvalidNodeError
    );
    const oversized = new Uint8Array(PFT2_MAX_NODE_BYTES + 1);
    oversized.set(encoded);
    expect(() => decodePft2Node(oversized)).toThrow(Pft2InvalidNodeError);
  });

  it("rejects structural wire violations", () => {
    const inodeFields = (mutate: (out: ByteWriter) => void): Uint8Array => {
      const inner = new ByteWriter();
      mutate(inner);
      const fields = new ByteWriter();
      appendUint(fields, 1, BigInt(Pft2NodeKind.Inode));
      appendBytes(fields, 3, inner.finish());
      return nodeBody(fields.finish());
    };

    // Explicit default (mode = 0 encoded explicitly).
    expect(() =>
      decodePft2Node(
        inodeFields((out) => {
          appendUint(out, 1, 99n);
          appendUint(out, 2, BigInt(Pft2FileKind.Regular));
          appendTag(out, 3, WIRE_TYPE_VARINT);
          out.pushByte(0);
          appendUint(out, 6, 1n);
        })
      )
    ).toThrow();

    // Non-minimal varint (ino = 1 as two bytes).
    expect(() =>
      decodePft2Node(
        inodeFields((out) => {
          appendTag(out, 1, WIRE_TYPE_VARINT);
          out.pushByte(0x81);
          out.pushByte(0x00);
          appendUint(out, 2, BigInt(Pft2FileKind.Regular));
          appendUint(out, 6, 1n);
        })
      )
    ).toThrow();

    // 64-bit varint overflow.
    expect(() =>
      decodePft2Node(
        inodeFields((out) => {
          appendTag(out, 1, WIRE_TYPE_VARINT);
          for (const byte of [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02]) {
            out.pushByte(byte);
          }
          appendUint(out, 2, BigInt(Pft2FileKind.Regular));
          appendUint(out, 6, 1n);
        })
      )
    ).toThrow();

    // Duplicate field.
    expect(() =>
      decodePft2Node(
        inodeFields((out) => {
          appendUint(out, 1, 99n);
          appendUint(out, 1, 99n);
          appendUint(out, 2, BigInt(Pft2FileKind.Regular));
          appendUint(out, 6, 1n);
        })
      )
    ).toThrow();

    // Out-of-order fields.
    expect(() =>
      decodePft2Node(
        inodeFields((out) => {
          appendUint(out, 2, BigInt(Pft2FileKind.Regular));
          appendUint(out, 1, 99n);
          appendUint(out, 6, 1n);
        })
      )
    ).toThrow();

    // Unknown field.
    expect(() =>
      decodePft2Node(
        inodeFields((out) => {
          appendUint(out, 1, 99n);
          appendUint(out, 2, BigInt(Pft2FileKind.Regular));
          appendUint(out, 6, 1n);
          appendUint(out, 99, 1n);
        })
      )
    ).toThrow();

    // Arm not matching kind (ROOT kind with inode arm field 3).
    const mismatchedFields = new ByteWriter();
    appendUint(mismatchedFields, 1, BigInt(Pft2NodeKind.Root));
    const inodeArm = new ByteWriter();
    appendUint(inodeArm, 1, 99n);
    appendUint(inodeArm, 2, BigInt(Pft2FileKind.Regular));
    appendUint(inodeArm, 6, 1n);
    appendBytes(mismatchedFields, 3, inodeArm.finish());
    expect(() => decodePft2Node(nodeBody(mismatchedFields.finish()))).toThrow();

    // Unknown kind 14.
    const unknownKind = new ByteWriter();
    appendUint(unknownKind, 1, 14n);
    appendBytes(unknownKind, 15, new Uint8Array([0x08, 0x01]));
    expect(() => decodePft2Node(nodeBody(unknownKind.finish()))).toThrow();
  });

  it("rejects invalid structures at encode time", () => {
    const unsorted: Pft2Node = {
      kind: Pft2NodeKind.DirectoryLeaf,
      directoryLeaf: {
        entries: [
          { name: "b", ino: 1n, kind: Pft2FileKind.Regular },
          { name: "a", ino: 2n, kind: Pft2FileKind.Regular },
        ],
      },
    };
    expect(() => encodePft2Node(unsorted)).toThrow(Pft2InvalidNodeError);

    const singleChildIndex: Pft2Node = {
      kind: Pft2NodeKind.DirectoryIndex,
      directoryIndex: {
        children: [{ firstName: "a", lastName: "b", child: labelRef("c", 100n), entryCount: 2n }],
      },
    };
    expect(() => encodePft2Node(singleChildIndex)).toThrow(Pft2InvalidNodeError);

    const countOverflow: Pft2Node = {
      kind: Pft2NodeKind.DirectoryIndex,
      directoryIndex: {
        children: [
          { firstName: "a", lastName: "b", child: labelRef("c", 100n), entryCount: 1n << 63n },
          { firstName: "c", lastName: "d", child: labelRef("d", 100n), entryCount: 1n << 63n },
        ],
      },
    };
    expect(() => encodePft2Node(countOverflow)).toThrow(Pft2InvalidNodeError);

    const symlinkSizeMismatch: Pft2Node = {
      kind: Pft2NodeKind.Inode,
      inode: {
        ino: 5n,
        kind: Pft2FileKind.Symlink,
        mode: 0,
        uid: 0,
        gid: 0,
        nlink: 1n,
        size: 3n,
        mtimeMs: 0n,
        ctimeMs: 0n,
        atimeMs: 0n,
        birthtimeMs: 0n,
        flags: 0,
        symlinkTarget: "abcd",
      },
    };
    expect(() => encodePft2Node(symlinkSizeMismatch)).toThrow(Pft2InvalidNodeError);

    const misalignedExtent: Pft2Node = {
      kind: Pft2NodeKind.ExtentLeaf,
      extentLeaf: { entries: [{ pageOffset: 4096n, page: labelRef("p", 900n) }] },
    };
    expect(() => encodePft2Node(misalignedExtent)).toThrow(Pft2InvalidNodeError);

    const featureBits: Pft2Node = {
      kind: Pft2NodeKind.Root,
      root: {
        rootInode: labelRef("a", 100n),
        inodeIndex: labelRef("b", 100n),
        maxInoSeen: 1n,
        inodeCount: 1n,
        direntCount: 0n,
        logicalBytes: 0n,
        features: 1n,
      },
    };
    expect(() => encodePft2Node(featureBits)).toThrow(Pft2InvalidNodeError);

    for (const name of [".", "..", "a/b", "a\0b", "", "x".repeat(256)]) {
      expect(() => validateEntryName(name)).toThrow(Pft2InvalidNodeError);
    }
  });

  it("bounds extent index counts by the possible page range", () => {
    const pageBytes = 65536n;
    const child = (first: bigint, last: bigint, count: bigint) => ({
      firstPage: first,
      lastPage: last,
      child: labelRef("c", 100n),
      entryCount: count,
    });
    const possible: Pft2Node = {
      kind: Pft2NodeKind.ExtentIndex,
      extentIndex: {
        children: [child(0n, pageBytes, 2n), child(4n * pageBytes, 4n * pageBytes, 1n)],
      },
    };
    const encoded = encodePft2Node(possible);
    expect(() => decodePft2Node(encoded)).not.toThrow();

    const impossible: Pft2Node = {
      kind: Pft2NodeKind.ExtentIndex,
      extentIndex: {
        children: [child(0n, pageBytes, 3n), child(4n * pageBytes, 4n * pageBytes, 1n)],
      },
    };
    expect(() => encodePft2Node(impossible)).toThrow(Pft2InvalidNodeError);

    // The widest legal range accepts its exactly-possible count and rejects
    // one more (overflow-safe bigint arithmetic).
    const maxFile = 1n << 62n;
    const widest = (maxFile - pageBytes - pageBytes) / pageBytes + 1n;
    const extreme: Pft2Node = {
      kind: Pft2NodeKind.ExtentIndex,
      extentIndex: {
        children: [child(0n, 0n, 1n), child(pageBytes, maxFile - pageBytes, widest)],
      },
    };
    expect(() => encodePft2Node(extreme)).not.toThrow();
    (extreme.extentIndex.children[1]!).entryCount = widest + 1n;
    expect(() => encodePft2Node(extreme)).toThrow(Pft2InvalidNodeError);
  });

  it("every single-byte mutation decodes canonically or not at all", () => {
    // The full sweep runs in Go; here sweep two representative nodes.
    for (const name of ["inode-file", "directory-leaf"]) {
      const encoded = encodePft2Node(sampleNodes().get(name)!);
      for (let i = 0; i < encoded.length; i += 1) {
        for (const delta of [0x01, 0x80, 0xff]) {
          const mutated = new Uint8Array(encoded);
          mutated[i] = mutated[i]! ^ delta;
          let decoded: Pft2Node;
          try {
            decoded = decodePft2Node(mutated);
          } catch {
            continue;
          }
          const reencoded = encodePft2Node(decoded);
          expect(Buffer.from(reencoded).toString("hex"), `${name} byte ${i} delta ${delta}`).toBe(
            Buffer.from(mutated).toString("hex")
          );
        }
      }
    }
  });

  it("verifyObjectBytes enforces advertised size before digest", () => {
    const encoded = encodePft2Node(sampleNodes().get("root")!);
    const ref = pft2RefOf(encoded);
    expect(() => verifyObjectBytes(ref, encoded)).not.toThrow();
    expect(() => verifyObjectBytes(ref, encoded.subarray(0, encoded.length - 1))).toThrow(
      Pft2CorruptError
    );
    const flipped = new Uint8Array(encoded);
    flipped[5] = flipped[5]! ^ 1;
    expect(() => verifyObjectBytes(ref, flipped)).toThrow(Pft2CorruptError);
    expect(() => verifyObjectBytes({ digest: ref.digest, size: ref.size + 1n }, encoded)).toThrow(
      Pft2CorruptError
    );
    expect(() =>
      verifyObjectBytes({ digest: labelDigest("other"), size: ref.size }, encoded)
    ).toThrow(Pft2CorruptError);
  });

  // The TS twin of Go's TestInodeBirthtimeFlagsCompatContract. Cross-language
  // byte identity for the stamped encodings is proven by the golden vectors;
  // this pins the compat contract itself on the TS side.
  it("decodes pre-revision inodes with a zero birth time and zero flags", () => {
    const legacy = {
      ino: 4242n,
      kind: Pft2FileKind.Regular,
      mode: 0o644,
      uid: 0,
      gid: 0,
      nlink: 1n,
      size: 9n,
      mtimeMs: 1700000000000n,
      ctimeMs: 1700000000000n,
      atimeMs: 1700000000000n,
      birthtimeMs: 0n,
      flags: 0,
      symlinkTarget: "",
    };
    const legacyEncoded = encodePft2Node({ kind: Pft2NodeKind.Inode, inode: legacy });
    const decoded = decodePft2NodeKind(legacyEncoded, Pft2NodeKind.Inode);
    expect(decoded.kind).toBe(Pft2NodeKind.Inode);
    if (decoded.kind !== Pft2NodeKind.Inode) throw new Error("unreachable");
    // Zero is "unknown", not 1970: an old tree must not be read as if it had
    // been created at the epoch with no flags set on purpose.
    expect(decoded.inode.birthtimeMs).toBe(0n);
    expect(decoded.inode.flags).toBe(0);
    expect(Buffer.from(encodePft2Node(decoded)).toString("hex")).toBe(
      Buffer.from(legacyEncoded).toString("hex")
    );

    for (const [birthtimeMs, flags] of [
      [1700000000001n, 0x00008000],
      [1699999999999n, 0],
      [0n, 0xffffffff],
      [-1700000000001n, 0x00000002],
    ] as const) {
      const stamped = { ...legacy, birthtimeMs, flags };
      const encoded = encodePft2Node({ kind: Pft2NodeKind.Inode, inode: stamped });
      const back = decodePft2NodeKind(encoded, Pft2NodeKind.Inode);
      if (back.kind !== Pft2NodeKind.Inode) throw new Error("unreachable");
      expect(back.inode.birthtimeMs).toBe(birthtimeMs);
      expect(back.inode.flags).toBe(flags);
      expect(Buffer.from(encodePft2Node(back)).toString("hex")).toBe(
        Buffer.from(encoded).toString("hex")
      );
    }

    // An unstamped inode still encodes to exactly the pre-revision bytes, so
    // the revision costs nothing on a tree that never uses it.
    expect(
      Buffer.from(
        encodePft2Node({ kind: Pft2NodeKind.Inode, inode: { ...legacy, birthtimeMs: 0n, flags: 0 } })
      ).toString("hex")
    ).toBe(Buffer.from(legacyEncoded).toString("hex"));

    // Out-of-range birth times fail validation exactly like the other times.
    expect(() =>
      encodePft2Node({
        kind: Pft2NodeKind.Inode,
        inode: { ...legacy, birthtimeMs: (1n << 56n) },
      })
    ).toThrow(Pft2InvalidNodeError);
  });
});
