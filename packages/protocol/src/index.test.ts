import { describe, expect, test } from "vitest";
import {
  isWellFormedString,
  posixPathSchema,
  treeEntrySchema,
  type TreeEntry,
} from "./index.js";

// These tests lock in the domain boundaries that keep the Go↔TS tree-hash parity
// invariant intact (see the comments in index.ts):
//   - mode/uid/gid are decoded as uint32 on the Go side, so values above
//     0xffffffff must be rejected at the boundary (an out-of-domain uid would make
//     the committed manifest undecodable on Go).
//   - paths and linkTargets containing a lone (unpaired) UTF-16 surrogate must be
//     rejected: JSON.stringify (the TS tree hash) re-escapes a lone surrogate to
//     "\uXXXX" while Go's JSON decoder replaces it with U+FFFD, so the SAME string
//     would hash to different tree hashes (and even land in different shards).

const MAX_U32 = 0xffffffff; // 4294967295, the largest in-domain value
const OVER_U32 = 0x100000000; // 4294967296 = 2^32, the first out-of-domain value

const LONE_HIGH_SURROGATE = "\uD800"; // high surrogate with no following low surrogate
const LONE_LOW_SURROGATE = "\uDC00"; // low surrogate with no preceding high surrogate
// A valid, well-formed multibyte string: emoji (a proper surrogate PAIR) + accents + CJK.
const WELL_FORMED_MULTIBYTE = "目標/café-🚀-naïve.txt";

function baseEntry(overrides: Partial<TreeEntry> = {}): Record<string, unknown> {
  return {
    path: "dir/file.txt",
    kind: "file",
    mode: 0o644,
    ...overrides,
  };
}

describe("isWellFormedString", () => {
  test("accepts ASCII, BMP accents, CJK, and non-BMP emoji (surrogate pairs)", () => {
    expect(isWellFormedString("a.txt")).toBe(true);
    expect(isWellFormedString("café-naïve")).toBe(true);
    expect(isWellFormedString("目標")).toBe(true);
    expect(isWellFormedString("🚀")).toBe(true); // U+1F680 = D83D DE80, a valid pair
    expect(isWellFormedString(WELL_FORMED_MULTIBYTE)).toBe(true);
    expect(isWellFormedString("")).toBe(true);
  });

  test("rejects a lone high surrogate", () => {
    expect(isWellFormedString(LONE_HIGH_SURROGATE)).toBe(false);
    expect(isWellFormedString(`a${LONE_HIGH_SURROGATE}b`)).toBe(false);
  });

  test("rejects a lone low surrogate", () => {
    expect(isWellFormedString(LONE_LOW_SURROGATE)).toBe(false);
    expect(isWellFormedString(`a${LONE_LOW_SURROGATE}b`)).toBe(false);
  });

  test("rejects a reversed (low-then-high) surrogate sequence", () => {
    // DC00 D800: a low surrogate first (rejected immediately), so not a valid pair.
    expect(isWellFormedString(`${LONE_LOW_SURROGATE}${LONE_HIGH_SURROGATE}`)).toBe(false);
  });

  test("matches an independent encodeURIComponent-based oracle across cases", () => {
    // Independent reference: encodeURIComponent throws URIError on a lone surrogate
    // (a different mechanism than the manual code-unit scan in isWellFormedString),
    // so agreement across these samples cross-checks the implementation. (We avoid
    // String.prototype.isWellFormed here because the repo targets the ES2022 lib.)
    const referenceWellFormed = (s: string): boolean => {
      try {
        encodeURIComponent(s);
        return true;
      } catch {
        return false;
      }
    };
    const samples = [
      "a.txt",
      "café-🚀-naïve",
      "目標",
      "🚀",
      LONE_HIGH_SURROGATE,
      LONE_LOW_SURROGATE,
      `a${LONE_HIGH_SURROGATE}`,
      `${LONE_LOW_SURROGATE}b`,
      `${LONE_HIGH_SURROGATE}${LONE_LOW_SURROGATE}`, // valid pair
      `${LONE_LOW_SURROGATE}${LONE_HIGH_SURROGATE}`, // reversed: not a valid pair
      "",
    ];
    for (const sample of samples) {
      expect(isWellFormedString(sample)).toBe(referenceWellFormed(sample));
    }
  });
});

describe("treeEntrySchema mode/uid/gid uint32 boundary", () => {
  test("accepts mode/uid/gid at exactly 0xffffffff", () => {
    const result = treeEntrySchema.safeParse(
      baseEntry({ mode: MAX_U32, uid: MAX_U32, gid: MAX_U32 })
    );
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.mode).toBe(MAX_U32);
      expect(result.data.uid).toBe(MAX_U32);
      expect(result.data.gid).toBe(MAX_U32);
    }
  });

  test("rejects mode > 0xffffffff (2^32)", () => {
    expect(treeEntrySchema.safeParse(baseEntry({ mode: OVER_U32 })).success).toBe(false);
  });

  test("rejects uid > 0xffffffff (2^32)", () => {
    expect(treeEntrySchema.safeParse(baseEntry({ uid: OVER_U32 })).success).toBe(false);
  });

  test("rejects gid > 0xffffffff (2^32)", () => {
    expect(treeEntrySchema.safeParse(baseEntry({ gid: OVER_U32 })).success).toBe(false);
  });

  test("still rejects negative or non-integer mode/uid/gid", () => {
    expect(treeEntrySchema.safeParse(baseEntry({ mode: -1 })).success).toBe(false);
    expect(treeEntrySchema.safeParse(baseEntry({ uid: 1.5 })).success).toBe(false);
    expect(treeEntrySchema.safeParse(baseEntry({ gid: -1 })).success).toBe(false);
  });
});

describe("treeEntrySchema path / linkTarget surrogate rejection", () => {
  test("accepts a well-formed multibyte path", () => {
    const result = treeEntrySchema.safeParse(baseEntry({ path: WELL_FORMED_MULTIBYTE }));
    expect(result.success).toBe(true);
  });

  test("rejects a path containing a lone high surrogate", () => {
    expect(treeEntrySchema.safeParse(baseEntry({ path: LONE_HIGH_SURROGATE })).success).toBe(false);
    expect(
      treeEntrySchema.safeParse(baseEntry({ path: `dir/${LONE_HIGH_SURROGATE}.txt` })).success
    ).toBe(false);
  });

  test("rejects a path containing a lone low surrogate", () => {
    expect(treeEntrySchema.safeParse(baseEntry({ path: `dir/${LONE_LOW_SURROGATE}.txt` })).success).toBe(
      false
    );
  });

  test("accepts a symlink with a well-formed multibyte linkTarget", () => {
    const result = treeEntrySchema.safeParse(
      baseEntry({ kind: "symlink", linkTarget: "目標/café-🚀-naïve/ .txt" })
    );
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.linkTarget).toBe("目標/café-🚀-naïve/ .txt");
    }
  });

  test("rejects a linkTarget containing a lone high surrogate", () => {
    expect(
      treeEntrySchema.safeParse(
        baseEntry({ kind: "symlink", linkTarget: `a${LONE_HIGH_SURROGATE}` })
      ).success
    ).toBe(false);
  });

  test("rejects a linkTarget containing a lone low surrogate", () => {
    expect(
      treeEntrySchema.safeParse(
        baseEntry({ kind: "symlink", linkTarget: `${LONE_LOW_SURROGATE}b` })
      ).success
    ).toBe(false);
  });
});

describe("posixPathSchema rejects traversal and non-name segments", () => {
  test("rejects a `..` parent-escape segment anywhere in the path", () => {
    expect(posixPathSchema.safeParse("..").success).toBe(false);
    expect(posixPathSchema.safeParse("../a").success).toBe(false);
    expect(posixPathSchema.safeParse("a/..").success).toBe(false);
    expect(posixPathSchema.safeParse("foo/../bar").success).toBe(false);
  });

  test("rejects `.` and empty (`a//b`, trailing slash) segments", () => {
    expect(posixPathSchema.safeParse(".").success).toBe(false);
    expect(posixPathSchema.safeParse("a/./b").success).toBe(false);
    expect(posixPathSchema.safeParse("a//b").success).toBe(false);
    expect(posixPathSchema.safeParse("a/").success).toBe(false);
  });

  test("still accepts ordinary relative name paths, including dotfiles", () => {
    expect(posixPathSchema.safeParse("dir/file.txt").success).toBe(true);
    expect(posixPathSchema.safeParse(".gitignore").success).toBe(true);
    expect(posixPathSchema.safeParse("a/.hidden/b.txt").success).toBe(true);
    // only a WHOLE `.`/`..` segment is rejected; names that merely start with dots are fine
    expect(posixPathSchema.safeParse("..foo/bar..baz").success).toBe(true);
  });

  test("treeEntrySchema rejects a manifest entry path with a `..` escape", () => {
    expect(treeEntrySchema.safeParse(baseEntry({ path: "foo/../bar" })).success).toBe(false);
    expect(treeEntrySchema.safeParse(baseEntry({ path: "../escape" })).success).toBe(false);
  });
});

describe("posixPathSchema surrogate rejection (standalone)", () => {
  test("accepts a well-formed multibyte relative path", () => {
    expect(posixPathSchema.safeParse(WELL_FORMED_MULTIBYTE).success).toBe(true);
  });

  test("rejects a lone surrogate while still rejecting absolute / NUL paths", () => {
    expect(posixPathSchema.safeParse(LONE_HIGH_SURROGATE).success).toBe(false);
    expect(posixPathSchema.safeParse(LONE_LOW_SURROGATE).success).toBe(false);
    // sanity: the pre-existing relative-path guards still hold
    expect(posixPathSchema.safeParse("/abs").success).toBe(false);
    expect(posixPathSchema.safeParse("a b").success).toBe(false);
  });
});
