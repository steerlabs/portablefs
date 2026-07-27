import { describe, expect, test } from "vitest";
import {
  parseAccessLeaseControlSeq,
  parseAccessLeaseTokenGeneration,
  parseManagerEpoch,
} from "@portablefs/protocol";
import {
  assertCryptographicRng,
  canonicalAccessTokenClaims,
  deriveTokenKey,
  mintAccessLeaseId,
  mintAccessToken,
  mintManagerEpoch,
  mintRootSecret,
  parseAccessToken,
  parseAccessTokenRootSecret,
  verifyAccessToken,
  type AccessTokenClaims,
} from "./access-tokens.js";

const ROOT_SECRET = Buffer.alloc(32, 7);

function claims(overrides: Partial<AccessTokenClaims> = {}): AccessTokenClaims {
  return {
    protocolVersion: 1,
    managerEpoch: parseManagerEpoch("1234567890"),
    accessLeaseId: "pfal_0123456789abcdef",
    controlSeq: parseAccessLeaseControlSeq("1"),
    tokenGeneration: parseAccessLeaseTokenGeneration("1"),
    teamId: "team_1",
    volumeId: "vol_1",
    branch: "main",
    authorityInstanceId: "pfai_1",
    authorityRuntimeGeneration: "1",
    consumerId: "worker-9",
    expiresAt: 1_800_000_000_000,
    ...overrides,
  };
}

describe("deterministic access tokens", () => {
  test("mint, parse, and verify round-trip; re-mint is byte-identical", () => {
    const token = mintAccessToken(ROOT_SECRET, claims());
    expect(token).toBe(mintAccessToken(ROOT_SECRET, claims()));
    expect(token.startsWith("pfal_0123456789abcdef.g1.")).toBe(true);

    const parsed = parseAccessToken(token);
    expect(parsed).not.toBeNull();
    expect(parsed!.accessLeaseId).toBe("pfal_0123456789abcdef");
    expect(String(parsed!.tokenGeneration)).toBe("1");

    expect(verifyAccessToken(ROOT_SECRET, claims(), token)).toBe(true);
  });

  test("verification rejects tampered tokens, wrong claims, and wrong secrets", () => {
    const token = mintAccessToken(ROOT_SECRET, claims());
    const flipped = token.slice(0, -1) + (token.endsWith("A") ? "B" : "A");
    expect(verifyAccessToken(ROOT_SECRET, claims(), flipped)).toBe(false);
    expect(verifyAccessToken(ROOT_SECRET, claims(), `${token}x`)).toBe(false);
    expect(verifyAccessToken(ROOT_SECRET, claims(), "")).toBe(false);
    expect(verifyAccessToken(ROOT_SECRET, claims({ volumeId: "vol_other" }), token)).toBe(false);
    expect(verifyAccessToken(ROOT_SECRET, claims({ expiresAt: 1 }), token)).toBe(false);
    expect(verifyAccessToken(Buffer.alloc(32, 8), claims(), token)).toBe(false);
  });

  test("generation and epoch are inside the key derivation", () => {
    // A token minted for generation N never verifies against generation N+1
    // claims, and vice versa; same for a different manager epoch.
    const gen1 = mintAccessToken(ROOT_SECRET, claims());
    const gen2Claims = claims({
      tokenGeneration: parseAccessLeaseTokenGeneration("2"),
    });
    const gen2 = mintAccessToken(ROOT_SECRET, gen2Claims);
    expect(gen1).not.toBe(gen2);
    expect(verifyAccessToken(ROOT_SECRET, gen2Claims, gen1)).toBe(false);
    expect(verifyAccessToken(ROOT_SECRET, claims(), gen2)).toBe(false);

    const otherEpochClaims = claims({ managerEpoch: parseManagerEpoch("999") });
    expect(verifyAccessToken(ROOT_SECRET, otherEpochClaims, gen1)).toBe(false);

    const keyA = deriveTokenKey(ROOT_SECRET, parseManagerEpoch("1"), parseAccessLeaseTokenGeneration("1"));
    const keyB = deriveTokenKey(ROOT_SECRET, parseManagerEpoch("2"), parseAccessLeaseTokenGeneration("1"));
    const keyC = deriveTokenKey(ROOT_SECRET, parseManagerEpoch("1"), parseAccessLeaseTokenGeneration("2"));
    expect(keyA.equals(keyB)).toBe(false);
    expect(keyA.equals(keyC)).toBe(false);
  });

  test("canonical claims are length-delimited so values cannot smear", () => {
    // ("ab", "c") and ("a", "bc") must encode differently.
    const a = canonicalAccessTokenClaims(claims({ teamId: "ab", volumeId: "c" }));
    const b = canonicalAccessTokenClaims(claims({ teamId: "a", volumeId: "bc" }));
    expect(a.equals(b)).toBe(false);
  });

  test("parseAccessToken rejects malformed shapes", () => {
    expect(parseAccessToken("")).toBeNull();
    expect(parseAccessToken("just-a-string")).toBeNull();
    expect(parseAccessToken("pfal_x.g1")).toBeNull();
    expect(parseAccessToken("pfal_x.g0.mac")).toBeNull(); // generation is positive
    expect(parseAccessToken("pfal_x.g01.mac")).toBeNull(); // canonical decimal only
    expect(parseAccessToken("pfal_x.gg.mac")).toBeNull();
    expect(parseAccessToken(".g1.mac")).toBeNull();
    expect(parseAccessToken("pfal_x.g1.")).toBeNull();
    expect(parseAccessToken(`pfal_x.g1.${"m".repeat(600)}`)).toBeNull(); // bounded before work
    const parsed = parseAccessToken("pfal_x.g42.someMac_-");
    expect(parsed).toEqual({
      accessLeaseId: "pfal_x",
      tokenGeneration: parseAccessLeaseTokenGeneration("42"),
      mac: "someMac_-",
    });
  });
});

describe("root secret parsing", () => {
  test("accepts 64 hex chars", () => {
    const secret = parseAccessTokenRootSecret("ab".repeat(32));
    expect(secret.byteLength).toBe(32);
    expect(secret.equals(Buffer.from("ab".repeat(32), "hex"))).toBe(true);
  });

  test("accepts base64 and base64url of exactly 32 bytes, with surrounding whitespace", () => {
    const raw = Buffer.alloc(32, 0xfb);
    expect(parseAccessTokenRootSecret(raw.toString("base64")).equals(raw)).toBe(true);
    expect(parseAccessTokenRootSecret(` ${raw.toString("base64url")} \n`).equals(raw)).toBe(true);
  });

  test("rejects wrong sizes and malformed values", () => {
    expect(() => parseAccessTokenRootSecret("")).toThrow(/32 bytes/);
    expect(() => parseAccessTokenRootSecret("ab".repeat(16))).toThrow(/32 bytes/);
    expect(() => parseAccessTokenRootSecret("zz".repeat(32))).toThrow(/32 bytes/);
    expect(() => parseAccessTokenRootSecret(Buffer.alloc(16, 1).toString("base64"))).toThrow(
      /32 bytes/
    );
  });
});

describe("cryptographic minting", () => {
  test("CSPRNG is asserted and minted identifiers land in their domains", () => {
    expect(() => assertCryptographicRng()).not.toThrow();
    expect(mintRootSecret().byteLength).toBe(32);
    expect(mintAccessLeaseId()).toMatch(/^pfal_[0-9a-f]{32}$/);
    expect(mintAccessLeaseId()).not.toBe(mintAccessLeaseId());
    for (let i = 0; i < 32; i += 1) {
      const epoch = mintManagerEpoch();
      expect(epoch).toMatch(/^[1-9][0-9]{0,18}$/u);
      expect(() => parseManagerEpoch(epoch)).not.toThrow();
    }
  });
});
