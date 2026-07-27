import { createHash } from "node:crypto";
import { describe, expect, test } from "vitest";
import {
  isJournalDigest,
  journalChainDigest,
  journalCodecPairs,
  journalLimits,
  journalPayloadCodec,
  journalPayloadMagics,
  journalRecordHash,
  zeroJournalDigest,
} from "./journal.js";

describe("journal digest chain", () => {
  test("one chain step is sha256(prev || be64(len) || payload)", () => {
    const payload = Buffer.concat([journalPayloadMagics.pfr1, Buffer.from("record body")]);
    const previous = "ab".repeat(32);
    const length = Buffer.alloc(8);
    length.writeBigUInt64BE(BigInt(payload.byteLength));
    const expected = createHash("sha256")
      .update(Buffer.from(previous, "hex"))
      .update(length)
      .update(payload)
      .digest("hex");
    expect(journalChainDigest(previous, payload)).toBe(expected);
  });

  test("the record hash is the chain step anchored at 32 zero bytes", () => {
    const payload = Buffer.concat([journalPayloadMagics.pfj3, Buffer.from("entry")]);
    expect(journalRecordHash(payload)).toBe(journalChainDigest(zeroJournalDigest, payload));
  });

  test("chaining is order-sensitive", () => {
    const first = Buffer.concat([journalPayloadMagics.pfr1, Buffer.from("a")]);
    const second = Buffer.concat([journalPayloadMagics.pfr1, Buffer.from("b")]);
    const forward = journalChainDigest(journalChainDigest(zeroJournalDigest, first), second);
    const reversed = journalChainDigest(journalChainDigest(zeroJournalDigest, second), first);
    expect(forward).not.toBe(reversed);
  });

  test("a malformed previous digest is a typed refusal", () => {
    expect(() => journalChainDigest("nope", Buffer.alloc(0))).toThrowError(
      /64 lowercase hex characters/
    );
    expect(isJournalDigest(zeroJournalDigest)).toBe(true);
    expect(isJournalDigest("AB".repeat(32))).toBe(false);
  });
});

describe("journal payload codecs", () => {
  test("recognizes exactly the two frozen payload magics", () => {
    expect(journalPayloadCodec(Buffer.concat([journalPayloadMagics.pfr1, Buffer.from("x")]))).toBe(
      "pfr1"
    );
    expect(journalPayloadCodec(Buffer.concat([journalPayloadMagics.pfj3, Buffer.from("x")]))).toBe(
      "pfj3"
    );
    expect(journalPayloadCodec(Buffer.from("PFXX????"))).toBeNull();
    expect(journalPayloadCodec(Buffer.from("PF"))).toBeNull();
  });

  test("the codec pairs are immutable and exactly two", () => {
    expect(journalCodecPairs).toEqual([
      { recordCodec: "pfr1", controlCodec: "pfc1" },
      { recordCodec: "pfj3", controlCodec: "pfc2" },
    ]);
  });
});

describe("frozen journal bounds", () => {
  test("server-side bounds match the SQL backstops byte for byte", () => {
    expect(journalLimits.maxRecordPayloadBytes).toBe(8 * 1024 * 1024);
    expect(journalLimits.maxGroupRecords).toBe(128);
    expect(journalLimits.maxGroupPayloadBytes).toBe(16 * 1024 * 1024);
    expect(journalLimits.maxPageRecords).toBe(256);
    expect(journalLimits.maxPageBytes).toBe(16 * 1024 * 1024);
  });
});
