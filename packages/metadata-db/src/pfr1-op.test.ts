import { describe, expect, it } from "vitest";
import { PFR1_OP_CONTROL, pfr1ControlOnly, pfr1RecordOp } from "./pfr1-op.js";

function hex(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s.replace(/\s/g, ""), "hex"));
}

describe("pfr1 record-op sniffer", () => {
  it("reads the op from a canonical Go golden vector (excl create, seq 16)", () => {
    // vcs/internal/wal/pfr1_test.go "excl-create" golden: PFR1, seq=16, op=1.
    const vector = hex("50465231 081010011a06782e6c6f636b388003c80101");
    expect(pfr1RecordOp(vector)).toBe(1);
    expect(pfr1ControlOnly(vector)).toBe(false);
  });

  it("classifies an OpControl record as control-only", () => {
    // PFR1, seq=1 (field 1 varint), op=13 (field 2 varint) — the prefix is
    // all the sniffer reads, so the truncated body is irrelevant.
    const prefix = hex("50465231 0801 100d");
    expect(pfr1RecordOp(prefix)).toBe(PFR1_OP_CONTROL);
    expect(pfr1ControlOnly(prefix)).toBe(true);
  });

  it("handles multi-byte seq varints", () => {
    // seq = 300 (0xAC 0x02), op = 2 (write).
    const prefix = hex("50465231 08ac02 1002");
    expect(pfr1RecordOp(prefix)).toBe(2);
  });

  it("classifies anything unparseable as content (the conservative arm)", () => {
    expect(pfr1RecordOp(hex(""))).toBeNull();
    expect(pfr1RecordOp(hex("deadbeef 0801 1002"))).toBeNull(); // wrong magic
    expect(pfr1RecordOp(hex("50465231 1002"))).toBeNull(); // op before seq
    expect(pfr1RecordOp(hex("50465231 0880"))).toBeNull(); // truncated varint
    expect(pfr1ControlOnly(hex("deadbeef"))).toBe(false);
  });
});
