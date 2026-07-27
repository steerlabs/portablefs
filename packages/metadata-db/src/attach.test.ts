import { describe, expect, test } from "vitest";
import { attachRequestFingerprint } from "./attach.js";

const base = {
  tenantId: "t1",
  volumeId: "vol_a",
  branchName: "main",
  mode: "write" as const,
  shared: false,
  rootPath: "src",
  holderId: "holder-1",
  leaseTtlMs: 60_000,
};

describe("attachRequestFingerprint", () => {
  test("is stable for semantically identical retries", () => {
    const first = attachRequestFingerprint({
      ...base,
      prefetchPaths: ["b", "a", "a"],
      clientInfo: { component: "vcs", pid: 7 },
    });
    const second = attachRequestFingerprint({
      ...base,
      // Different spelling/order of the same semantics.
      rootPath: "/src/",
      prefetchPaths: ["a", "b"],
      clientInfo: { pid: 7, component: "vcs" },
    });
    expect(first).toBe(second);
    expect(first).toMatch(/^sha256:[0-9a-f]{64}$/u);
  });

  test("binds every semantic field", () => {
    const original = attachRequestFingerprint(base);
    expect(attachRequestFingerprint({ ...base, mode: "read" })).not.toBe(original);
    expect(attachRequestFingerprint({ ...base, shared: true })).not.toBe(original);
    expect(attachRequestFingerprint({ ...base, branchName: "dev" })).not.toBe(original);
    expect(attachRequestFingerprint({ ...base, leaseTtlMs: 61_000 })).not.toBe(original);
    expect(attachRequestFingerprint({ ...base, holderId: "holder-2" })).not.toBe(original);
    expect(attachRequestFingerprint({ ...base, tenantId: "t2" })).not.toBe(original);
  });
});
