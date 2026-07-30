import { describe, expect, test } from "vitest";
import { dataPlaneTransportSchema } from "./access-leases.js";

describe("data-plane transport contract", () => {
  test("accepts each explicit mode and exact DNS/IP server names", () => {
    expect(dataPlaneTransportSchema.parse({ mode: "plaintext" })).toEqual({ mode: "plaintext" });
    expect(
      dataPlaneTransportSchema.parse({
        mode: "tls-system-pki",
        serverName: "router.example",
      })
    ).toEqual({ mode: "tls-system-pki", serverName: "router.example" });
    expect(
      dataPlaneTransportSchema.parse({
        mode: "tls-system-pki",
        serverName: "2001:db8::1",
      })
    ).toEqual({ mode: "tls-system-pki", serverName: "2001:db8::1" });
    expect(
      dataPlaneTransportSchema.parse({
        mode: "tls-private-ca",
        serverName: "192.0.2.10",
        caPem: "bounded wire value; manager and clients perform X.509 validation",
        caSha256: "a".repeat(64),
      })
    ).toMatchObject({ mode: "tls-private-ca", serverName: "192.0.2.10" });
  });

  test("rejects missing, conflicting, unknown, and ambiguous names", () => {
    for (const value of [
      {},
      { mode: "future" },
      { mode: "plaintext", serverName: "router.example" },
      { mode: "tls-system-pki" },
      { mode: "tls-system-pki", serverName: "router.example:2050" },
      { mode: "tls-system-pki", serverName: " router.example" },
      {
        mode: "tls-private-ca",
        serverName: "router.example",
        caPem: "x",
        caSha256: "A".repeat(64),
      },
    ]) {
      expect(dataPlaneTransportSchema.safeParse(value).success).toBe(false);
    }
  });
});
