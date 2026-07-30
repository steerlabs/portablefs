import { describe, expect, test } from "vitest";
import { formatAuthorityAddress, parseAuthorityAddress } from "./authority-address.js";

describe("authority address parser", () => {
  test("parses DNS, IPv4, bracketed IPv6, and scoped bracketed IPv6", () => {
    expect(parseAuthorityAddress("router.example:2050", { label: "router" })).toEqual({
      host: "router.example",
      port: 2050,
    });
    expect(parseAuthorityAddress("127.0.0.1:1", { label: "router" })).toEqual({
      host: "127.0.0.1",
      port: 1,
    });
    expect(parseAuthorityAddress("[2001:db8::1]:65535", { label: "router" })).toEqual({
      host: "2001:db8::1",
      port: 65_535,
    });
    expect(parseAuthorityAddress("[fe80::1%en0]:2050", { label: "router" })).toEqual({
      host: "fe80::1%en0",
      port: 2050,
    });
  });

  test("accepts only explicitly supported schemes", () => {
    const ipv6 = parseAuthorityAddress("tcp://[2001:db8::1]:2050", {
        label: "router",
        allowedSchemes: ["tcp", "fsproto"],
      });
    expect(ipv6).toEqual({ host: "2001:db8::1", port: 2050 });
    expect(formatAuthorityAddress(ipv6)).toBe("[2001:db8::1]:2050");
    expect(
      formatAuthorityAddress(
        parseAuthorityAddress("fsproto://router.example:2050", {
          label: "router",
          allowedSchemes: ["tcp", "fsproto"],
        })
      )
    ).toBe("router.example:2050");
    expect(() =>
      parseAuthorityAddress("https://router.example:2050", {
        label: "router",
        allowedSchemes: ["tcp", "fsproto"],
      })
    ).toThrow(/unsupported scheme/);
  });

  test.each([
    "",
    " router.example:2050",
    "router.example:2050 ",
    "router.example",
    "router.example:",
    ":2050",
    "router.example:0",
    "router.example:01",
    "router.example:65536",
    "router.example:-1",
    "router.example:2050:extra",
    "01.2.3.4:2050",
    "1.2.3.999:2050",
    "127.1:2050",
    "2001:db8::1:2050",
    "[2001:db8::1]",
    "[2001:db8::1]:",
    "[router.example]:2050",
    "[fe80::1%]:2050",
    "router.example:2050/path",
    "user@router.example:2050",
    "router.example:2050?x=1",
    "router.example:2050#fragment",
    "tcp:/router.example:2050",
  ])("rejects malformed or ambiguous address %j", (value) => {
    expect(() => parseAuthorityAddress(value, { label: "router" })).toThrow(
      /strict host:port/
    );
  });
});
