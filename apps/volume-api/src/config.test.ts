import { describe, expect, test } from "vitest";
import { intEnv, requiredEnv, semverEnv } from "./config.js";

describe("intEnv", () => {
  test("uses the fallback when absent or empty", () => {
    expect(intEnv({}, "VOLUME_DATABASE_POOL_MAX", 32, 1, 32)).toBe(32);
    expect(intEnv({ VOLUME_DATABASE_POOL_MAX: "  " }, "VOLUME_DATABASE_POOL_MAX", 32, 1, 32)).toBe(
      32
    );
  });

  test("parses strict decimal integers", () => {
    expect(intEnv({ VOLUME_DATABASE_POOL_MAX: "8" }, "VOLUME_DATABASE_POOL_MAX", 32, 1, 32)).toBe(
      8
    );
  });

  test("rejects non-integers instead of silently defaulting", () => {
    for (const raw of ["abc", "1.5", "0x10", "Infinity", "NaN", "12x", "1e3"]) {
      expect(() =>
        intEnv({ VOLUME_DATABASE_POOL_MAX: raw }, "VOLUME_DATABASE_POOL_MAX", 32, 1, 32)
      ).toThrow(/decimal integer/);
    }
  });

  test("rejects out-of-range values (pool max is bounded to 32)", () => {
    expect(() =>
      intEnv({ VOLUME_DATABASE_POOL_MAX: "64" }, "VOLUME_DATABASE_POOL_MAX", 32, 1, 32)
    ).toThrow(/\[1, 32\]/);
    expect(() =>
      intEnv({ VOLUME_DATABASE_POOL_MAX: "0" }, "VOLUME_DATABASE_POOL_MAX", 32, 1, 32)
    ).toThrow(/\[1, 32\]/);
    expect(() =>
      intEnv({ VOLUME_DATABASE_POOL_MAX: "-1" }, "VOLUME_DATABASE_POOL_MAX", 32, 1, 32)
    ).toThrow(/\[1, 32\]/);
  });
});

describe("requiredEnv", () => {
  test("returns trimmed values and rejects absent or blank ones", () => {
    expect(requiredEnv({ VOLUME_DATABASE_URL: " postgres://x " }, "VOLUME_DATABASE_URL")).toBe(
      "postgres://x"
    );
    expect(() => requiredEnv({}, "VOLUME_DATABASE_URL")).toThrow(/required/);
    expect(() => requiredEnv({ VOLUME_DATABASE_URL: "  " }, "VOLUME_DATABASE_URL")).toThrow(
      /required/
    );
  });
});

describe("semverEnv", () => {
  test("absent or blank means the feature is off", () => {
    expect(semverEnv({}, "PORTABLEFS_MIN_CLI_VERSION")).toBeUndefined();
    expect(semverEnv({ PORTABLEFS_MIN_CLI_VERSION: "  " }, "PORTABLEFS_MIN_CLI_VERSION")).toBeUndefined();
  });

  test("accepts semver, trimmed, including pre-release and build metadata", () => {
    for (const raw of ["0.4.7", "1.0.0", "10.20.30", "1.2.3-rc.1", "1.2.3+build.5", "1.2.3-rc.1+sha.abc"]) {
      expect(semverEnv({ PORTABLEFS_MIN_CLI_VERSION: raw }, "PORTABLEFS_MIN_CLI_VERSION")).toBe(raw);
    }
    expect(semverEnv({ PORTABLEFS_MIN_CLI_VERSION: " 0.4.7 " }, "PORTABLEFS_MIN_CLI_VERSION")).toBe(
      "0.4.7"
    );
  });

  test("garbage is a startup failure, never a silently shipped header", () => {
    for (const raw of ["banana", "1.2", "v1.2.3", "1.2.3.4", "1.2.x", "1.2.3-", "latest"]) {
      expect(() =>
        semverEnv({ PORTABLEFS_MIN_CLI_VERSION: raw }, "PORTABLEFS_MIN_CLI_VERSION")
      ).toThrow(/semantic version/);
    }
  });
});
