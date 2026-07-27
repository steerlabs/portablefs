import { describe, expect, test } from "vitest";
import { PostgresMetadataRepository } from "./postgres.js";

// The pg Pool is lazy: constructing it opens no connections, so the clamp is
// assertable without a database.
function poolMax(repository: PostgresMetadataRepository): number | undefined {
  return (repository as unknown as { pool: { options: { max?: number } } }).pool.options.max;
}

describe("PostgresMetadataRepository pool bounds", () => {
  test("defaults the pool ceiling to 32 connections", async () => {
    const repository = new PostgresMetadataRepository("postgres://user@localhost:5432/db");
    expect(poolMax(repository)).toBe(32);
    await repository.close();
  });

  test("accepts smaller configured pools verbatim", async () => {
    const repository = new PostgresMetadataRepository({
      connectionString: "postgres://user@localhost:5432/db",
      max: 8,
    });
    expect(poolMax(repository)).toBe(8);
    await repository.close();
  });

  test("clamps oversized and non-positive pool requests to the sane range", async () => {
    const oversized = new PostgresMetadataRepository({
      connectionString: "postgres://user@localhost:5432/db",
      max: 200,
    });
    expect(poolMax(oversized)).toBe(32);
    await oversized.close();

    const nonPositive = new PostgresMetadataRepository({
      connectionString: "postgres://user@localhost:5432/db",
      max: 0,
    });
    expect(poolMax(nonPositive)).toBe(1);
    await nonPositive.close();
  });
});
