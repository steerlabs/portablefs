// Strict environment configuration parsing. Every numeric and enum value is
// validated: NaN, infinity, floats, negatives, out-of-range values, and typos
// are STARTUP FAILURES, never silent defaults or fail-open behavior.

export function requiredEnv(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name]?.trim();
  if (!value) {
    throw new Error(`${name} is required.`);
  }
  return value;
}

/** Refuses the retired in-process command runner instead of silently ignoring it. */
export function rejectRetiredExecEnv(env: NodeJS.ProcessEnv): void {
  if (env.VOLUME_API_TENANT_EXEC?.trim() === "1") {
    throw new Error(
      "VOLUME_API_TENANT_EXEC=1 is retired: the Volume API never runs tenant commands in its host trust domain. Mount the volume and execute locally, or deploy a separately isolated runner."
    );
  }
}

// Semantic version: MAJOR.MINOR.PATCH with optional pre-release/build
// metadata (semver.org shape, dotted alphanumeric-and-hyphen identifiers).
const semverPattern =
  /^\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

/**
 * Parses an optional semantic-version environment value. Absent/empty is
 * undefined (the feature stays off); anything that does not look like semver
 * ("banana", "1.2", "v1.2.3") is a STARTUP FAILURE, never a garbage header.
 */
export function semverEnv(env: NodeJS.ProcessEnv, name: string): string | undefined {
  const raw = env[name]?.trim();
  if (raw === undefined || raw === "") {
    return undefined;
  }
  if (!semverPattern.test(raw)) {
    throw new Error(
      `${name} must be a semantic version (MAJOR.MINOR.PATCH[-pre][+build]), got ${JSON.stringify(raw)}.`
    );
  }
  return raw;
}

/**
 * Parses a strictly-decimal integer environment value with inclusive bounds.
 * Absent/empty uses the fallback; anything non-decimal (including "12x",
 * "1.5", "Infinity", "NaN", "0x10") is rejected.
 */
export function intEnv(
  env: NodeJS.ProcessEnv,
  name: string,
  fallback: number,
  min = 0,
  max = Number.MAX_SAFE_INTEGER
): number {
  const raw = env[name]?.trim();
  if (raw === undefined || raw === "") {
    if (!Number.isSafeInteger(fallback) || fallback < min || fallback > max) {
      throw new Error(`${name} fallback ${fallback} is outside [${min}, ${max}].`);
    }
    return fallback;
  }
  if (!/^-?\d+$/.test(raw)) {
    throw new Error(`${name} must be a decimal integer, got ${JSON.stringify(raw)}.`);
  }
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer in [${min}, ${max}], got ${raw}.`);
  }
  return value;
}
