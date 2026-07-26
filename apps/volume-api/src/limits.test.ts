import { describe, expect, test } from "vitest";
import { AdmissionController, parseContentLength, routePolicies } from "./limits.js";
import { VolumeApiError } from "./errors.js";

describe("AdmissionController", () => {
  test("rejects above the global active-request cap with a typed 429", () => {
    const admission = new AdmissionController({ maxActiveRequests: 2 });
    admission.admit(routePolicies.control, 0);
    admission.admit(routePolicies.control, 0);
    try {
      admission.admit(routePolicies.control, 0);
      expect.unreachable("third admit must be refused");
    } catch (error) {
      expect(error).toBeInstanceOf(VolumeApiError);
      expect((error as VolumeApiError).code).toBe("VOLUME_OVERLOADED");
      expect((error as VolumeApiError).status).toBe(429);
    }
  });

  test("rejects above a route's own concurrency cap while other routes stay admittable", () => {
    const admission = new AdmissionController({ maxActiveRequests: 100 });
    admission.admit(routePolicies.exec, 0); // exec concurrency is 1
    expect(() => admission.admit(routePolicies.exec, 0)).toThrowError(/concurrency limit/);
    // A different route is not starved by the exec cap.
    const permit = admission.admit(routePolicies.control, 0);
    permit.release();
  });

  test("charges body bytes at the audited parse amplification plus the response reserve", () => {
    const admission = new AdmissionController({
      maxActiveRequests: 100,
      // Two control requests with 1 KiB bodies fit exactly; a third does not:
      // weight = 1024 x 2 (amplification) + 4 MiB (reserve).
      maxTransientBytes: 2 * (1024 * 2 + routePolicies.control.responseReserveBytes),
    });
    admission.admit(routePolicies.control, 1024);
    admission.admit(routePolicies.control, 1024);
    try {
      admission.admit(routePolicies.control, 1024);
      expect.unreachable("transient memory budget must refuse");
    } catch (error) {
      expect((error as VolumeApiError).message).toMatch(/transient memory/);
    }
  });

  test("a chunked body prepays the route maximum", () => {
    const admission = new AdmissionController({
      maxActiveRequests: 100,
      maxTransientBytes:
        routePolicies.control.maxBodyBytes * routePolicies.control.parseAmplification +
        routePolicies.control.responseReserveBytes,
    });
    // undefined Content-Length = chunked: reserves the route max, filling the budget.
    admission.admit(routePolicies.control, undefined);
    expect(() => admission.admit(routePolicies.control, 0)).toThrowError(/transient memory/);
  });

  test("rejects a declared Content-Length above the route bound with 413 before any read", () => {
    const admission = new AdmissionController();
    try {
      admission.admit(routePolicies.control, routePolicies.control.maxBodyBytes + 1);
      expect.unreachable("oversized declared body must be refused");
    } catch (error) {
      expect((error as VolumeApiError).code).toBe("VOLUME_BODY_TOO_LARGE");
      expect((error as VolumeApiError).status).toBe(413);
    }
  });

  test("the blob-probe policy admits the schema's own maximum request", () => {
    // 4096 digests ("sha256:" + 64 hex + JSON quoting/commas) is the largest
    // body the probe schema accepts; the dedicated policy must admit it where
    // the generic 64 KiB control budget cannot.
    const maxProbeBodyBytes = Buffer.byteLength(
      JSON.stringify({ digests: Array(4096).fill(`sha256:${"a".repeat(64)}`) })
    );
    expect(maxProbeBodyBytes).toBeGreaterThan(routePolicies.control.maxBodyBytes);
    expect(routePolicies.blobProbe.maxBodyBytes).toBeGreaterThanOrEqual(maxProbeBodyBytes);
    const admission = new AdmissionController();
    admission.admit(routePolicies.blobProbe, maxProbeBodyBytes).release();
  });

  test("permit release is idempotent and returns every budget", () => {
    const admission = new AdmissionController({ maxActiveRequests: 1 });
    const permit = admission.admit(routePolicies.control, 0);
    permit.release();
    permit.release();
    expect(admission.activeRequests).toBe(0);
    expect(admission.reservedTransientBytes).toBe(0);
    // The slot is admittable again exactly once.
    admission.admit(routePolicies.control, 0);
    expect(() => admission.admit(routePolicies.control, 0)).toThrowError(/concurrency limit/);
  });

  test("chargeResponseBytes charges the global budget at serve time and releases with the permit", () => {
    const admission = new AdmissionController({
      maxTransientBytes: routePolicies.blobRead.responseReserveBytes + 1024,
    });
    const permit = admission.admit(routePolicies.blobRead, 0);
    const admitted = admission.reservedTransientBytes;
    expect(admitted).toBe(routePolicies.blobRead.responseReserveBytes);

    permit.chargeResponseBytes(1024);
    expect(admission.reservedTransientBytes).toBe(admitted + 1024);

    // One byte past the budget refuses typed and charges NOTHING.
    try {
      permit.chargeResponseBytes(1);
      expect.unreachable("overcharge must be refused");
    } catch (error) {
      expect((error as VolumeApiError).code).toBe("VOLUME_OVERLOADED");
      expect((error as VolumeApiError).status).toBe(429);
    }
    expect(admission.reservedTransientBytes).toBe(admitted + 1024);

    // Release returns the admission weight AND every accepted charge.
    permit.release();
    expect(admission.reservedTransientBytes).toBe(0);
  });
});

describe("per-tenant admission dimension", () => {
  test("defaults to 50% of the global budgets", () => {
    const admission = new AdmissionController({ maxActiveRequests: 10 });
    for (let index = 0; index < 5; index += 1) {
      admission.admit(routePolicies.control, 0).bindTenant("t1");
    }
    // The sixth request for t1 is refused at 50% of the 10-request budget
    // while the server itself still has slots.
    const permit = admission.admit(routePolicies.control, 0);
    try {
      permit.bindTenant("t1");
      expect.unreachable("tenant cap must refuse");
    } catch (error) {
      expect((error as VolumeApiError).code).toBe("VOLUME_TENANT_OVERLOADED");
    }
    permit.release();
    // Another tenant proceeds untouched.
    admission.admit(routePolicies.control, 0).bindTenant("t2");
  });

  test("trips the request cap with a typed 429 carrying Retry-After, distinct from the global refusal", () => {
    const admission = new AdmissionController({ tenantMaxRequests: 2 });
    admission.admit(routePolicies.control, 0).bindTenant("t1");
    admission.admit(routePolicies.control, 0).bindTenant("t1");
    const third = admission.admit(routePolicies.control, 0);
    try {
      third.bindTenant("t1");
      expect.unreachable("tenant request cap must refuse");
    } catch (error) {
      expect(error).toBeInstanceOf(VolumeApiError);
      expect((error as VolumeApiError).code).toBe("VOLUME_TENANT_OVERLOADED");
      expect((error as VolumeApiError).status).toBe(429);
      expect((error as VolumeApiError).headers).toEqual({ "retry-after": "1" });
    }
    // The refused request still releases its GLOBAL reservation cleanly.
    third.release();
    expect(admission.activeRequests).toBe(2);
    // Other tenants admit normally while t1 is saturated.
    admission.admit(routePolicies.control, 0).bindTenant("t2");
  });

  test("bounds reserved-byte accumulation across a tenant's concurrent requests but never starves its only request", () => {
    // Each control request weighs exactly the 4 MiB response reserve.
    const weight = routePolicies.control.responseReserveBytes;
    const admission = new AdmissionController({
      maxTransientBytes: 100 * weight,
      tenantMaxRequests: 0, // isolate the byte dimension
      tenantMaxReservedBytes: 2 * weight,
    });
    // A sole in-flight request is NEVER refused by the accumulation cap, even
    // when it alone outweighs it (a maximal commit must keep working).
    const huge = admission.admit(routePolicies.commitFull, undefined);
    huge.bindTenant("t1");
    expect(admission.tenantReserved("t1")).toBeGreaterThan(2 * weight);
    huge.release();

    const first = admission.admit(routePolicies.control, 0);
    first.bindTenant("t1");
    const second = admission.admit(routePolicies.control, 0);
    second.bindTenant("t1");
    const third = admission.admit(routePolicies.control, 0);
    try {
      third.bindTenant("t1");
      expect.unreachable("tenant byte cap must refuse the third concurrent reservation");
    } catch (error) {
      expect((error as VolumeApiError).code).toBe("VOLUME_TENANT_OVERLOADED");
      expect((error as VolumeApiError).message).toMatch(/reserved-memory/);
    }
    third.release();

    // Response charges count against the same tenant accumulation.
    try {
      second.chargeResponseBytes(weight);
      expect.unreachable("tenant byte cap must refuse the response charge");
    } catch (error) {
      expect((error as VolumeApiError).code).toBe("VOLUME_TENANT_OVERLOADED");
    }

    // Releases return tenant accounting to zero (no residue).
    first.release();
    second.release();
    expect(admission.tenantReserved("t1")).toBe(0);
    expect(admission.tenantActiveRequests("t1")).toBe(0);
  });

  test("0 disables a tenant cap", () => {
    const admission = new AdmissionController({
      maxActiveRequests: 8,
      tenantMaxRequests: 0,
      tenantMaxReservedBytes: 0,
    });
    for (let index = 0; index < 8; index += 1) {
      admission.admit(routePolicies.control, 0).bindTenant("t1");
    }
    // All 8 global slots went to one tenant without a tenant refusal.
    expect(admission.tenantActiveRequests("t1")).toBe(8);
    expect(() => admission.admit(routePolicies.control, 0)).toThrowError(/concurrency limit/);
  });
});

describe("parseContentLength", () => {
  test("accepts canonical decimals and treats absence as chunked", () => {
    expect(parseContentLength("0")).toBe(0);
    expect(parseContentLength("12345")).toBe(12345);
    expect(parseContentLength(undefined)).toBeUndefined();
    expect(parseContentLength("")).toBeUndefined();
  });

  test("rejects malformed values with a typed 400 so weights cannot be spoofed", () => {
    for (const value of ["-1", "1.5", "0x10", "01", "9".repeat(30)]) {
      expect(() => parseContentLength(value)).toThrowError(VolumeApiError);
    }
  });
});
