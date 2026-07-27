// Dependency-free bounded metrics registry for the authority manager.
//
// Names are validated against a strict pattern and capped in number so a bug
// can never mint unbounded series; values must be finite. There are no
// labels at all — every manager metric is a fixed-name scalar, which is the
// strongest possible cardinality bound.
const metricNamePattern = /^[a-z][a-z0-9_]{0,127}$/;
const maxMetricNames = 256;

export class ManagerMetrics {
  private readonly counters = new Map<string, number>();
  private readonly gauges = new Map<string, number>();

  counter(name: string): { add(n: number): void } {
    this.assertName(name);
    return {
      add: (n: number) => {
        if (!Number.isFinite(n) || n < 0) {
          return; // counters are monotonic; garbage increments are dropped
        }
        this.counters.set(name, (this.counters.get(name) ?? 0) + n);
      },
    };
  }

  setGauge(name: string, value: number): void {
    this.assertName(name);
    if (!Number.isFinite(value)) {
      return;
    }
    this.gauges.set(name, value);
  }

  renderPrometheus(): string {
    const lines: string[] = [];
    for (const [name, value] of this.counters) {
      lines.push(`${name} ${value}`);
    }
    for (const [name, value] of this.gauges) {
      lines.push(`${name} ${value}`);
    }
    lines.sort();
    return lines.join("\n") + (lines.length > 0 ? "\n" : "");
  }

  snapshot(): Record<string, number> {
    return Object.fromEntries([...this.counters.entries(), ...this.gauges.entries()]);
  }

  private assertName(name: string): void {
    if (!metricNamePattern.test(name)) {
      throw new Error("Manager metric names must be lowercase snake_case (bounded).");
    }
    if (
      this.counters.size + this.gauges.size >= maxMetricNames &&
      !this.counters.has(name) &&
      !this.gauges.has(name)
    ) {
      throw new Error("Manager metric name budget exceeded.");
    }
  }
}
