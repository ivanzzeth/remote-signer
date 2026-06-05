import { describe, expect, it } from "vitest";
import {
  formatDuration,
  isDurationField,
  parseDuration,
} from "./settingsDuration";

describe("isDurationField", () => {
  it("treats approval_guard.window as a duration", () => {
    expect(isDurationField("window", 10)).toBe(true);
  });

  it("treats resume_after and max_request_age as durations", () => {
    expect(isDurationField("resume_after", 1)).toBe(true);
    expect(isDurationField("max_request_age", 1)).toBe(true);
  });

  it("ignores non-duration keys", () => {
    expect(isDurationField("min_samples", 5)).toBe(false);
    expect(isDurationField("window", "10s")).toBe(false);
  });
});

describe("parseDuration", () => {
  it("parses human-readable units to nanoseconds", () => {
    expect(parseDuration("10s")).toBe(10_000_000_000);
    expect(parseDuration("2m")).toBe(120_000_000_000);
  });
});

describe("formatDuration", () => {
  it("formats whole seconds", () => {
    expect(formatDuration(10_000_000_000)).toBe("10s");
  });
});
