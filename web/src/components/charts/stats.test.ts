import { describe, expect, it } from "vitest";
import { seriesStats } from "./stats";

const pts = (vs: number[]) => vs.map((v, i) => ({ t: i * 1000, v }));

describe("seriesStats", () => {
  it("returns null for an empty series", () => {
    expect(seriesStats([])).toBeNull();
  });
  it("reports current, min and max", () => {
    expect(seriesStats(pts([3, 1, 5, 2]))).toMatchObject({ current: 2, min: 1, max: 5 });
  });
  it("calls steady growth rising and steady decline falling", () => {
    expect(seriesStats(pts([1, 2, 3, 4, 5, 6, 7, 8]))?.trend).toBe("rising");
    expect(seriesStats(pts([8, 7, 6, 5, 4, 3, 2, 1]))?.trend).toBe("falling");
  });
  it("does not call noise around a flat line a trend", () => {
    expect(seriesStats(pts([0.985, 0.987, 0.983, 0.986, 0.984, 0.988, 0.985, 0.986]))?.trend).toBe("steady");
  });
  it("treats an all-zero series as steady (no division by zero)", () => {
    expect(seriesStats(pts([0, 0, 0, 0]))?.trend).toBe("steady");
  });
});
