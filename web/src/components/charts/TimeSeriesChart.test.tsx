import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";
import type { Series } from "@/api/types";
import { renderPage } from "@/test/render";
import { expectNoA11yViolations } from "@/test/a11y";
import { stubResizeObserver } from "./chartTestUtils";
import { TimeSeriesChart } from "./TimeSeriesChart";

const GiB = 1024 ** 3;
const series: Series = {
  metric: "retainedWalBytes",
  unit: "bytes",
  warning: 5 * GiB,
  critical: 20 * GiB,
  points: Array.from({ length: 12 }, (_, i) => ({ t: 1_700_000_000_000 + i * 60_000, v: (1 + i) * GiB })),
};

beforeEach(() => stubResizeObserver());

describe("TimeSeriesChart", () => {
  it("shows the current value, a screen-reader summary and the thresholds as text", () => {
    renderPage(<TimeSeriesChart title="WAL retained by slots" series={series} rangeLabel="1 hour" />);
    expect(screen.getByText("12 GiB", { selector: "p.font-mono" })).toBeInTheDocument();
    expect(screen.getByText(/currently 12 GiB, lowest 1 GiB, highest 12 GiB, rising over the last 1 hour/)).toBeInTheDocument();
    expect(screen.getByText(/Thresholds:/)).toHaveTextContent("Warning 5 GiB · Critical 20 GiB");
  });

  it("swaps the chart for an accessible data table and back", async () => {
    const { container } = renderPage(<TimeSeriesChart title="WAL retained by slots" series={series} rangeLabel="1 hour" />);
    const toggle = screen.getByRole("button", { name: "View as table" });
    expect(toggle).toHaveAttribute("aria-pressed", "false");
    fireEvent.click(toggle);

    const region = screen.getByRole("region", { name: "WAL retained by slots data table, scrollable" });
    expect(region).toHaveAttribute("tabindex", "0"); // keyboard-scrollable
    const table = within(region).getByRole("table", { name: /WAL retained by slots: values over the last 1 hour/ });
    expect(within(table).getAllByRole("row")).toHaveLength(13); // header + 12 points
    expect(within(table).getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Time", "Value"]);
    await expectNoA11yViolations(container);

    const back = screen.getByRole("button", { name: "View as chart" });
    expect(back).toHaveAttribute("aria-pressed", "true");
    fireEvent.click(back);
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("says so instead of drawing an empty chart", () => {
    renderPage(<TimeSeriesChart title="Cache hit ratio" series={{ ...series, points: [] }} rangeLabel="1 hour" />);
    expect(screen.getByText("No data for this range yet.")).toBeInTheDocument();
  });

  it("really draws the chart (line, both threshold lines with text labels) and has no a11y violations", async () => {
    const { container } = renderPage(<TimeSeriesChart title="WAL retained by slots" series={series} rangeLabel="1 hour" />);
    // Guard against a vacuous test: the SVG must exist, otherwise axe would only be checking an empty figure.
    await waitFor(() => expect(container.querySelector("svg.recharts-surface")).not.toBeNull());
    expect(container.querySelectorAll(".recharts-line-curve")).toHaveLength(1);
    expect(container.querySelectorAll(".recharts-reference-line")).toHaveLength(2);
    // Threshold lines are labelled in text, not by colour alone.
    const svgText = container.querySelector("svg.recharts-surface")!.textContent ?? "";
    expect(svgText).toContain("Warning · 5 GiB");
    expect(svgText).toContain("Critical · 20 GiB");
    await expectNoA11yViolations(container);
  });

  it("omits a threshold line that is far above the data, but still lists it in text", async () => {
    const tiny: Series = { ...series, points: series.points.map((p) => ({ ...p, v: 30 * 1024 ** 2 })) };
    const { container } = renderPage(<TimeSeriesChart title="WAL retained by slots" series={tiny} rangeLabel="1 hour" />);
    await waitFor(() => expect(container.querySelector("svg.recharts-surface")).not.toBeNull());
    expect(container.querySelectorAll(".recharts-reference-line")).toHaveLength(0);
    expect(screen.getByText(/Thresholds:/)).toHaveTextContent("Warning 5 GiB · Critical 20 GiB");
  });
});
