import { fireEvent, screen, within } from "@testing-library/react";
import { useLocation } from "react-router-dom";
import { describe, expect, it } from "vitest";
import Alerts from "./Alerts";
import { createMockApi } from "@/api/mock";
import type { LockkeeperApi } from "@/api/client";
import type { Alert } from "@/api/types";
import { renderPage } from "@/test/render";
import { expectNoA11yViolations } from "@/test/a11y";

function Probe() {
  return <output data-testid="loc">{useLocation().search}</output>;
}
const page = (route = "/alerts", opts: { api?: LockkeeperApi; lang?: "en" | "id" } = {}) =>
  renderPage(
    <>
      <Alerts />
      <Probe />
    </>,
    { route, ...opts },
  );
const severity = () => screen.findByRole("combobox", { name: "Severity" });

describe("Alerts page", () => {
  it("lists firing alerts, most severe first, with no a11y violations", async () => {
    const { container } = page();
    expect(await screen.findByRole("heading", { level: 2, name: "Firing now" })).toBeInTheDocument();
    expect(await screen.findByText("4 alerts shown")).toBeInTheDocument();
    const rows = screen.getAllByRole("listitem");
    expect(rows).toHaveLength(4);
    // The two critical alerts come before the two warnings.
    expect(rows.slice(0, 2).every((r) => within(r).queryByText("Critical"))).toBe(true);
    expect(rows.slice(2).every((r) => within(r).queryByText("Warning"))).toBe(true);
    await expectNoA11yViolations(container);
  });

  it("filters by severity and keeps the filter in the URL", async () => {
    page();
    fireEvent.change(await severity(), { target: { value: "warning" } });
    expect(await screen.findByText("2 alerts shown")).toBeInTheDocument();
    expect(screen.getByTestId("loc")).toHaveTextContent("?severity=warning");
    expect(screen.queryByText("Server unreachable")).not.toBeInTheDocument();
    expect(screen.getByText("Replication lag")).toBeInTheDocument();
  });

  it("filters by server, and opens already filtered from a deep link", async () => {
    page("/alerts?server=staging-pg");
    expect(await screen.findByText("1 alert shown")).toBeInTheDocument();
    expect(screen.getByText("Server unreachable")).toBeInTheDocument();
    const server = screen.getByRole("combobox", { name: "Server" }) as HTMLSelectElement;
    await screen.findByRole("option", { name: "staging-pg" });
    expect(server.value).toBe("staging-pg");
  });

  it("explains an empty filtered result and clears the filters", async () => {
    const { container } = page("/alerts?severity=critical&server=mysql-billing");
    expect(await screen.findByText("No alerts match these filters.")).toBeInTheDocument();
    expect(screen.getByText("0 alerts shown")).toBeInTheDocument();
    await expectNoA11yViolations(container);
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(await screen.findByText("4 alerts shown")).toBeInTheDocument();
    expect(screen.getByTestId("loc")).toHaveTextContent(/^$/);
    expect((await severity() as HTMLSelectElement).value).toBe("");
  });

  it("ignores an unknown severity in the URL", async () => {
    page("/alerts?severity=catastrophic");
    expect(await screen.findByText("4 alerts shown")).toBeInTheDocument();
  });

  it("shows the all-clear state when nothing is firing", async () => {
    const api: LockkeeperApi = { ...createMockApi(), listAlerts: async () => [] };
    page("/alerts", { api });
    expect(await screen.findByText(/No active alerts\. Everything monitored is within its thresholds\./)).toBeInTheDocument();
  });

  it("lists resolved alerts in their own section after the firing ones", async () => {
    const resolved: Alert = { id: "r1", serverId: "rds-main", rule: "pg.xid.age_ratio", severity: "warning", state: "resolved", since: new Date(Date.now() - 3_600_000).toISOString(), value: 0.2, threshold: 0.4, unit: "ratio", labels: {} };
    const base = createMockApi();
    const api: LockkeeperApi = { ...base, listAlerts: async (o) => [...(await base.listAlerts(o)), resolved] };
    const { container } = page("/alerts", { api });
    const firing = await screen.findByRole("heading", { level: 2, name: "Firing now" });
    const done = await screen.findByRole("heading", { level: 2, name: "Recently resolved" });
    expect(firing.compareDocumentPosition(done) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    await expectNoA11yViolations(container);
  });

  it("renders in Indonesian", async () => {
    page("/alerts", { lang: "id" });
    expect(await screen.findByRole("heading", { level: 1, name: "Peringatan" })).toBeInTheDocument();
    expect(await screen.findByText("4 peringatan ditampilkan")).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Tingkat keparahan" })).toBeInTheDocument();
  });
});
