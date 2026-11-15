import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { Route, Routes, useLocation } from "react-router-dom";
import { beforeEach, describe, expect, it } from "vitest";
import ServerDetail from "./ServerDetail";
import { renderPage } from "@/test/render";
import { expectNoA11yViolations } from "@/test/a11y";
import { stubResizeObserver } from "@/components/charts/chartTestUtils";

function Probe() {
  return <output data-testid="loc">{useLocation().search}</output>;
}
function renderServer(id: string, query = "", lang: "en" | "id" = "en") {
  return renderPage(
    <>
      <Routes>
        <Route path="/servers/:id" element={<ServerDetail />} />
      </Routes>
      <Probe />
    </>,
    { route: `/servers/${id}${query}`, lang },
  );
}
// Radix Tabs activates on mousedown (or arrow keys), not on click.
const pick = (name: string) => fireEvent.mouseDown(screen.getByRole("tab", { name }), { button: 0, ctrlKey: false });

beforeEach(() => stubResizeObserver());

describe("ServerDetail: header and databases", () => {
  it("shows the server, its databases discovered beneath it, and no a11y violations", async () => {
    const { container } = renderServer("rds-main");
    expect(await screen.findByRole("heading", { level: 1, name: "rds-main" })).toBeInTheDocument();
    // Host and port are separate spans (the port never wraps), so compare the combined text of the <dd>.
    expect(screen.getByText((_, el) => el?.tagName === "DD" && el.textContent === "main-prod.c9x1example.eu-west-1.rds.amazonaws.com:5432")).toBeInTheDocument();
    expect(screen.getByText("From config file (read-only)")).toBeInTheDocument();
    const table = await screen.findByRole("table", { name: "Databases on rds-main" });
    for (const db of ["shop", "billing", "auth", "analytics", "notifications", "postgres"]) {
      expect(within(table).getByRole("rowheader", { name: db })).toBeInTheDocument();
    }
    await expectNoA11yViolations(container);
  });

  it("links to the migration planner for PostgreSQL", async () => {
    renderServer("rds-main");
    const link = await screen.findByRole("link", { name: "Plan a migration from this server" });
    expect(link).toHaveAttribute("href", "/migrations/new?source=rds-main");
  });

  it("sorts by a column with aria-sort and keyboard-operable buttons", async () => {
    renderServer("rds-main");
    const table = await screen.findByRole("table", { name: "Databases on rds-main" });
    const firstRow = () => within(table).getAllByRole("row")[1]!;
    const sizeHeader = within(table).getByRole("columnheader", { name: /Size/ });

    expect(within(table).getByRole("columnheader", { name: /Database/ })).toHaveAttribute("aria-sort", "ascending");
    expect(within(firstRow()).getByRole("rowheader")).toHaveTextContent("analytics");

    fireEvent.click(within(sizeHeader).getByRole("button", { name: "Sort by Size" }));
    expect(sizeHeader).toHaveAttribute("aria-sort", "ascending");
    expect(within(firstRow()).getByRole("rowheader")).toHaveTextContent("postgres"); // 7.4 MiB

    fireEvent.click(within(sizeHeader).getByRole("button", { name: "Sort by Size" }));
    expect(sizeHeader).toHaveAttribute("aria-sort", "descending");
    expect(within(firstRow()).getByRole("rowheader")).toHaveTextContent("shop"); // 71 GiB
  });
});

describe("ServerDetail: tabs and deep links", () => {
  it("keeps the active tab in the URL", async () => {
    renderServer("rds-main");
    await screen.findByRole("table", { name: "Databases on rds-main" });
    expect(screen.getByTestId("loc")).toHaveTextContent("");
    pick("Slots & WAL");
    await waitFor(() => expect(screen.getByTestId("loc")).toHaveTextContent("?tab=slots"));
    expect(screen.getByRole("tab", { name: "Slots & WAL" })).toHaveAttribute("aria-selected", "true");
    pick("Databases");
    await waitFor(() => expect(screen.getByTestId("loc")).toHaveTextContent(/^$/));
  });

  it("opens straight on a tab from ?tab=, and ignores an unknown value", async () => {
    const { unmount } = renderServer("rds-main", "?tab=alerts");
    expect(await screen.findByRole("heading", { level: 2, name: "Alerts for this server" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /Alerts/ })).toHaveAttribute("aria-selected", "true");
    unmount();
    renderServer("rds-main", "?tab=nonsense");
    expect(await screen.findByRole("table", { name: "Databases on rds-main" })).toBeInTheDocument();
  });

  it("shows only this server's alerts on the Alerts tab", async () => {
    const { container } = renderServer("rds-main", "?tab=alerts");
    await screen.findByText("WAL retained by a replication slot");
    expect(screen.getByText("Transaction ID age (wraparound risk)")).toBeInTheDocument();
    expect(screen.queryByText("Server unreachable")).not.toBeInTheDocument();
    await expectNoA11yViolations(container);
  });
});

describe("ServerDetail: metrics", () => {
  it("renders a chart per metric with a table alternative, and a range selector", async () => {
    const { container } = renderServer("rds-main", "?tab=metrics");
    for (const name of ["Connections used", "Cache hit ratio", "WAL retained by slots", "Transaction ID age"]) {
      expect(await screen.findByRole("figure", { name })).toBeInTheDocument();
    }
    expect(screen.queryByRole("figure", { name: "Replication lag" })).not.toBeInTheDocument(); // PostgreSQL reports none here

    const fig = screen.getByRole("figure", { name: "WAL retained by slots" });
    fireEvent.click(within(fig).getByRole("button", { name: "View as table" }));
    expect(within(fig).getByRole("table")).toBeInTheDocument();

    const hour = screen.getByRole("button", { name: "1 hour" });
    expect(hour).toHaveAttribute("aria-pressed", "true");
    fireEvent.click(screen.getByRole("button", { name: "24 hours" }));
    expect(screen.getByRole("button", { name: "24 hours" })).toHaveAttribute("aria-pressed", "true");
    expect(hour).toHaveAttribute("aria-pressed", "false");
    await screen.findByRole("figure", { name: "Connections used" });
    await expectNoA11yViolations(container);
  });

  it("can pause and resume live updates", async () => {
    renderServer("rds-main", "?tab=metrics");
    await screen.findByRole("figure", { name: "Connections used" });
    expect(screen.getByText("Updating every 15 seconds")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Pause updates" }));
    expect(screen.getByText("Updates paused")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Resume updates" }));
    expect(screen.getByText("Updating every 15 seconds")).toBeInTheDocument();
  });

  it("charts replication lag, not WAL, for MySQL", async () => {
    renderServer("mysql-billing", "?tab=metrics");
    expect(await screen.findByRole("figure", { name: "Replication lag" })).toBeInTheDocument();
    expect(screen.queryByRole("figure", { name: "WAL retained by slots" })).not.toBeInTheDocument();
    expect(screen.queryByRole("figure", { name: "Transaction ID age" })).not.toBeInTheDocument();
  });
});

describe("ServerDetail: slots", () => {
  it("lists slots read-only, warns about the inactive one and links the migration", async () => {
    const { container } = renderServer("rds-main", "?tab=slots");
    const table = await screen.findByRole("table", { name: "Replication slots on rds-main" });
    expect(within(table).getByRole("rowheader", { name: "demo_orphan_slot" })).toBeInTheDocument();
    expect(within(table).getAllByText("Active")).toHaveLength(2);
    expect(within(table).getByText("Inactive")).toBeInTheDocument();
    const callout = screen.getByText("An inactive slot is holding WAL").closest("div")!.parentElement!;
    expect(callout).toHaveTextContent("demo_orphan_slot");
    expect(callout).toHaveTextContent("18.4 GiB");
    expect(within(table).getAllByRole("link", { name: "Migration m5f3a9c21" })[0]).toHaveAttribute("href", "/migrations/m5f3a9c21");
    // Security principle 2: never delete on the source. No destructive control exists here.
    expect(screen.queryByRole("button", { name: /drop|delete|remove|clean/i })).not.toBeInTheDocument();
    expect(screen.getByText(/Lockkeeper never drops a slot from here/)).toBeInTheDocument();
    await expectNoA11yViolations(container);
  });

  it("explains that slots do not apply to MySQL", async () => {
    const { container } = renderServer("mysql-billing", "?tab=slots");
    expect(await screen.findByText("Replication slots do not apply to MySQL")).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    await expectNoA11yViolations(container);
  });

  it("disables migration planning for MySQL and says why", async () => {
    renderServer("mysql-billing");
    const button = await screen.findByRole("button", { name: "Plan a migration from this server" });
    expect(button).toBeDisabled();
    expect(button).toHaveAccessibleDescription(/not built yet/);
    expect(screen.queryByRole("link", { name: "Plan a migration from this server" })).not.toBeInTheDocument();
  });
});

describe("ServerDetail: unusual states", () => {
  it("explains an unreachable server and labels its data as stale", async () => {
    const { container } = renderServer("staging-pg");
    expect(await screen.findByText("This server is not answering")).toBeInTheDocument();
    expect(screen.getByText(/last known data and may be out of date/)).toBeInTheDocument();
    expect(screen.getByText(/Stale: no recent sample/)).toBeInTheDocument();
    expect(await screen.findByText(/No database information was collected/)).toBeInTheDocument();
    await expectNoA11yViolations(container);
  });

  it("shows a friendly not-found state for an unknown server", async () => {
    const { container } = renderServer("does-not-exist");
    expect(await screen.findByText("Server not found")).toBeInTheDocument();
    expect(screen.getByText(/No server named "does-not-exist"/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Back to servers" })).toHaveAttribute("href", "/servers");
    await expectNoA11yViolations(container);
  });

  it("renders in Indonesian", async () => {
    renderServer("rds-main", "?tab=slots", "id");
    expect(await screen.findByRole("tab", { name: "Slot & WAL" })).toBeInTheDocument();
    expect(await screen.findByRole("table", { name: "Replication slot di rds-main" })).toBeInTheDocument();
    expect(screen.getByText("Ada slot tidak aktif yang menahan WAL")).toBeInTheDocument();
    expect(screen.getByText("Dari file konfigurasi (hanya baca)")).toBeInTheDocument();
  });
});
