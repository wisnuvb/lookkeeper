import { fireEvent, screen, within } from "@testing-library/react";
import { Route, Routes } from "react-router-dom";
import { describe, expect, it } from "vitest";
import MigrationRun from "./MigrationRun";
import { renderPage } from "@/test/render";
import { expectNoA11yViolations } from "@/test/a11y";

const SLOW = { timeout: 3000 };
const render = (id: string, lang: "en" | "id" = "en") =>
  renderPage(
    <Routes>
      <Route path="/migrations/:id" element={<MigrationRun />} />
    </Routes>,
    { route: `/migrations/${id}`, lang },
  );

describe("MigrationRun", () => {
  it("shows the route, the state, the short plan hash and one card per database", async () => {
    const { container } = render("m5f3a9c21");
    expect(await screen.findByRole("heading", { level: 1, name: "rds-main → ovh-main" }, SLOW)).toBeInTheDocument();
    expect(screen.getAllByText("Copying").length).toBeGreaterThan(0);
    expect(screen.getByText(/9b1f3c0e7a52d84e…/)).toBeInTheDocument();
    for (const db of ["shop", "billing", "auth"]) expect(screen.getByRole("heading", { level: 3, name: db })).toBeInTheDocument();
    const bars = screen.getAllByRole("progressbar");
    expect(bars.map((b) => b.getAttribute("aria-label"))).toEqual(expect.arrayContaining(["Copy progress of shop", "Copy progress of billing"]));
    expect(screen.getByText(/lk_m5f3a9c21_shop/)).toBeInTheDocument();
    await expectNoA11yViolations(container);
  });

  it("is honest that verify, cutover and cleanup are not available", async () => {
    render("m5f3a9c21");
    const timeline = await screen.findByRole("list", { name: "Progress" }, SLOW);
    const items = within(timeline).getAllByRole("listitem");
    expect(items).toHaveLength(8);
    expect(within(timeline).getAllByText("Not available in this version")).toHaveLength(3);
    for (const stage of ["Verify", "Cutover", "Cleanup"]) {
      const li = items.find((i) => i.textContent?.startsWith(stage));
      expect(li, stage).toBeDefined();
      expect(li).toHaveTextContent("Not available in this version");
    }
    expect(items.filter((i) => i.getAttribute("aria-current") === "step")).toHaveLength(1);
  });

  it("states that writes on the target do not flow back, and shows the migration warnings", async () => {
    render("m5f3a9c21");
    expect(await screen.findByText(/After cutover, writes on the target do not flow back to the source/, {}, SLOW)).toBeInTheDocument();
    expect(screen.getByText(/Schema changes on the source must stay frozen/)).toBeInTheDocument();
  });

  it("disables Abort and Cleanup and says why", async () => {
    render("m5f3a9c21");
    const abort = await screen.findByRole("button", { name: "Abort migration" }, SLOW);
    const cleanup = screen.getByRole("button", { name: "Clean up source" });
    expect(abort).toBeDisabled();
    expect(cleanup).toBeDisabled();
    expect(screen.getByText(/arrive with the real backend \(stage U3\)/)).toBeInTheDocument();
    expect(abort).toHaveAttribute("aria-describedby", "actions-note");
    fireEvent.click(abort); // must stay a no-op
    expect(screen.getByRole("heading", { level: 1, name: "rds-main → ovh-main" })).toBeInTheDocument();
  });

  it("shows a friendly not-found state for an unknown id", async () => {
    const { container } = render("m00000000");
    expect(await screen.findByText("There is no migration with the id m00000000.", {}, SLOW)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Back to migrations" })).toBeInTheDocument();
    await expectNoA11yViolations(container);
  });

  it("renders in Indonesian", async () => {
    render("m5f3a9c21", "id");
    expect(await screen.findByRole("heading", { level: 2, name: "Kemajuan" }, SLOW)).toBeInTheDocument();
    expect(screen.getAllByText("Belum tersedia di versi ini")).toHaveLength(3);
    expect(screen.getByRole("button", { name: "Batalkan migrasi" })).toBeDisabled();
  });
});
