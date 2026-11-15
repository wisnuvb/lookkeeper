import { screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import Migrations from "./Migrations";
import { createMockApi } from "@/api/mock";
import { renderPage } from "@/test/render";
import { expectNoA11yViolations } from "@/test/a11y";

const SLOW = { timeout: 3000 };

describe("Migrations list", () => {
  it("lists each migration with its route, state and progress, and links to it", async () => {
    const { container } = renderPage(<Migrations />, { route: "/migrations" });
    const links = await screen.findAllByRole("link", { name: /rds-main\s*→?\s*ovh-main/ }, SLOW);
    expect(links.some((l) => l.getAttribute("href") === "/migrations/m5f3a9c21")).toBe(true);
    expect(screen.getAllByText("Copying").length).toBeGreaterThan(0);
    expect(screen.getAllByRole("progressbar").length).toBeGreaterThan(0);
    expect(screen.getByRole("link", { name: "Plan a migration" })).toHaveAttribute("href", "/migrations/new");
    await expectNoA11yViolations(container);
  });

  it("shows an empty state with a call to action when there are no migrations", async () => {
    const api = { ...createMockApi(), listMigrations: async () => [] };
    const { container } = renderPage(<Migrations />, { route: "/migrations", api });
    expect(await screen.findByText("No migrations yet", {}, SLOW)).toBeInTheDocument();
    expect(screen.getAllByRole("link", { name: "Plan a migration" }).length).toBeGreaterThan(0);
    await expectNoA11yViolations(container);
  });

  it("shows an error with a retry when loading fails", async () => {
    const api = { ...createMockApi(), listMigrations: async () => Promise.reject(new Error("boom")) };
    renderPage(<Migrations />, { route: "/migrations", api });
    expect(await screen.findByRole("button", { name: "Try again" }, SLOW)).toBeInTheDocument();
  });

  it("renders in Indonesian", async () => {
    renderPage(<Migrations />, { route: "/migrations", lang: "id" });
    expect(await screen.findByRole("heading", { level: 1, name: "Migrasi" }, SLOW)).toBeInTheDocument();
    expect(await screen.findAllByText("Menyalin", {}, SLOW)).not.toHaveLength(0);
  });
});
