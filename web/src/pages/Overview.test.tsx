import { screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import Overview from "./Overview";
import { renderPage } from "@/test/render";
import { expectNoA11yViolations } from "@/test/a11y";

describe("Overview", () => {
  it("lists every server and the alerts that need attention, with no a11y violations", async () => {
    const { container } = renderPage(<Overview />);
    // Server names are links on the cards and again inside alert rows, hence findAll.
    expect((await screen.findAllByRole("link", { name: "rds-main" })).length).toBeGreaterThan(0);
    expect((await screen.findAllByRole("link", { name: "mysql-billing" })).length).toBeGreaterThan(0);
    expect((await screen.findAllByRole("link", { name: "staging-pg" })).length).toBeGreaterThan(0);
    expect((await screen.findAllByText("WAL retained by a replication slot")).length).toBeGreaterThan(0);
    await expectNoA11yViolations(container);
  });

  it("never relies on colour alone: every status badge carries text", async () => {
    renderPage(<Overview />);
    expect((await screen.findAllByText("Critical")).length).toBeGreaterThan(0);
    expect((await screen.findAllByText("Unreachable")).length).toBeGreaterThan(0);
  });

  it("renders in Indonesian", async () => {
    renderPage(<Overview />, { lang: "id" });
    expect(await screen.findByRole("heading", { level: 1, name: "Ringkasan" })).toBeInTheDocument();
    expect((await screen.findAllByText("Kritis")).length).toBeGreaterThan(0);
  });
});
