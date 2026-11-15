import { fireEvent, screen, waitFor } from "@testing-library/react";
import { Route, Routes } from "react-router-dom";
import { describe, expect, it } from "vitest";
import MigrationNew from "./MigrationNew";
import { createMockApi } from "@/api/mock";
import type { LockkeeperApi } from "@/api/client";
import { renderPage } from "@/test/render";
import { expectNoA11yViolations } from "@/test/a11y";

const SLOW = { timeout: 4000 };
const PAIR = "/migrations/new?source=rds-main&target=ovh-main";

/** The mock's pre-flight always reports a blocker; this variant models "the operator fixed it". */
function apiWithoutBlockers(over: Partial<LockkeeperApi> = {}): LockkeeperApi {
  const base = createMockApi();
  return {
    ...base,
    async runPreflight(s, t) {
      const r = await base.runPreflight(s, t);
      return { ...r, findings: r.findings.filter((f) => f.severity !== "blocker") };
    },
    ...over,
  };
}

function render(opts: { route?: string; api?: LockkeeperApi; lang?: "en" | "id" } = {}) {
  return renderPage(
    <Routes>
      <Route path="/migrations/new" element={<MigrationNew />} />
      <Route path="/migrations/:id" element={<p>RUN PAGE</p>} />
      <Route path="/migrations" element={<p>LIST PAGE</p>} />
    </Routes>,
    { route: opts.route ?? PAIR, api: opts.api, lang: opts.lang },
  );
}

const next = () => fireEvent.click(screen.getByRole("button", { name: "Next" }));
const nextBtn = () => screen.getByRole("button", { name: "Next" });

async function toStep(api: LockkeeperApi, step: "preflight" | "plan" | "approve") {
  const view = render({ api });
  await waitFor(() => expect(nextBtn()).toBeEnabled(), SLOW);
  next();
  await screen.findByRole("heading", { level: 2, name: "Pre-flight check" });
  if (step === "preflight") return view;
  await screen.findByText(/Informational: \d+/, {}, SLOW);
  await waitFor(() => expect(nextBtn()).toBeEnabled(), SLOW);
  next();
  await screen.findByRole("heading", { level: 2, name: "Review the plan" });
  if (step === "plan") return view;
  await screen.findByText("Plan hash", {}, SLOW);
  await waitFor(() => expect(nextBtn()).toBeEnabled(), SLOW);
  next();
  await screen.findByRole("heading", { level: 2, name: "Approve the plan" });
  return view;
}

describe("MigrationNew: choose servers", () => {
  it("prefills from the query string, states that roles are per migration and has no a11y violations", async () => {
    const { container } = render();
    expect(screen.getByText("Step 1 of 4")).toBeInTheDocument();
    expect(screen.getByText(/A server has no fixed role/)).toBeInTheDocument();
    await waitFor(() => expect(nextBtn()).toBeEnabled(), SLOW);
    expect((screen.getByLabelText(/^Source server/) as HTMLSelectElement).value).toBe("rds-main");
    expect((screen.getByLabelText(/^Target server/) as HTMLSelectElement).value).toBe("ovh-main");
    await expectNoA11yViolations(container);
  });

  it("cannot continue until both servers are chosen", async () => {
    render({ route: "/migrations/new" });
    await screen.findAllByRole("option", { name: /rds-main/ }, SLOW);
    expect(nextBtn()).toBeDisabled();
    expect(screen.getByText("Choose both servers to continue.")).toBeInTheDocument();
  });

  it("refuses the same server as source and target", async () => {
    render({ route: "/migrations/new?source=rds-main&target=rds-main" });
    expect(await screen.findByText("Source and target must be different servers.", {}, SLOW)).toBeInTheDocument();
    expect(nextBtn()).toBeDisabled();
  });

  it("blocks MySQL with a clear message that it is not built yet", async () => {
    render({ route: "/migrations/new?source=rds-main&target=mysql-billing" });
    expect(await screen.findByText("MySQL migration is not built yet", {}, SLOW)).toBeInTheDocument();
    expect(screen.getByText(/Phase 5/)).toBeInTheDocument();
    expect(nextBtn()).toBeDisabled();
  });
});

describe("MigrationNew: pre-flight", () => {
  it("is explicitly read-only and a blocker disables continuing, with a way to re-run", async () => {
    const { container } = await toStepBlocked();
    expect(screen.getByText("Read-only: nothing was changed")).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 3, name: "Blockers (1)" })).toBeInTheDocument();
    expect(screen.getByText("1 blocker must be resolved first")).toBeInTheDocument();
    expect(screen.getByText("Resolve the blockers to continue.")).toBeInTheDocument();
    expect(nextBtn()).toBeDisabled();
    expect(screen.getByRole("button", { name: "Run the pre-flight again" })).toBeEnabled();
    // remedies are commands for the operator, copyable
    expect(screen.getAllByRole("button", { name: "Copy command" }).length).toBeGreaterThan(0);
    await expectNoA11yViolations(container);
  }, 15000);

  it("lets the operator continue once there are no blockers, and groups the remaining findings", async () => {
    await toStep(apiWithoutBlockers(), "preflight");
    await screen.findByText(/Blockers: 0 · Warnings: 3/, {}, SLOW);
    expect(screen.queryByRole("heading", { level: 3, name: /Blockers/ })).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 3, name: "Warnings (3)" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 3, name: "Information (2)" })).toBeInTheDocument();
    await waitFor(() => expect(nextBtn()).toBeEnabled(), SLOW);
  }, 15000);
});

async function toStepBlocked() {
  const view = render();
  await waitFor(() => expect(nextBtn()).toBeEnabled(), SLOW);
  next();
  await screen.findByText(/1 blocker must be resolved first/, {}, SLOW);
  return view;
}

describe("MigrationNew: plan and approval", () => {
  it("shows the plan with the source-changing group first, exact SQL and a copyable hash", async () => {
    const { container } = await toStep(apiWithoutBlockers(), "plan");
    await screen.findByText("Plan hash", {}, SLOW);
    expect(screen.getByRole("heading", { level: 3, name: "Changes the SOURCE server" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 3, name: "Target side" })).toBeInTheDocument();
    expect(screen.getByText(/CREATE ROLE lk_m5f3a9c21 LOGIN REPLICATION/)).toBeInTheDocument();
    expect(screen.getByText(/9b1f3c0e7a52d84e/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy plan hash" })).toBeInTheDocument();
    expect(screen.getByText(/Nothing in this prototype has been validated against real RDS/)).toBeInTheDocument();
    await expectNoA11yViolations(container);
  }, 20000);

  it("keeps Approve disabled until the exact phrase is typed, then approves and opens the migration", async () => {
    const { container } = await toStep(apiWithoutBlockers(), "approve");
    const approve = screen.getByRole("button", { name: "Approve plan" });
    expect(approve).toBeDisabled();
    expect(screen.getByText(/Approval is recorded in the audit log/)).toBeInTheDocument();
    const input = screen.getByLabelText(/^Confirmation phrase/);
    fireEvent.change(input, { target: { value: "migrate rds-main to ovh" } });
    expect(approve).toBeDisabled();
    await expectNoA11yViolations(container);

    fireEvent.change(input, { target: { value: "migrate rds-main to ovh-main" } });
    expect(approve).toBeEnabled();
    fireEvent.click(approve);
    expect(await screen.findByText("RUN PAGE", {}, SLOW)).toBeInTheDocument();
  }, 25000);

  it("shows the server's rejection when the phrase differs from what the server expects", async () => {
    const base = apiWithoutBlockers();
    // The page shows a phrase that the (mock) server does not accept: only the server is the authority.
    const api = apiWithoutBlockers({ buildPlan: async (s, t) => ({ ...(await base.buildPlan(s, t)), confirmationPhrase: "something else" }) });
    await toStep(api, "approve");
    fireEvent.change(screen.getByLabelText(/^Confirmation phrase/), { target: { value: "something else" } });
    fireEvent.click(screen.getByRole("button", { name: "Approve plan" }));
    expect(await screen.findByText(/The confirmation text does not match the phrase/, {}, SLOW)).toBeInTheDocument();
    expect(screen.queryByText("RUN PAGE")).not.toBeInTheDocument();
  }, 25000);

  it("tells the user the plan changed when the hash is rejected and offers the new plan", async () => {
    const base = apiWithoutBlockers();
    let calls = 0;
    const api = apiWithoutBlockers({
      buildPlan: async (s, t) => {
        const plan = await base.buildPlan(s, t);
        return ++calls === 1 ? { ...plan, hash: "deadbeef" } : plan; // first plan is stale, the rebuilt one is current
      },
    });
    await toStep(api, "approve");
    fireEvent.change(screen.getByLabelText(/^Confirmation phrase/), { target: { value: "migrate rds-main to ovh-main" } });
    fireEvent.click(screen.getByRole("button", { name: "Approve plan" }));
    expect(await screen.findByText("The plan changed", {}, SLOW)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Review the new plan" }));
    await screen.findByRole("heading", { level: 2, name: "Review the plan" });
    expect(await screen.findByText(/9b1f3c0e7a52d84e/, {}, SLOW)).toBeInTheDocument();
  }, 30000);
});

describe("MigrationNew: language", () => {
  it("renders in Indonesian", async () => {
    render({ lang: "id" });
    expect(screen.getByRole("heading", { level: 1, name: "Rencanakan migrasi" })).toBeInTheDocument();
    expect(screen.getByText("Langkah 1 dari 4")).toBeInTheDocument();
    expect(screen.getByText(/Server tidak punya peran tetap/)).toBeInTheDocument();
  });
});
