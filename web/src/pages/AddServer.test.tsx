import { fireEvent, screen, waitFor } from "@testing-library/react";
import { Route, Routes } from "react-router-dom";
import { describe, expect, it } from "vitest";
import AddServer from "./AddServer";
import { renderPage } from "@/test/render";
import { expectNoA11yViolations } from "@/test/a11y";

const PASSWORD = "S3cret-canary-pw-9f2";
const SLOW = { timeout: 4000 };

function page() {
  return (
    <Routes>
      <Route path="/servers/new" element={<AddServer />} />
      <Route path="/servers/:id" element={<p>SERVER DETAIL PAGE</p>} />
    </Routes>
  );
}
const render = (lang: "en" | "id" = "en") => renderPage(page(), { route: "/servers/new", lang });

const next = () => fireEvent.click(screen.getByRole("button", { name: "Next" }));
const field = (name: RegExp) => screen.getByLabelText(name) as HTMLInputElement;

function fillEndpoint(host = "db.example.com", name = "prod-db") {
  fireEvent.change(field(/^Name/), { target: { value: name } });
  fireEvent.change(field(/^Host/), { target: { value: host } });
}
function fillCredentials(password = PASSWORD) {
  fireEvent.change(field(/^User/), { target: { value: "lockkeeper" } });
  fireEvent.change(field(/^Password/), { target: { value: password } });
}
async function toTestStep(host?: string, tls?: string) {
  next(); // engine -> endpoint
  fillEndpoint(host);
  if (tls) fireEvent.change(field(/^TLS mode/), { target: { value: tls } });
  next();
  fillCredentials();
  next();
  await screen.findByRole("heading", { level: 2, name: "Test the connection" });
}

describe("AddServer wizard", () => {
  it("shows the step indicator, marks the current step and has no a11y violations", async () => {
    const { container } = render();
    expect(screen.getByText("Step 1 of 5")).toBeInTheDocument();
    const current = screen.getAllByRole("listitem").filter((li) => li.getAttribute("aria-current") === "step");
    expect(current).toHaveLength(1);
    expect(current[0]).toHaveTextContent("Engine");
    await expectNoA11yViolations(container);
  });

  it("defaults the port by engine and keeps entered values when going back", () => {
    render();
    fireEvent.click(screen.getByRole("radio", { name: /MySQL/ }));
    next();
    expect(field(/^Port/).value).toBe("3306");
    expect(screen.getByText("Step 2 of 5")).toBeInTheDocument();
    fillEndpoint("db.example.com", "billing");
    next();
    expect(screen.getByRole("heading", { level: 2, name: "Which account should Lockkeeper use?" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Back" }));
    expect(field(/^Name/).value).toBe("billing");
    expect(field(/^Host/).value).toBe("db.example.com");
    expect(field(/^Port/).value).toBe("3306");
  });

  it("validates on blur and, after a failed submit, focuses a summary that links to each field", async () => {
    const { container } = render();
    next();
    const host = field(/^Host/);
    fireEvent.blur(host);
    expect(screen.getByText("Enter the host name or IP address.")).toBeInTheDocument();
    expect(host).toHaveAttribute("aria-invalid", "true");
    expect(host.getAttribute("aria-describedby")).toContain("f-host-error");

    next(); // name and host are still empty
    const summary = screen.getByText("2 problems to fix before continuing").closest("[tabindex]");
    await waitFor(() => expect(summary).toHaveFocus());
    const link = screen.getByRole("link", { name: "Enter a name for this server." });
    fireEvent.click(link);
    expect(field(/^Name/)).toHaveFocus();
    await expectNoA11yViolations(container);
  });

  it("rejects a malformed host and an out-of-range port", () => {
    render();
    next();
    fillEndpoint("https://db.example.com/x");
    fireEvent.change(field(/^Port/), { target: { value: "70000" } });
    next();
    // After a failed submit each message is in the summary and next to its field.
    expect(screen.getAllByText("Enter only the host: no spaces, no protocol, no port.")).toHaveLength(2);
    expect(screen.getAllByText("Enter a port between 1 and 65535.")).toHaveLength(2);
  });

  it("shows a warning for a weaker TLS mode", () => {
    render();
    next();
    expect(screen.queryByText("Weaker TLS mode")).not.toBeInTheDocument();
    fireEvent.change(field(/^TLS mode/), { target: { value: "require" } });
    expect(screen.getByText("Weaker TLS mode")).toBeInTheDocument();
  });

  it("requires a password and never writes it back into the page after the credentials step", async () => {
    const { container } = render();
    next();
    fillEndpoint();
    next();
    // The write-only password is required: an empty password is stopped before any test is possible.
    fireEvent.change(field(/^User/), { target: { value: "lockkeeper" } });
    next();
    expect(screen.getAllByText("Enter the password.").length).toBeGreaterThan(0);
    await expectNoA11yViolations(container);

    fireEvent.change(field(/^Password/), { target: { value: PASSWORD } });
    next();
    await screen.findByRole("heading", { level: 2, name: "Test the connection" });
    expect(document.body.innerHTML).not.toContain(PASSWORD);
    for (const input of Array.from(document.querySelectorAll("input,textarea"))) expect((input as HTMLInputElement).value).not.toBe(PASSWORD);

    // Going back shows an empty field and says a password is set; it is never echoed.
    fireEvent.click(screen.getByRole("button", { name: "Back" }));
    expect(field(/^Password/).value).toBe("");
    expect(screen.getByText(/A password is already set/)).toBeInTheDocument();
    expect(document.body.innerHTML).not.toContain(PASSWORD);
  });

  it("blocks saving until the connection test has succeeded, and explains an unreachable host", async () => {
    const { container } = render();
    await toTestStep("unreachable.example.com");
    const nextBtn = screen.getByRole("button", { name: "Next" });
    expect(nextBtn).toBeDisabled();
    expect(screen.getByText("Next is available after a successful test.")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Test connection" }));
    expect(await screen.findByText("The server could not be reached", {}, SLOW)).toBeInTheDocument();
    expect(screen.getByText(/Check the host, the port and any firewall/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Edit endpoint" })).toBeInTheDocument();
    await expectNoA11yViolations(container);
  }, 15000);

  it("explains that TLS is required for a remote server", async () => {
    render();
    await toTestStep("db.example.com", "disable");
    fireEvent.click(screen.getByRole("button", { name: "Test connection" }));
    expect(await screen.findByText("The TLS requirements were not met", {}, SLOW)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
  }, 15000);

  it("refuses a cloud metadata address with a specific message", async () => {
    render();
    await toTestStep("169.254.169.254");
    fireEvent.click(screen.getByRole("button", { name: "Test connection" }));
    expect(await screen.findByText("This address is never allowed", {}, SLOW)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
  }, 15000);

  it("runs the whole flow, shows the test result, saves, hides the password and navigates", async () => {
    const { container } = render();
    await toTestStep();
    fireEvent.click(screen.getByRole("button", { name: "Test connection" }));
    expect(await screen.findByText("Connection works", {}, SLOW)).toBeInTheDocument();
    expect(screen.getByText("PostgreSQL 16.4")).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 3, name: "Databases found (3)" })).toBeInTheDocument();
    expect(screen.getByText("app_production")).toBeInTheDocument();
    expect(screen.getByText("Read-only session")).toBeInTheDocument();
    await expectNoA11yViolations(container);

    expect(screen.getByRole("button", { name: "Next" })).toBeEnabled();
    next();
    expect(screen.getByRole("heading", { level: 2, name: "Review and save" })).toBeInTheDocument();
    expect(screen.getByText("Set (hidden)")).toBeInTheDocument();
    expect(document.body.innerHTML).not.toContain(PASSWORD);
    await expectNoA11yViolations(container);

    fireEvent.click(screen.getByRole("button", { name: "Save server" }));
    expect(await screen.findByText("SERVER DETAIL PAGE", {}, SLOW)).toBeInTheDocument();
  }, 20000);

  it("invalidates a successful test when the connection details change", async () => {
    render();
    await toTestStep();
    fireEvent.click(screen.getByRole("button", { name: "Test connection" }));
    await screen.findByText("Connection works", {}, SLOW);
    fireEvent.click(screen.getByRole("button", { name: "Back" })); // credentials
    fireEvent.click(screen.getByRole("button", { name: "Back" })); // endpoint
    fireEvent.change(field(/^Host/), { target: { value: "other.example.com" } });
    next();
    next();
    await screen.findByRole("heading", { level: 2, name: "Test the connection" });
    expect(screen.getByText(/You changed the connection details after the last test/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
  }, 20000);

  it("renders in Indonesian", () => {
    render("id");
    expect(screen.getByRole("heading", { level: 1, name: "Tambah server" })).toBeInTheDocument();
    expect(screen.getByText("Langkah 1 dari 5")).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: /PostgreSQL/ })).toBeChecked();
  });
});
