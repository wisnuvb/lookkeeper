# ADR 0005: Self-hosted web UI and a dynamic connection registry

- Status: **Accepted** by the owner on 2026-11-06, including item 4 **Option B (encrypted vault +
  references)**, which deliberately relaxes the letter of security principle 3: secrets may be stored
  at rest as AEAD ciphertext, with the master key never in the database. The vault is built with the
  web-UI slice; until then only `env:`/`file:`/prompt references exist.
- Deciders: owner

## Context

The owner asked whether the tool can run "on the web", with origin and destination configured
dynamically rather than in a static file. Current design: CLI + YAML; each database is declared in
config and tied to a role by name.

Interpretation used here: a **self-hosted web UI served by the same binary** (`lockkeeper serve`),
not a multi-tenant hosted SaaS. A hosted SaaS remains a later possibility via the agent model in
ARCHITECTURE section 4.

Risk shift: a web server that holds production credentials and can mutate the source (create slots,
freeze writes) is a far more attractive target than a CLI that runs when invoked. Every security
principle must therefore hold through the web path, not just the CLI path.

## Decision

1. **One service layer, two thin front ends.** All behaviour lives in `internal/service`. The CLI
   calls it in-process (works with no server running, as today). `lockkeeper serve` exposes the same
   service as a JSON/HTTP API (+ Server-Sent Events for progress/alerts) and serves an embedded
   static web UI (`go:embed`, so still one binary, no Node at runtime). The CLI can also target a
   running server. No logic lives in handlers or in UI code.
2. **Dynamic connection registry.** Connections are named endpoints stored in the local DB
   (created, tested and removed from the UI, API or `lockkeeper connections …`). **A connection has no
   role.** "Source" and "target" are assigned per migration (`migrate plan --source A --target B`) and
   per monitor target, so any database can be an origin or a destination, and the same one can be
   both in different migrations. Connections declared in YAML remain supported as read-only entries
   (useful for GitOps / headless installs). A connection test is a read-only action and is always
   allowed; it reports TLS mode, server version, roles/privileges and RDS detection.
3. **Server hardening (defaults, not options):**
   - Binds to `127.0.0.1` by default. Binding a non-loopback address is refused unless TLS is
     configured **and** authentication is enabled. Recommended remote access: SSH tunnel, VPN or a
     TLS reverse proxy. Exposing it directly to the internet is documented as unsupported.
   - Authentication: local users with argon2id-hashed passwords (`golang.org/x/crypto`, BSD-3); first
     run requires creating the admin via a one-time token printed on the console. Roles:
     `viewer` (read-only metrics), `operator` (run preflight, start/resume/verify), `admin`
     (connections, users, source-mutating approvals, cutover, cleanup). Optional TOTP later.
   - Sessions: random 256-bit tokens, `HttpOnly`, `Secure`, `SameSite=Strict` cookies, server-side
     revocation, idle and absolute timeouts, login rate limiting with backoff.
   - CSRF protection (token + `Origin`/`Host` checks); strict CSP, no inline scripts, no third-party
     assets; `X-Content-Type-Options`, `Referrer-Policy: no-referrer`, frame denial.
   - **Secrets are write-only through the API:** no endpoint ever returns a password, token or
     connection string with credentials; the UI shows "set / not set". Logs and audit entries pass
     through the redaction layer.
   - **Source-mutating actions keep the plan-hash gate on the server side.** The UI shows the exact SQL
     and requires a typed confirmation; the server independently verifies that the submitted plan hash
     matches a plan it generated, that the user is `admin`, and that the confirmation text matches. A
     compromised or buggy UI cannot skip it. Every action is written to the audit log with the user.
   - Long-running work (copy, follow, verification) runs in the server process under the same
     supervisor and state machine; closing the browser has no effect. A server restart resumes via
     reconcile (SPEC section 9).
4. **Credential storage — decision needed.** A UI user cannot practically set an environment variable
   on the server, so the UI needs somewhere to keep the passwords it is given.
   - **Option A: references only** (`env:`/`file:`). Strictly within principle 3; the UI can create a
     connection only if the secret already exists on the server. Safest, awkward for a web workflow.
   - **Option B (recommended): encrypted vault + references.** Secrets entered in the UI are encrypted
     with AES-256-GCM (standard library) using a random data key, wrapped by a **master key that is
     never stored in the database**: supplied via env var, a `0600` file, or a systemd credential,
     and the server refuses to start without it. Decrypted only in memory at the moment of connection
     (`secret.Value`). Master-key rotation is a command. `env:`/`file:` references keep working and are
     preferred where possible. Stored values are ciphertext, so the "no secrets in state files" intent
     (no plaintext, no recoverable secret in a copied DB file) holds, but the *principle's letter*
     ("passwords not in state files") is relaxed: an attacker with both the DB file and the master key
     recovers everything. This must be approved.
   - **Option C: session-only secrets** (held in server memory until restart, re-entered after). No
     secret at rest, but a restart in the middle of a multi-hour migration blocks until someone
     re-enters credentials, and the follow/guardrail logic cannot run unattended.
5. **Frontend stack is deliberately not chosen here.** It will be selected, and the UI/UX designed,
   when the web UI slice starts, using the `ui-ux-pro-max` skill first (owner's standing rule for UI
   work). Constraint: static assets embedded in the binary, accessible, no runtime CDN.
6. **Delivery order.** The service layer and API shape are built from Phase 1 slice 1 (cheap, and
   avoids a rewrite), the web UI ships as Phase 1 slice 3 (connections, dashboard, alerts, slots),
   and the migration wizard UI arrives with Phases 3–4 behind the same confirmations. The CLI stays
   fully capable throughout.

## Alternatives considered

- **Hosted multi-tenant SaaS now.** Rejected: tenancy, billing, isolation and being custodian of
  customers' production credentials are a different company-sized scope; the agent model keeps that
  door open.
- **Terminal UI (TUI) instead of web.** Lighter, but does not meet the "runs on the web" request.
- **No auth when bound to localhost.** Rejected: other local users/processes, browser-based attacks
  (DNS rebinding, CSRF) and later exposure via a reverse proxy make unauthenticated mode unsafe.
- **Separate frontend service/SPA with its own build and host.** More moving parts; contradicts the
  single-binary goal.

## Consequences

- Material extra scope: auth, sessions, CSRF, a vault, an API with versioning, UI and its tests.
  Roughly doubles the surface to secure and test; sequencing keeps the monitoring MVP unblocked.
- New permanent tests: auth bypass attempts on every route, CSRF and `Origin` checks, API-never-returns-
  secrets scan, plan-hash enforcement via the API, canary scan extended to API responses, HTTP logs and
  the DB file (must show ciphertext only).
- More dependencies to vet: `golang.org/x/crypto` (BSD-3, v0.58.0, verified 2026-11-06); HTTP router
  from the standard library (`net/http` `ServeMux`) unless a need appears.
- The threat model gains T14–T18 (SPEC section 12).
