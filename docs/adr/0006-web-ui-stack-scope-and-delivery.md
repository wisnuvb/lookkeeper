# ADR 0006: Web UI stack, scope and delivery order

- Status: **Accepted** by the owner on 2026-11-15 (stack, scope, languages, order).
- Deciders: owner
- Builds on: ADR 0005 (self-hosted web UI, dynamic connections, vault, server hardening). Nothing in
  ADR 0005 is relaxed here; this ADR fills in what it deliberately left open (item 5, the frontend
  stack) and adds scope, a new threat and the delivery order.

## Context

ADR 0005 accepted a self-hosted web UI served by the `lockkeeper` binary and left the frontend stack
open. On 2026-11-15 the owner asked for a modern, attractive, intuitive UI from which everything is
controlled: connecting databases, monitoring, and migrating ("sync/import") from one server to another.

Clarification from the owner the same day: Lockkeeper must **monitor every database on a server**
(including remote ones), as a fleet/operations tool. It is **not** a single-database client like
TablePlus.

Facts about the current code that shape the decision (verified 2026-11-15):

- `internal/service` already exposes `Check`, `SlotsList`, `Inventory`, `PreflightPG`, `AlertsTest`.
- The PostgreSQL collector is already server-wide: it reads `pg_database` / `pg_stat_database` and
  labels samples per database. A connection therefore maps to one **server**; its databases are
  discovered, not configured one by one. Only table-level detail (inventory) needs a session per database.
- The SQLite store has `metrics`, `alert_state`, `events` but only `LatestSamples` / `RecentEvents`; there
  is no time-range query for charts.
- The migration orchestrator (Phase 3) lives on `integration/phase3`, not on `main`. Cutover and
  verification (Phase 4) and MySQL migration (Phase 5) do not exist. A UI can only be as capable as its
  backend.

## Decision

1. **Information model is server-centric.** One connection = one server (host, port, credentials, TLS).
   The UI hierarchy is Server -> Database -> table / slot. Databases are discovered from the server and
   are never registered one by one. A connection still has no source/target role (ADR 0005).
2. **Stack: Vite + React + TypeScript + Tailwind CSS + shadcn/ui (Radix primitives).** The production
   build is static files embedded with `go:embed`. Node is a **build-time** requirement only; the shipped
   artefact is still one Go binary with no CDN and no runtime Node. `go install` of the module will not
   include the UI unless `dist` is committed; releases are built binaries.
3. **Self-hosted fonts and assets.** Fira Sans and Fira Code (SIL OFL) are embedded as woff2. The CSP
   forbids external origins, which overrides the Google Fonts link the design generator emits.
4. **Languages: Indonesian and English from the start**, via `react-i18next`. No user-visible string
   literal in components; a missing key in either language fails a check.
5. **Design system** is persisted in `design-system/lockkeeper/MASTER.md` (generated with the
   `ui-ux-pro-max` skill, then corrected: see the "Lockkeeper decisions" block at its top). Light and dark
   themes are designed together, with semantic tokens only, and every colour pair is measured for contrast.
6. **API contract first.** `/api/v1` JSON plus Server-Sent Events (no WebSocket), described by an OpenAPI
   document; TypeScript types are generated from it, never hand-written. Handlers stay thin (ADR 0005).
7. **Scope.** "Sync/import" means a **full-database migration**: bulk copy, continuous replication,
   verification, cutover. Explicitly out of scope: a SQL console or query editor, table browsing/editing,
   and table-level ETL/import. These would turn a read-mostly operations tool into a database admin
   client and contradict security principles 1 and 3.
8. **New threat T21 (SSRF through connection tests).** Anyone who can create or test a connection can make
   the server open a TCP connection to an arbitrary host and port. Mitigations: only `admin` may create
   or test connections; only PostgreSQL/MySQL protocols; link-local and cloud-metadata addresses
   (`169.254.0.0/16`, `fd00:ec2::/32`) are always refused; loopback and private ranges are allowed only for
   addresses the operator has put on an explicit allowlist (or `--allow-private-targets`); strict timeouts;
   rate limiting; error messages do not reveal whether a port is open versus filtered beyond what the
   protocol handshake already shows; every test is audited.
9. **Delivery order** (each stage ends in something runnable and tested):

   | Stage | Content | Needs |
   |---|---|---|
   | U0 | Persisted design system, ADR/SPEC updates, a **real** frontend scaffold with mocked data and the key screens (Overview, Server detail, Add connection, Migration wizard, Migration run). Not throwaway: it becomes the production frontend. | nothing |
   | U1 | `lockkeeper serve`, authentication, sessions, CSRF, roles, audit, vault, connection registry (merged with read-only YAML entries), SSRF guard, read API, time-range store queries | nothing |
   | U2 | Real monitoring UI on U1: login, fleet overview, connections CRUD and test, server detail with charts, alerts, settings; inventory and pre-flight views | U1 |
   | U3 | Migration wizard on the real orchestrator: plan, approve (server-side plan hash + typed confirmation), run, status, abort, cleanup; the driver runs inside the server process and resumes by reconcile | merge of Phase 3 |
   | U4 | Verification and guided cutover screens | Phase 4 backend |
   | U5 | MySQL migration wizard, TOTP, packaging | Phase 5 backend |

   The critical path is on the backend: merging Phase 3 and building Phase 4.

## Dependency policy for the frontend

Exact versions pinned and a lockfile committed; `npm audit` (production dependencies) in CI next to
`govulncheck`; every direct dependency's licence recorded in SPEC Appendix A before release; no
postinstall scripts from unvetted packages. Prefer few, mainstream, permissively licensed packages
(MIT/Apache-2.0/ISC/OFL for fonts).

## Alternatives considered

- **Go `html/template` + htmx.** Smaller and no Node at build time, but wizards, live progress and the
  expected "modern" feel are harder; rejected by the owner in favour of React.
- **Svelte.** Lighter than React, but the design tooling used here has no Svelte guidance and the
  shadcn ecosystem is React-first.
- **A TablePlus-style single-database client.** Rejected: contradicts the fleet-monitoring goal and
  the security principles (no data browsing, no ad-hoc SQL).

## Consequences

- A second toolchain (Node) appears in CI and the release build; `make build` gains a `web` step.
- The prototype in U0 uses mocked data behind the same API client the real UI will use, so U2 swaps the
  data source, not the screens.
- Mocked data must be unmistakably labelled in the UI (a visible "demo data" banner) so a prototype can
  never be mistaken for a real database's state.
- New permanent tests: per-route authentication and role matrix, SSRF guard cases, secrets never in API
  responses, browser tests (keyboard-only flows, both themes, 375/768/1024/1440 px, reduced motion,
  automated accessibility checks).

## Addendum 2026-11-15: stage U0 done, stage U1 started (slice U1-A)

Decisions taken while building, each verified in a real browser against the real binary:

- **Style nonce instead of `unsafe-inline`.** Radix UI (menus, dialogs) injects a `<style>` element when
  it locks page scroll. A strict `style-src 'self'` blocks it (CSP violation, lost scrollbar
  compensation). The server now generates a 128-bit nonce per response, puts it in the CSP
  (`style-src 'self' 'nonce-...'`) and into `index.html` (`<meta name="csp-nonce">`), and the app hands
  it to Radix through `__webpack_nonce__`. `script-src` stays `'self'` with no nonce. The app shell is
  therefore `Cache-Control: no-store`. Inline style attributes remain blocked; the UI sets styles through
  the DOM, which CSP permits.
- **Schema versions must not collide.** The state database applies a linear list of migrations (index +
  1 = version). The Phase 3 branch appends version 2; U1 tables (users, sessions, audit of web actions,
  connection registry, vault records) must therefore be built on top of it, as version 3. **Phase 3 is
  merged before the store-backed part of U1.** Slice U1-A touches no schema.
- **Slice U1-A (done):** `internal/netguard` (T21), `internal/vault`, `internal/auth`
  (password hashing, tokens, roles, login throttling, CSRF, sessions behind an interface, first-run
  token), `internal/web` and `internal/webui` (hardened server, embedded UI), and a preview command
  `lockkeeper serve` (demo data, loopback only, no login). The UI is embedded with `make build-ui`.
- **Next slice U1-B** (the Phase 3 merge is done, `2b83a28`): schema v3, SQLite `SessionStore`, user store and the
  login/logout/setup/session endpoints, authentication and role middleware, audit of every mutating
  request, the connection registry with vault-backed passwords and the netguard dialer wired into
  `dbconn`, read-only API endpoints, `QuerySeries`, and the server reading its `web:` configuration.
- **Toolchain.** `go.mod` now pins `toolchain go1.27.4`: GO-2026-6859 (HTTP/1 server crash through a
  `MaxBytesReader` header race in `net/http`, fixed in 1.27.4) is reachable from the new server, which
  uses both.

### Independent security review of slice U1-A (2026-11-15) and what was done about it

A reviewer with no access to the author's reasoning read the new packages and proved issues with tests.
No critical or high issue; the bind policy, Host guard, CSP nonce, static-file rules, argon2id handling,
token storage and vault AEAD were found sound. Everything it proved or plausibly argued was fixed in the
same slice, each with a regression test that was shown to fail when the fix is removed:

| # | Finding | Fix |
|---|---|---|
| 1 | Login throttle bypassed by parallel requests (200 of 200 passed a threshold of 5) | Reserve before verify: `Limiter.Acquire` counts the attempt atomically; success or a non-credential error gives it back (`LoginGuard.Begin` returns an `Attempt`) |
| 2 | Flooding the key table evicted an active lock | A locked key is never evicted; a table full of locks refuses new keys (fail closed) |
| 3 | Counters never decayed; a lockout could be held forever | Counters decay after `DecayAfter` (1 h quiet); `LoginGuard.Unlock` for the administrator console |
| 4 | `CheckOrigin` ignored the scheme | Origin must match scheme and host; `https` is passed in explicitly |
| 5 | netguard allowed some metadata and IPv6 transition ranges (Azure, Alibaba, Oracle, `::/96`, SIIT, Teredo, local NAT64, site-local, documentation, benchmarking) | Added to the never-allowed list |
| 6 | `Rewrap` did not verify the payload; `nil` next panicked | Payload tag is verified before success; `nil` is an error |
| 7 | Rollback to an older blob within one context | Documented; callers put a revision in the context (`connection:<id>:password:v<rev>`) |
| 8 | No safe client-IP / HTTPS detection behind a reverse proxy | `web.ProxyPolicy` (trusted proxies, rightmost-untrusted `X-Forwarded-For`, `X-Forwarded-Proto` only from a trusted peer) |
| 9 | Unbounded concurrent argon2 runs (64 MiB each) | At most min(4, CPUs) at once; a saturated server answers `ErrBusy` (503) |
| 10 | Plain-HTTP loopback cookie is shared across ports | Documented in code; serving over TLS under its own host name removes it |
| 11 | `net.Listen("localhost")` resolved after the policy approved the string | `Serve` checks the address actually bound |
| 12 | Limiter and user store could normalise usernames differently | One `auth.CanonicalUsername` (NFKC, lower case, trimmed) |
| 13 | netguard errors named resolved internal IPs | Generic `Error()`; detail only through `errors.As(*RefusedError)` for the log |

**Wiring requirements for U1-B** (from the review; not code yet):
- Create the connection from structured fields only, never a raw DSN (pgx options such as `sslkey`,
  `sslrootcert`, `passfile`, `service` and multi-host lists would become local-file reads and dial
  targets), and always pass `netguard.Policy.Dialer`. Map `ErrRefused` to one generic API error.
- Streaming endpoints (SSE, WebSocket) are GET requests: apply `auth.CheckSameOrigin`, and extend the
  write deadline with `http.NewResponseController` (the server's 60 s write timeout would cut the stream).
- Create the administrator and consume the bootstrap token in one transaction: validate with
  `Bootstrap.Valid`, create the account, then `Consume`.
- Run `Manager.RunJanitor` in the server so sessions that are never presented again are removed.
- Never put a token in a URL path (the access log records paths, never query strings).
- Use a revision in every vault context that can be replaced in place.

### Slice U1-B, step 1 (done): schema v3 and the SQLite stores

State schema **v3** (`internal/store/schema_web.go`, on top of Phase 3's v2) holds `users`, `sessions` and
`web_audit`. Decisions:

- **Users are disabled, never deleted.** Audit rows and migrations name them; a deleted-then-recreated name
  would inherit that history. Sessions still cascade if a row is removed by hand.
- **Usernames are stored canonical** (`auth.CanonicalUsername`: NFKC, lower case, trimmed), so the UNIQUE
  constraint is the one definition of "same user", matching the login limiter.
- **The last active administrator cannot be demoted or disabled** (`ErrLastAdmin`), checked inside the same
  transaction as the change. A disabled admin does not count as active.
- **`CreateFirstAdmin` inserts only into an empty `users` table, in one transaction**, so concurrent setup
  requests cannot both win (tested with 8 racing callers). Callers still validate the bootstrap token first
  and consume it afterwards.
- **Only digests and hashes reach the disk:** the SHA-256 of a session token and the argon2id PHC string of a
  password. A test scans the state file and WAL for a live token. The store refuses a password hash that is
  not argon2id.
- **`web_audit` is append-only** (triggers refuse UPDATE and DELETE), `detail` is clipped without splitting a
  multi-byte character, and the outcome is constrained to `ok | denied | error`.
- `Store.Sessions()` returns the `auth.SessionStore` implementation, driven in tests by the real
  `auth.Manager` (slide, idle and absolute expiry, revoke, revoke-user, janitor deletion).
- Seven security controls were broken on purpose (last-admin check, active-admin count, first-admin-once,
  expiry predicate, revoke-user scope, audit delete trigger, username canonicalisation); each mutant
  compiled and was killed by a test.

Still to do in U1-B: schema **v4** (connection registry, vault records), the HTTP endpoints and middleware,
audit of mutating requests, the netguard-wired `dbconn`, the read API and `QuerySeries`.
