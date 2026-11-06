# Lockkeeper — Architecture (draft v0.1)

Companion to `docs/SPEC.md`. Language: Go. Module path: `github.com/wisnuvb/lockkeeper`.
Licence: Apache-2.0.

## 1. Principles

- **Core is a library; the CLI and the web server are thin shells over one service layer** (ADR
  0005). Nothing in core reads globals, flags, env vars or the filesystem directly; those are injected
  (config, clock, secret resolver, store). Authorization and plan-hash enforcement live in the
  service layer, so neither front end can bypass them.
- **Side effects behind interfaces** so the state machine and alert engine are testable without
  databases.
- **Source mutation is a first-class, typed concept** (`Action`), never ad-hoc SQL scattered around.
- Small dependency set; prefer the standard library.

## 2. Module layout

```
cmd/lockkeeper/            main(): wiring, signal handling, exit codes
internal/
  service/                 use-cases (connections, monitor, preflight, migrate); authz + plan-hash checks
  cli/                     command definitions (flag parsing, output formatting only)
  api/                     HTTP JSON + SSE handlers (thin), versioned (/api/v1), secrets write-only
  web/                     embedded static UI assets (go:embed); stack chosen at slice 3 (ADR 0005)
  auth/                    users (argon2id), sessions, roles, CSRF/Origin checks, rate limiting
  vault/                   AEAD secret storage + master-key loading (only if option B approved)
  connreg/                 dynamic connection registry (no source/target role on a connection)
  cloudwatch/              optional RDS metrics reader behind a small interface (AWS SDK v2)
  config/                  YAML load, strict validation, defaults
  secret/                  Value type (redacting), resolvers (env, file, prompt), passfile writer
  redact/                  io.Writer wrapper scrubbing secrets and URI passwords
  dbconn/                  pgx / mysql connection factories: TLS policy, read-only sessions, timeouts
  collector/
    pg/                    metric queries -> []Sample   (version-aware SQL)
    mysql/
  alert/
    rules/                 pure rule engine: samples + time -> events (no I/O)
    notify/                telegram, slack, smtp, webhook behind Notifier
  store/                   SQLite: MetricStore, MigrationStore, AuditLog
  inventory/               read-only discovery (databases, tables, PK-less tables, extensions)
  preflight/
    pg/ mysql/             checks -> Report{Findings}
  migrate/
    machine/               state machine (pure): states, transitions, guards
    plan/                  Plan = ordered []Action + hash
    replicator/            Replicator interface (CDC seam)
    pgcopydb/              process runner + output parsers (Copier impl: bulk copy, sequences, compare)
    pgnative/              native publication/subscription Replicator + slot/snapshot handoff (ADR 0002)
    mysql/                 (Phase 5) dump/load + binlog replicator
  verify/                  row counts, schema diff, sequences, checksums
  guard/                   WAL-slot guardrail (used by monitor and migrate)
  action/                  Action type: Describe(), SQL(), DryRun(), Apply(); audit hook
docs/  testdata/  scripts/
```

`internal/` until an API is stable; promote packages to `pkg/` (or a separate module) deliberately
when a SaaS agent needs them.

## 3. Component boundaries

```
            ┌────────────┐   Samples    ┌────────────┐  Events   ┌───────────┐
  DBs ◀────▶│ collector  ├─────────────▶│ alert rules├──────────▶│ notifiers │
            └─────┬──────┘              └─────┬──────┘           └───────────┘
                  │ persist                   │ read windows
                  ▼                           ▼
                ┌───────────────── store (SQLite) ─────────────────┐
                └───────▲───────────────────▲───────────────▲──────┘
                        │                   │               │
                  ┌─────┴──────┐      ┌─────┴─────┐   ┌─────┴─────┐
                  │  migrator  │─────▶│ verifier  │   │   guard   │ (reads slots, raises events)
                  │ (machine)  │      └───────────┘   └───────────┘
                  └─────┬──────┘
                        │ Copier / Replicator interfaces
                        ▼
         Copier: pgcopydb (os/exec)   Replicator: native subscription   (MySQL tools later)
```

Key interfaces (sketch, not final):

```go
// collector
type Collector interface { Collect(ctx context.Context) ([]Sample, error) }

// alert
type Rule interface { Eval(now time.Time, w Window) []Event }  // pure
type Notifier interface { Send(ctx context.Context, e Event) error }

// store
type MigrationStore interface {
    Load(ctx context.Context, id MigrationID) (Migration, error)
    Transition(ctx context.Context, id MigrationID, from, to State, why string) error // CAS
    RecordStep(ctx context.Context, id MigrationID, s StepResult) error
}
type AuditLog interface { Append(ctx context.Context, e AuditEvent) error }          // append-only

// migrate
type Copier interface {
    Snapshot(ctx context.Context) (SnapshotRef, error)
    CopyData(ctx context.Context, opts CopyOptions) error     // schema, tables, indexes, roles, extensions
}
type Replicator interface {                                     // the CDC seam (ADR 0002)
    Setup(ctx context.Context) error
    Start(ctx context.Context) error
    Progress(ctx context.Context) (Progress, error)             // receive LSN, replay LSN, lag
    SetEndPosition(ctx context.Context, lsn LSN) error
    WaitCaughtUp(ctx context.Context, lsn LSN) error
    Stop(ctx context.Context) error
    Cleanup(ctx context.Context) error                          // separate, confirmed action
}
type Action interface {
    Describe() string; SQL() string; Target() Endpoint
    Apply(ctx context.Context, c Conn) error                    // always audited
}
```

## 4. Core vs. future service layer (open source → SaaS)

- **Agent / control-plane split.** The `lockkeeper` binary is the *agent*: it runs next to the user's
  databases, holds credentials locally, and does all work. A future SaaS adds a **control plane**
  that receives *samples, events and migration status* from agents over HTTPS and sends *commands*
  (e.g. "start preflight"). Credentials never leave the customer side.
- Seams that make this possible without a rewrite: `store` interfaces (swap SQLite for a server DB
  in the control plane), `Notifier` (add a "cloud" sink), `Sample`/`Event`/`AuditEvent` as
  serializable structs with a versioned schema, `context`-driven everything.
- Not built now: multi-tenancy, auth, billing, web UI. The only commitment today is not to paint
  ourselves into a corner (no global state, no UI logic in core, permissive dependency licences).
- Licence hygiene: record licence for every dependency; GPL tools (mydumper) are subprocess-only and
  are not distributed with our binary.

## 5. Calling pgcopydb

Decision context: ADR 0002. Mechanics:

- **Discovery and pinning:** `exec.LookPath` or configured path; run `pgcopydb --version`; require
  the exact pinned version, else refuse unless `--allow-untested-pgcopydb`.
- **Process:** `exec.CommandContext`; own process group; on `ctx` cancel send SIGTERM, wait a grace
  period, then SIGKILL; record outcome in state either way. One child per migration, guarded by a
  lease.
- **Environment:** start from an empty env; set `PGPASSFILE` (per-run `0600` file in a `0700` temp dir,
  removed on exit/signal), set the source/target URIs *without passwords*, set `PATH` and locale only.
  Secrets never on `argv`. (ADR 0004)
- **Work directory:** `--dir <state-dir>/migrations/<id>/pgcopydb` — opaque to us, scanned for canary
  secrets in tests.
- **Output:** stdout/stderr pass through the `redact` writer into a log file; we do not rely on
  scraping prose. Structured sources: `pgcopydb list progress --json`, `list schema --json`,
  and `compare … --json`.
  Parser unit tests use golden files captured from real runs against containers.
- **Typical flow** (ADR 0002; exact flags confirmed in the spike):
  1. `pgnative` creates the publication (confirmed source action) and opens a replication connection
     that runs `CREATE_REPLICATION_SLOT … LOGICAL pgoutput (SNAPSHOT 'export')`, keeping the
     connection idle so the snapshot stays valid.
  2. `pgcopydb clone --snapshot <id> --table-jobs N --index-jobs M` (no `--follow`).
  3. Release the snapshot connection; on the target create the subscription with
     `create_slot=false, copy_data=false`, then enable it.
  4. Monitor `caught_up` via source LSN vs the subscription's remote LSN.
  5. At cutover: freeze writes, wait for the remote LSN to reach the source LSN, disable the
     subscription, `pgcopydb copy sequences` + our `setval` gap, `pgcopydb compare schema`, our own
     row-count/checksum verification.
  6. Subscription, slot, publication and migration user are dropped only in the confirmed `cleanup`
     phase (slot and publication live on the source — a source-mutating action).
- **Never:** `--follow` (not our CDC path), `--restart` mid-migration; automatic cleanup; letting
  pgcopydb install DDL event triggers on the source (`--replicate-ddl`) unless explicitly opted in.
- **Failure handling:** non-zero exit or lost process ⇒ state `failed(step)`. `resume` reconciles
  real state first (slot present? subscription state? remote LSN?). If pgcopydb died mid-copy, the
  exported snapshot is gone; the safe recovery is a documented fresh copy into a clean target
  database while keeping the existing slot only if it is still retaining WAL from before the new
  snapshot — otherwise create a new slot. The exact rule is decided in the spike and encoded in the
  state machine, with a test.

## 6. Concurrency, shutdown, durability

- `errgroup` per daemon: collectors (one goroutine per target, jittered interval), evaluator,
  notifier workers, migration supervisor.
- Every network and DB call takes `context.Context` with timeouts; connection pools are small and
  closed on shutdown.
- Signal handling in `main`: `SIGINT/SIGTERM` cancel the root context; supervisors persist state,
  stop children gracefully, flush notifiers, then exit.
- SQLite in WAL mode; all multi-row updates in transactions; state transitions are compare-and-swap
  on `(id, from_state)`.

## 7. Testing strategy

| Layer | What | How |
|---|---|---|
| Unit (fast, no I/O) | state machine transitions/guards; alert rule evaluation (fake clock, hysteresis, cooldown, dedupe); pgcopydb parsers (golden files); redaction; config validation; plan hash determinism; preflight decision logic on canned catalog results | table-driven tests, `-race` |
| Integration (containers) | collectors against real Postgres (14–18) and MySQL (8.0, 8.4); preflight against a Postgres configured with `wal_level=logical`; full Postgres → Postgres migration through pgcopydb; resume after killing pgcopydb mid-copy; WAL-slot guardrail (inactive slot + generated WAL ⇒ alert); sequence reset; verification catching injected corruption | `testcontainers-go` or docker compose, build tag `integration`; pgcopydb provided via a pinned container image |
| Regression, permanent | **snapshot→slot handoff test** (concurrent writes incl. overlapping transactions during copy ⇒ no gap, no duplicate; kill pgcopydb mid-copy and resume — ADR 0002); **canary-secret scan** (ADR 0004) | part of the integration suite, required in CI |
| Safety harness | test helper refuses any DSN whose host is not loopback or a container started by the test; integration tests never read production config files | enforced in `internal/testutil` |
| MySQL (Phase 5) | dump+binlog flow against two MySQL containers; binlog-purged-before-load failure path | same pattern |
| Static | `go vet`, `staticcheck` (not installed locally — install in CI), `govulncheck`, `gofmt`/`goimports`, `-race` | CI on every PR |

Limits to be honest about: containers can mimic RDS *roles* (`rds_superuser`, `rds_replication`) and
parameters, but not RDS's managed behaviour (reboot-required parameters, storage autoscaling,
proxy/TLS specifics). Real RDS validation is a manual, owner-run checklist against a **non-production**
RDS instance, documented in `docs/`.

## 8. Observability of the tool itself

Structured logging (`log/slog`), levels, always through the redaction writer; `--json` logs for
daemons; optional Prometheus `/metrics` endpoint (off by default) exposing the same samples.

## 9. Distribution

Static binaries for linux/amd64, linux/arm64, darwin/arm64 via a release workflow; checksums
published; no auto-download of pgcopydb — the docs and `lockkeeper doctor` (future) explain how to
install the pinned version.
