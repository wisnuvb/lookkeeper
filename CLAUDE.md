# Lockkeeper — project context for Claude Code

> Status: **Phase 1, slice 1 is implemented** (PostgreSQL monitoring: collector, alert engine,
> Telegram/Slack, SQLite state, CLI `init`/`config validate`/`check`/`monitor run`/`alerts test`/
> `slots list`). Spec approved by the owner on 2026-11-06. Not built yet: MySQL collector, email,
> Prometheus export, CloudWatch reader (moved to slice 2), web UI and vault, migration (Phases 2-5).
> Run `make ci` (needs `staticcheck` and `govulncheck` in `$(go env GOPATH)/bin`) and
> `make test-integration` (needs Docker) before committing.

## What this is

**Lockkeeper** is a tool for **PostgreSQL and MySQL** that does two things:

1. **Monitoring** — watches database health and sends alerts.
2. **Migration** — moves a database from anywhere (main example: AWS RDS) to another server
   (VPS / dedicated, e.g. OVH, Contabo) with minimal downtime and maximum safety.

Name rationale: a canal lock keeper moves ships between water levels safely while constantly
reading the water level.

- Project name: **Lockkeeper**. Binary: **`lockkeeper`**.
- The short alias `lk` was requested, but **`lk` is already the binary of the LiveKit CLI**
  (Homebrew formula `livekit-cli`, Apache-2.0). We do **not** ship `lk` by default. Docs may tell
  users to add `alias lk=lockkeeper` themselves. If a shipped short name is wanted, candidates
  `lkp`, `lkr`, `lkeep` had no Homebrew formula/cask and no local binary on 2026-11-06 (Debian/apt
  and other package indexes were **not** checked).
- The project may become **open source**, and later a **SaaS**. Keep a clean seam between the
  core (collectors, preflight, migrator, verifier) and anything service-like (see
  `docs/ARCHITECTURE.md`, "Core vs. future service layer"). Keep dependency licenses permissive.
- Go module path: **`github.com/wisnuvb/lockkeeper`** (owner chose their personal account on
  2026-11-06; moving to an org later means rewriting every import path).
- Licence: **Apache-2.0** for the core (owner decision). Create `LICENSE` from the official
  Apache text when implementation starts; keep a dependency-licence list.

## The real first use case

Owner is migrating from AWS to **one dedicated OVH server**. Source: **RDS PostgreSQL** (number and
size of databases not yet inventoried — the tool must help inventory them). Many apps/databases.
A short downtime at cutover is acceptable. Wants automatic sync RDS → OVH before cutover.
**Postgres RDS → self-hosted is the priority path. MySQL comes after Postgres is stable.**

## Technical decisions (approved by owner)

- **Language: Go** (I/O-bound work, single static binary, strong driver/replication ecosystem).
- **Use mature tools; do not rewrite them.** pgcopydb (pinned version) is invoked as an external
  process for the **bulk copy** (schema, tables, indexes, roles, extensions, sequences, compare).
  **CDC uses native Postgres logical replication** (publication/subscription, `pgoutput`), not
  `pgcopydb --follow` (owner decision after finding pgcopydb bug #1044; ADR 0002). The snapshot→slot
  handoff is designed but unproven — Phase 3 starts with a spike. For MySQL, evaluate
  `mydumper`/`myloader` and native binlog replication before building anything.
- **Light footprint:** one binary, light local state (SQLite), no mandatory Docker / Grafana /
  Prometheus. Prometheus export is an optional feature only.
- Language rules: **chat with the owner in Indonesian; code, identifiers, code comments and all repo
  documentation in English.**

## Findings that changed the plan (verified 2026-11-06; details in `docs/SPEC.md` Appendix A)

- **pgcopydb v0.18 has an open silent-data-loss bug in its CDC pipeline** (dimitri/pgcopydb#1044:
  overlapping transactions that commit in a different order than they began can be dropped, exit
  code 0). So CDC goes through native logical replication, **verification (row counts + content
  checksums) is a hard gate before cutover, not an option**, pgcopydb is version-pinned, and the CDC
  engine sits behind an interface. See ADR 0002.
- pgcopydb is maintained mostly by one person (509 commits vs. 53 for the next contributor) — a
  bus-factor risk to track.
- `jackc/pglogrepl` has **no tagged releases** (pseudo-versions only) though it is actively
  maintained. Only relevant if we ever implement our own CDC reader.
- RDS exposes no disk-free metric over SQL, so the WAL-slot guardrail needs either configured
  thresholds in bytes or an optional CloudWatch integration (open question).

## Security principles (non-negotiable)

1. **Read-only by default.** Anything that changes the source (create slot/publication, change
   parameters, create users, `REPLICA IDENTITY FULL`, freeze writes) must be explicit, support
   dry-run, and ask for confirmation. Non-interactive runs must present a **plan hash** that the
   operator passes back; there is no blanket `--yes` for source-mutating actions.
2. **Never delete data on the source.** Cleanup (drop slot, drop migration user) happens only after
   a verified cutover and with explicit confirmation from the owner.
3. **Secrets never leak:** not in logs, not in process arguments visible in `ps`, not in state
   files. Use env vars, strict-permission files, or interactive prompts. Config and state hold
   secret *references*, never values. **TLS is required** for remote databases by default
   (`verify-full`; `require` alone is not enough because it does not authenticate the server).
4. **WAL slot guardrail:** during migration monitor retained WAL per slot; warn, and stop/drop
   consumption before the source disk fills.
5. **Clear, idempotent state machine,** resumable after failure, never silently deleting CDC state.
   Never use `pgcopydb --restart` mid-migration.
6. **Verification is not optional:** row counts, schema comparison, sequences, extensions and
   sampled checksums before cutover.
7. **Written rollback plan.** After cutover, writes on the target do **not** flow back to the
   source; the tool must say so clearly and record the rollback window.

## Phases

1. Monitoring (Postgres + MySQL collectors, alerts to Telegram/Slack/email, light storage, CLI + YAML).
2. Migration pre-flight check (Postgres first), report with severities.
3. Postgres migration orchestrator wrapping pgcopydb with a state machine.
4. Guided cutover and automatic verification.
5. MySQL: pre-flight, dump + binlog migration, verification, cutover.

Owner confirmed this order (2026-11-06): full monitoring first. The Phase 1 MVP slice is the
Postgres collector + alert engine + Telegram/Slack + SQLite + `check`/`monitor run`; the MySQL
collector and email notifier follow within Phase 1.

## Quality bar

- Modern Go; `go vet` and `staticcheck` clean; wrap errors with context; `context.Context` on every
  network/database operation; graceful shutdown.
- Tests for core logic (state machine, pgcopydb output parser, alert-rule evaluation, redaction).
  Integration tests use containers and **never touch a production database** (the test helper must
  refuse non-loopback / non-container hosts).
- Small commits with clear messages. Never commit secrets. Provide `.gitignore` and an example
  config with no real credentials.
- When unsure between two approaches: state the trade-off briefly and recommend one. Don't guess
  silently. Mark anything unverified as unverified.

## Things learned while building slice 1 (keep in mind)

- **A read-only session is not a security boundary.** `default_transaction_read_only=on` does not stop
  a role that has the privilege from creating/dropping replication slots. The least-privilege role
  (`LOGIN` + `pg_monitor`) is the boundary; `pg.AuditRole` warns otherwise. Without `pg_monitor`,
  other users' sessions are invisible and metrics silently read 0.
- **Rules whose meaning is a duration need history** (`Rule.NeedsHistory`, e.g. slot inactive for 10
  minutes). The one-shot `check` skips them and says so; ignoring their `for` gave a false CRITICAL.
- An incomplete collection must never clear active alerts (`Engine.Eval(..., complete)`).
- `go.mod` pins `toolchain go1.27.3`: go1.27.1 had 9 reachable stdlib vulnerabilities.
- **MySQL has the same gap:** `transaction_read_only=1` does not stop `SET GLOBAL`, `FLUSH`,
  `PURGE BINARY LOGS`, `KILL`; required grants are exactly `PROCESS, REPLICATION CLIENT ON *.*`.
  `INNODB_TRX.trx_started` is in the system time zone (sessions use `time_zone='SYSTEM'`).
- Size functions (`pg_total_relation_size`) take locks and can stall behind ACCESS EXCLUSIVE: skip such relations.
- The pre-flight cannot test target->source reachability read-only: it always emits a WARN with a manual command.
- Preflight/inventory report only counts, names, sizes, settings: never data or other sessions' SQL.
- Merging parallel work: git merges can be textually clean yet broken (a missing closing brace once);
  always rebuild and run the whole suite on the merged result.
- The e2e test (`internal/e2e`) runs the real binary and scans `ps`, logs and the state DB for canary
  secrets. Keep it green; extend it when adding anything that handles a secret.

## Local environment notes (2026-11-06)

Go 1.27.x and Docker are installed; `staticcheck` and `govulncheck` were installed with `go install`
into `~/go/bin`. `pgcopydb` is **not** installed locally (needed from Phase 3).

## Decisions made on 2026-11-06

GitHub module `github.com/wisnuvb/lockkeeper`; CDC = native subscription; phase order as in the
original plan (monitoring first); Apache-2.0.

Added later the same day: **self-hosted web UI and dynamic connections are in scope** (ADR 0005,
Phase 1 slice 3; service layer + API are built from slice 1); **optional CloudWatch reader
approved**; bar is "ready for real production" (SPEC section 13). Data size/write rate are unknown —
design handles it (inventory first, relative thresholds). Dependencies verified: see SPEC Appendix A
(note `go-sql-driver/mysql` is MPL-2.0).

For any UI/UX work, **use the `ui-ux-pro-max` skill first** (owner's global rule).

Approved by the owner after that: **spec approved, Phase 1 slice 1 started**; **credential storage =
encrypted vault + references** (ADR 0005 item 4, Option B). This knowingly relaxes the *letter* of
security principle 3 (ciphertext at rest, master key outside the DB). The vault is built with the web
UI slice; until then only `env:`/`file:`/prompt references exist, and nothing else may store a
secret at rest.

## Open decisions (waiting for the owner)

- Name for a shipped short alias (assumed: none).
- Data size / write rate of the RDS source (unknown; inventory will measure it).

## Docs

- `docs/SPEC.md` — goals, non-goals, MVP, config, CLI, state model, metrics/alerts, threat model.
- `docs/ARCHITECTURE.md` — modules, boundaries, pgcopydb invocation, testing.
- `docs/adr/` — decision records (Go; pgcopydb vs. native CDC; state storage; secrets).
