# Lockkeeper — Specification (draft v0.1)

Status: **draft for owner review.** Items marked **[DECISION]** need an owner answer; items marked
**(unverified)** were not confirmed from a primary source.

## 1. Purpose

Lockkeeper is a single-binary tool that (1) **monitors** PostgreSQL and MySQL health and alerts, and
(2) **migrates** a live database from anywhere (first target: AWS RDS PostgreSQL) to a server the user
controls, with minimal downtime, strong verification and a written rollback plan.

Gap targeted: one light binary for both engines, built-in alerts, and **migration-aware monitoring**
(replication lag and retained WAL per slot while a migration is running). Existing tools (pgwatch —
Postgres only, Grafana-centric; Percona PMM — multi-engine but heavy; exporters + Prometheus —
DIY; pgMonitor; pgBadger) each miss at least one of those.

## 2. Users

1. **Solo developer / small team** moving off a managed cloud DB to a VPS or dedicated server (the
   owner's case). Comfortable with a CLI, not a database internals expert.
2. **Small-ops teams** running a handful of Postgres/MySQL servers who want alerts without
   deploying Prometheus + Grafana.
3. (Later) **SaaS customers** who want a hosted control plane with the same agent.

## 3. Goals

- G1. Safe-by-default: read-only unless explicitly told otherwise (section 12).
- G2. Postgres RDS → self-hosted migration with seconds-to-minutes of write downtime.
- G3. Every migration ends with automated verification; unverifiable = refused cutover.
- G4. Monitoring that is useful in five minutes: one YAML file, Telegram/Slack/email alerts.
- G5. One static binary, no mandatory Docker/Grafana/Prometheus.

## 4. Non-goals (for now)

- Not a general backup/restore or PITR tool. Not a schema-migration tool (no `gh-ost` / `pt-osc`
  role; `github/gh-ost` is for online schema change and is MIT-licensed, v1.1.11 — irrelevant to
  moving a whole database).
- No bidirectional/reverse replication after cutover in MVP (rollback = go back to source; target
  writes after cutover are lost unless the user opts into a future reverse-replication feature).
- No DDL replication during migration: **schema freeze** is required (section 8).
- No hosted multi-tenant SaaS code (no tenancy, billing, or custody of customer credentials). A
  **self-hosted web UI** *is* in scope (ADR 0005), delivered after the CLI-first monitoring slice.
- No long-term TSDB. No managing the source's cloud infrastructure (security groups, parameter
  groups): the tool *tells* the user what to change, and can print the exact AWS CLI commands.
- Not a hosting/provisioning tool for the target server (user installs Postgres; we check it).

## 5. Minimum useful product (proposed)

**Owner decision (2026-11-06): keep the original phase order, monitoring first.** The smallest
useful first release is therefore a slice of Phase 1, read-only, with no source mutation:

**MVP (Phase 1, slice 1):**

- Postgres collector: connections, idle-in-transaction, long queries, locks, **replication slots and
  retained WAL**, replication lag, XID age, cache hit ratio.
- Alert engine (thresholds, `for`, hysteresis, cooldown, dedupe) with **Telegram and Slack**.
- SQLite store, YAML config with secret references, TLS `verify-full`.
- CLI: `init`, `config validate`, `check` (one-shot, exit code by severity), `monitor run` (daemon),
  `alerts test`, `slots list`.

The slice also lays the **service layer and API shape** (ADR 0005) so the web UI later needs no
rewrite, and an **optional CloudWatch reader** for RDS free storage (owner approved).

**Phase 1, slice 2:** remaining Postgres metrics (bloat, autovacuum, temp files, checkpoints,
`pg_stat_statements`), **MySQL collector**, email notifier, optional Prometheus export.

**Phase 1, slice 3 — web UI:** `lockkeeper serve`, authentication, dynamic connection registry
(add/test/remove any database; source/target chosen per migration), dashboard, alerts, slots view.
The migration wizard UI arrives with Phases 3–4 behind the same server-side confirmations.

Then Phase 2 (pre-flight, with `inventory`), Phase 3 (orchestrator), Phase 4 (cutover), Phase 5 (MySQL).
Note: the slot/WAL rules are in slice 1 on purpose, so the safety net exists before any migration
tooling does.

## 6. Features by phase

| Phase | Feature | Notes |
|---|---|---|
| 1 | Postgres collector | queries `pg_stat_*`, `pg_replication_slots`, `pg_locks`; no extension required, `pg_stat_statements` optional |
| 1 | MySQL collector | `performance_schema`, `SHOW GLOBAL STATUS`, replica status, InnoDB metrics |
| 1 | Alert engine | thresholds, `for` duration, hysteresis, cooldown, severity, dedupe |
| 1 | Notifiers | Telegram, Slack webhook, SMTP email, generic webhook |
| 1 | Storage | SQLite ring buffer, retention days |
| 1 | CLI + YAML config | `config validate`, `check` (one-shot), `monitor run` (daemon) |
| 1 | Service layer + JSON/SSE API | CLI and web are thin front ends over one service (ADR 0005) |
| 1 | Dynamic connection registry | connections have no role; source/target chosen per migration or monitor target |
| 1 | CloudWatch reader (optional) | RDS `FreeStorageSpace` (and CPU/IOPS later) via AWS SDK v2; read-only IAM |
| 1 | Web UI (slice 3) | `lockkeeper serve`; auth, roles, CSRF; embedded static assets; UI designed with the `ui-ux-pro-max` skill first |
| 2 | Postgres pre-flight | section 8.1 |
| 3 | Postgres migrator | state machine (section 9); pgcopydb for bulk copy, native logical replication for CDC (ADR 0002) |
| 4 | Guided cutover + verify | section 8.3–8.4 |
| 5 | MySQL pre-flight, dump + binlog migration, verify, cutover | section 8.5 |

## 7. Configuration (draft)

YAML, versioned, **secret references only** (ADR 0004). Example (no real credentials):

```yaml
version: 1

databases:
  rds-main:
    engine: postgres
    host: example-db.abc123.eu-west-1.rds.amazonaws.com
    port: 5432
    database: postgres
    user: lockkeeper_monitor
    password: { env: LK_RDS_MAIN_PASSWORD }      # or { file: /etc/lockkeeper/secrets/rds-main } or { prompt: true }
    tls: { mode: verify-full, ca_file: /etc/lockkeeper/rds-ca-bundle.pem }
    read_only: true                              # session forced read-only; cannot be turned off for monitoring
    # RDS gives no disk-free over SQL. Preferred: read it from CloudWatch (read-only IAM:
    # cloudwatch:GetMetricData; credentials from the standard AWS chain, never stored here).
    cloudwatch: { region: eu-west-1, db_instance_id: example-db }
    # Fallback when CloudWatch is not configured: lets "retained WAL" be judged as a % of disk.
    disk_total_gb: 500

  ovh-main:
    engine: postgres
    host: 203.0.113.10
    database: postgres
    user: lockkeeper_admin
    password: { file: /etc/lockkeeper/secrets/ovh-main }
    tls: { mode: verify-full, ca_file: /etc/lockkeeper/ovh-ca.pem }

monitor:
  interval: 30s
  retention: 14d
  targets: [rds-main, ovh-main]

alerts:
  channels:
    telegram:
      bot_token: { env: LK_TELEGRAM_TOKEN }
      chat_id: "123456789"
    slack:
      webhook_url: { env: LK_SLACK_WEBHOOK }
  routes:
    - match: { severity: [critical] }
      to: [telegram, slack]
    - match: { severity: [warning] }
      to: [slack]
  rules:                                          # overrides of defaults in section 10
    pg.slot.retained_wal_bytes:
      warning: 5GiB
      critical: 20GiB

store:
  path: ~/.local/state/lockkeeper/lockkeeper.db   # 0600 file, 0700 dir

server:                                           # only used by `lockkeeper serve` (ADR 0005)
  listen: 127.0.0.1:8443                          # non-loopback requires tls + auth, else refuse to start
  tls: { cert_file: /etc/lockkeeper/tls.crt, key_file: /etc/lockkeeper/tls.key }
  vault:                                          # only if credential option B is approved
    master_key: { file: /etc/lockkeeper/master.key }   # never stored in the DB

migrations:
  cdc:
    engine: native-subscription                   # ADR 0002; other engines may be added behind the same interface
  pgcopydb:
    path: /usr/local/bin/pgcopydb
    version: "0.18"                               # pinned; unknown versions refused without --allow-untested-pgcopydb
    table_jobs: 4
    index_jobs: 4
```

Connections may instead be created dynamically (UI/API/`lockkeeper connections add`) and live in
the local DB; YAML entries are read-only and take precedence on name clashes. A connection carries
no "source"/"target" role.

Rules: unknown keys are errors; inline plaintext secrets are errors; file permissions of referenced
secret files and of the config itself are checked.

## 8. Migration design

### 8.1 Pre-flight checks (Postgres, read-only)

Each check returns `OK | INFO | WARN | BLOCKER`, a message, and a remediation (with exact SQL / AWS
steps where possible). Report is human-readable and `--json`.

| Area | Check | Severity if failing |
|---|---|---|
| Connectivity | TCP/TLS reachability tool→source and tool→target; `verify-full` succeeds | BLOCKER |
| Connectivity | **target→source** reachability (the target server opens the subscription connection; RDS security group must admit the target IP). Tested with `dblink` on the target if installable, otherwise a documented manual `psql` check | BLOCKER (WARN if untestable) |
| Target params | `max_logical_replication_workers`, `max_worker_processes`, `max_sync_workers_per_subscription` leave headroom; role can `CREATE SUBSCRIPTION` (superuser or `pg_create_subscription`) | BLOCKER |
| Target logging | `log_statement` / `log_min_duration_statement` would capture the subscription conninfo (ADR 0004) | WARN, needs acknowledgement |
| Objects | **large objects** (not replicated by logical replication) present | WARN with size, needs a plan |
| Source slots | can create a logical slot over a replication connection (`rds_replication` / `REPLICATION`) | BLOCKER |
| Versions | source and target major versions; target ≥ source (logical replication across versions is supported, downgrade is not) | BLOCKER if target < source |
| Source params | `wal_level = logical` (on RDS: `rds.logical_replication = 1`, **static; needs reboot**) | BLOCKER |
| Source params | `max_replication_slots`, `max_wal_senders` ≥ needed | BLOCKER |
| Source params | `wal_sender_timeout` — pgcopydb docs say 0 for the migration user so long copies keep the slot (set per-role) | WARN |
| Source privileges | migration user has `rds_replication` (RDS) / `REPLICATION` and can read all tables | BLOCKER |
| Source privileges | user that enabled `rds.logical_replication` had `rds_superuser` | INFO |
| Slots | existing slots, inactive slots, retained WAL per slot now | WARN / BLOCKER if retained WAL already large |
| Tables | tables without primary key → need `REPLICA IDENTITY FULL` (or are excluded) | WARN with list and size |
| Tables | partitioned / unlogged / foreign tables, large objects, generated columns | INFO/WARN |
| Extensions | source extensions not installable on target | BLOCKER |
| Data | database sizes, largest tables, estimated copy time | INFO |
| Schema freeze | no active DDL (`pg_stat_activity`), list of DDL-heavy apps if known | INFO |
| Target | free disk ≥ 1.5× source size, `max_connections`, locale/encoding match, empty database | BLOCKER |
| Target | roles referenced by source objects exist or will be copied | WARN |
| Clock/network | latency source→tool, throughput sample | INFO |

### 8.2 Logical replication constraints (carried into UX text)

- Logical replication carries **data only, not DDL**; **sequences are not synchronized** — must be
  reset/copied at cutover; tables without PK need `REPLICA IDENTITY FULL`.
- RDS: `rds.logical_replication=1` + reboot; user needs `rds_superuser` to enable and
  `rds_replication` to manage slots. Supported plugins: `pgoutput` (since 10.4), `test_decoding`,
  `wal2json`.
- **An unread slot retains WAL and can fill the RDS disk.** The tool monitors this continuously and
  enforces the guardrail in 10.3.

### 8.3 Cutover (guided)

1. Preconditions: state `caught_up`, replication lag below threshold for N minutes, pre-flight
   re-run clean, verification pass #1 clean (non-blocking, online).
2. **Freeze writes at source.** Preferred: the operator stops/pauses the apps (tool prints a
   checklist). Optional, explicit, confirmed, dry-run-able: set `default_transaction_read_only = on`
   on the source database and terminate non-migration sessions (this *is* a source change).
3. Record the source's current WAL LSN; wait until the target subscription's remote LSN has reached
   it (`pg_replication_origin_status` / `pg_stat_subscription`); then disable the subscription.
4. Copy/reset sequences with a safety gap (`pgcopydb copy sequences` then our own `setval` gap);
   run `compare schema` + final row-count and checksum verification.
5. **Gate:** any verification failure or skipped verification ⇒ cutover refused (the owner may
   `abort` and keep the source live).
6. Operator switches application connection strings. State → `cutover_done`; rollback window opens.

### 8.4 Verification (mandatory)

Row counts per table; schema diff (tables, columns, indexes, constraints, triggers, views,
functions); sequence values; extensions and versions; content checksums — full for small tables,
sampled and range-partitioned (e.g. by PK ranges) for large ones; result persisted in the audit log.
Motivation: silent data loss is the worst failure of a migration tool. pgcopydb's CDC bug #1044 is
why CDC does not use it (ADR 0002), but verification guards against *any* engine's bugs, ours included.

### 8.5 Rollback

- Before `cutover_done`: abort → source untouched except a dropped slot (still manual), apps unchanged.
- After `cutover_done`: rollback = point apps back to the **source**. **Writes made on the target
  after cutover are not replicated back** and would be lost. The tool states this at cutover time,
  requires typed acknowledgement, and stores `rollback_window_until` (default 7 days, configurable)
  during which cleanup of the source is blocked. Optional future feature: reverse replication.
- The tool **never deletes data on the source**; `cleanup` only drops migration artefacts (slot,
  publication, migration user) after the window and typed confirmation.

### 8.6 MySQL path (Phase 5; research notes, mostly verified from AWS docs 2026-11-06)

AWS procedure "Exporting data from a MySQL DB instance by using replication": external server must
be the same or a **later** version; replication to an external DB is supported **only for the
duration of the export**; backup retention must be > 0 (that turns on binary logging); raise binlog
retention (`CALL mysql.rds_set_configuration('binlog retention hours', N)`); create a read replica
and `CALL mysql.rds_stop_replication` on it so binlogs are kept; read coordinates from
`SHOW REPLICA STATUS` (`SHOW SLAVE STATUS` before 8.0.23); dump with `mysqldump --single-transaction
--routines --triggers`; load into target; `CHANGE MASTER TO` (AWS page still uses this; we will use
`CHANGE REPLICATION SOURCE TO` on ≥ 8.0.23) + `START REPLICA`; wait until caught up;
`STOP REPLICA`; then `CALL mysql.rds_start_replication` on the RDS read replica so RDS can purge binlogs
again. If binlogs are purged before the dump is loaded, start over.

Known: `binlog_format` is deprecated since MySQL 8.0.34 and row-based is recommended for new
replication; MySQL 8.4 defaults to ROW. GTID is supported on RDS 5.7/8.0/8.4 (`gtid_mode`,
`enforce_gtid_consistency`).

**Still unverified, to research before Phase 5:** SSL options for the replication channel
(`SOURCE_SSL*`), definer rewriting on load, timezone and charset/collation differences, exact
`mysql`/`sys` schema exclusion list, whether `SOURCE_AUTO_POSITION` (GTID) works from an external
replica against RDS, and the choice mydumper/myloader (GPL-3.0, invoke as a subprocess only, never
bundle) vs. mysqldump (the AWS-documented route).

## 9. Migration state model

States (persisted in SQLite; transitions logged to the audit log):

```
draft ─▶ preflight_ok ─▶ source_changes_approved ─▶ copying ─▶ following ─▶ caught_up
                                                                               │
          ┌────────────────────────────────────────────────────────────────────┘
          ▼
   cutover_started ─▶ writes_frozen ─▶ drained ─▶ verified ─▶ cutover_done ─▶ cleanup_pending ─▶ cleaned
                                                                    │
   any state ─▶ failed(step, resumable)         cutover_done ─▶ rolled_back (apps pointed back; target writes lost)
   draft…caught_up ─▶ aborted (source slot cleanup is a separate confirmed action)
```

Rules:

- **Intent-then-effect:** write the intended step to the DB, perform it, record result. On resume,
  *reconcile with the real world* (does the slot exist? what is replay LSN?) rather than trusting the
  last recorded step. Every step is idempotent.
- `failed` is resumable; `resume` never passes `--restart` to pgcopydb and never deletes CDC state.
- Exactly one lockkeeper process may drive a migration (lock file + DB lease).
- Tables: `migrations`, `steps(attempt, status, error)`, `checkpoints(lsn, endpos)`,
  `actions` (each source-mutating action: SQL text, plan hash, approver, timestamp),
  `events` (append-only). No secrets.

## 10. Metrics and alert rules

Defaults are conservative starting points, all overridable. Evaluation: a rule fires when the
condition holds for `for` duration; resolves with hysteresis; per-rule cooldown prevents spam.

### 10.1 PostgreSQL

| Metric id | Source | Warning | Critical |
|---|---|---|---|
| `pg.connections.used_ratio` | `pg_stat_activity` / `max_connections` | > 80% for 5m | > 95% for 2m |
| `pg.idle_in_tx.max_age_s` | `pg_stat_activity` | > 300 | > 1800 |
| `pg.query.longest_s` | `pg_stat_activity` (active) | > 300 | > 1800 |
| `pg.locks.blocked_s` | `pg_locks` + activity | > 30 | > 300 |
| `pg.slot.retained_wal_bytes` (per slot) | `pg_replication_slots` + `pg_wal_lsn_diff` | > 5 GiB | > 20 GiB or > 20% of `disk_total_gb` if set |
| `pg.slot.active` (per slot, 1/0) | `pg_replication_slots.active` | = 0 for 10m | = 0 for 60m |
| `pg.repl.lag_bytes` / `lag_s` | `pg_stat_replication` | > 256 MiB / 60s | > 2 GiB / 600s |
| `pg.xid.age` | `age(datfrozenxid)` | > 750M | > 1.5B (wraparound at ≈ 2.1B) |
| `pg.mxid.age` | `mxid_age(datminmxid)` | > 750M | > 1.5B |
| `pg.cache.hit_ratio` | `pg_stat_database` | < 95% for 15m | < 90% for 15m |
| `pg.checkpoint.req_ratio` | `pg_stat_checkpointer`/`bgwriter` (version-dependent view) | > 30% | > 60% |
| `pg.temp.bytes_rate` | `pg_stat_database.temp_bytes` | configurable | configurable |
| `pg.bloat.dead_tuple_ratio` (per table) | `pg_stat_user_tables` | > 20% and > 100k rows | > 40% and > 1M rows |
| `pg.autovacuum.last_age_s` (big tables) | `pg_stat_user_tables` | > 3d | > 14d |
| `pg.db.size_growth` | `pg_database_size` | informational | — |
| `pg.statements.top` | `pg_stat_statements` (optional) | informational report, no alert | — |

### 10.2 MySQL

| Metric id | Source | Warning | Critical |
|---|---|---|---|
| `my.connections.used_ratio` | `Threads_connected` / `max_connections` | > 80% | > 95% |
| `my.threads.running` | `Threads_running` | > 2× cores | > 4× cores |
| `my.repl.io_running` / `sql_running` | `SHOW REPLICA STATUS` | — | not `Yes` for 1m |
| `my.repl.lag_s` | `Seconds_Behind_Source` | > 60 | > 600 |
| `my.slow_queries.rate` | `Slow_queries` | configurable | configurable |
| `my.innodb.buffer_pool_hit` | InnoDB status vars | < 99% | < 95% |
| `my.innodb.row_lock_waits` / deadlocks | `performance_schema`/status | rate-based | rate-based |
| `my.innodb.history_list_length` | `information_schema.INNODB_METRICS` | > 100k | > 1M |
| `my.binlog.disk_bytes` | `SHOW BINARY LOGS` | configurable | configurable |

### 10.3 Migration-aware rules (active only while a migration exists)

- **WAL guardrail:** warn at the warning threshold of `pg.slot.retained_wal_bytes`; at the critical
  threshold alert on every channel with the exact remediation. Pausing the consumer does not help
  (an unread slot grows *faster*); the real remedies are fixing the consumer or dropping the slot,
  and dropping a slot is a source-mutating action. So: the default is **alert loudly, never act
  silently**. An optional `guardrail.action: drop_slot` may be configured, but it still requires an
  explicit, recorded approval (e.g. a pre-authorised plan hash) and abandons the CDC state, forcing
  a restart of the follow phase. The exact policy is an open design item for Phase 3 to confirm with
  the owner.
- Replication lag trend: alert when lag is not decreasing for 10 minutes during `following`.
- Stalled apply: subscription remote LSN not advancing while the source LSN advances (also the
  symptom of pgcopydb #1060, a reminder that "reported progress" and "applied progress" differ).

RDS disk-free is not visible over SQL. **Owner approved an optional CloudWatch reader**
(`aws-sdk-go-v2/service/cloudwatch`, Apache-2.0, v1.75.5 verified 2026-11-06). Metric
`pg.disk.free_ratio` / `rds.free_storage_bytes` (CloudWatch `FreeStorageSpace`): warning < 20% free,
critical < 10% free. With it, the WAL rules become relative: critical when retained WAL exceeds
**50% of current free storage** (or the absolute threshold, whichever is lower). Without it, fall back
to absolute byte thresholds and `disk_total_gb`. The reader is optional, read-only, uses the standard
AWS credential chain (never stored by us) and the AWS SDK is only linked behind a build-neutral
interface so the core stays usable without AWS. Because data size is still unknown, `inventory` and
the first monitoring run report real sizes and growth rates before any threshold is trusted.

## 11. CLI (draft)

Binary `lockkeeper`. (No shipped `lk` alias — name clash with LiveKit CLI; see CLAUDE.md.)

```
lockkeeper init                              write an example config (no secrets)
lockkeeper config validate
lockkeeper serve [--listen ADDR]             web UI + API (ADR 0005); loopback by default
lockkeeper connections add|list|test|rm      dynamic registry; `test` is read-only; secrets via prompt/env/file, never argv
lockkeeper users add|list|disable            web users (argon2id); first admin via one-time token
lockkeeper inventory   [--source NAME] [--json]
lockkeeper preflight pg --source NAME --target NAME [--json]
lockkeeper check       [--target NAME]       one-shot metrics + rules, exit code reflects severity
lockkeeper monitor run                       daemon: collect, evaluate, alert
lockkeeper alerts test [--channel NAME]
lockkeeper slots list|drop SLOT              drop = source-mutating, confirmed
lockkeeper migrate plan  --source --target   prints actions + plan hash; changes nothing
lockkeeper migrate apply-source-changes --plan-hash H   [--dry-run]  explicit, confirmed
lockkeeper migrate start | status | logs | resume | verify
lockkeeper migrate cutover                   guided, typed confirmations
lockkeeper migrate rollback | abort | cleanup
lockkeeper version                           also prints pinned/detected pgcopydb version
```

Conventions: read-only commands never need confirmation. Source-mutating commands are dry-run by
default (`--apply` to execute), show the exact SQL, and require either an interactive typed
confirmation or `--plan-hash <hash>` from a prior `plan`. No global `--yes`. Exit codes:
0 ok, 1 error, 2 warnings (for `check`), 3 critical/blockers.

## 12. Threat model

Assets: production data, database credentials, replication slot health, integrity of the migrated data.

| # | Threat | Mitigation |
|---|---|---|
| T1 | Credential leak via logs, error messages, `ps`, state files | ADR 0004: references only, `secret.Value` type, redaction writer, passfile for children, canary test |
| T2 | Network MITM / sniffing between tool and DB | TLS required, `verify-full` default, warning banner on weaker modes |
| T3 | Tool modifies or damages the source accidentally | read-only sessions, dry-run, plan hash, typed confirmations, audit log of every source-mutating action, no source deletes, test helper refuses non-loopback DBs |
| T4 | Unread slot fills source disk (outage) | slot monitoring, guardrail rules, alert-first policy, runbook for slot cleanup |
| T5 | Silent data loss in CDC or in the snapshot→slot handoff | native logical replication (not pgcopydb `--follow`), mandatory verification gate, overlapping-transaction + concurrent-write regression tests, swappable engine |
| T13 | Source password stored in target `pg_subscription` / echoed in target logs | dedicated short-lived migration user, per-migration password, dropped at cleanup, logging pre-flight warning (ADR 0004 item 7) |
| T6 | Duplicate/parallel runs corrupt state | single-driver lease + lock file, idempotent steps, reconcile on resume |
| T7 | Supply chain: malicious/compromised pgcopydb or dependency | pin version + verify checksum/signature where published (unverified), `govulncheck` in CI, minimal deps, never auto-download binaries without confirmation |
| T8 | Local privilege / file exposure of config, state, passfile | modes 0600/0700 enforced, temp dir per run, cleanup on exit and on signals |
| T9 | Alert channel abuse (stolen webhook/token, spam, false alerts) | secrets via refs, rate limits, dedupe, no sensitive data in alert bodies (no queries with literals; hostnames/ids only) |
| T10 | Logged SQL text contains customer data (e.g. `pg_stat_activity.query`) | never persist or send raw query text by default; opt-in with truncation and literal scrubbing |
| T11 | Rollback misunderstanding after cutover | explicit statement + typed acknowledgement + rollback window blocks cleanup |
| T12 | SaaS future: tenant data/credential isolation | out of scope now; agent model keeps credentials on the customer side (ARCHITECTURE) |
| T14 | Unauthenticated or weakly authenticated web access to a server holding production credentials | loopback default, refuse non-loopback without TLS + auth, argon2id, rate limiting, session revocation, documented "never expose to the internet" |
| T15 | Browser attacks: CSRF, XSS, DNS rebinding, clickjacking | CSRF tokens + `Origin`/`Host` checks, strict CSP, no third-party assets, `SameSite=Strict`, frame denial |
| T16 | UI/API used to trigger source-mutating actions without intent (compromised session, buggy UI) | server-side plan-hash + typed confirmation + role check on every mutating endpoint; audit log with user identity |
| T17 | Credential exfiltration through API, logs, backups or a copied DB file | API is write-only for secrets; redaction on all sinks; vault stores ciphertext with master key outside the DB (if option B approved); canary scan covers API responses and the DB file |
| T18 | Privilege escalation between roles (viewer → operator → admin) | role checks centralised in the service layer, per-route tests that assert denial for every role/route pair |

## 13. Quality and testing summary

See ARCHITECTURE.md section 7. Gate for each phase: `go vet`, `staticcheck`, `go test -race`,
`govulncheck`, integration tests in containers, canary-secret scan.

**Production-readiness bar (owner asked for "ready for real production")** — a phase is not done until:

- Graceful shutdown and crash-safe state; every long operation resumable; `healthz`/`readyz`
  endpoints and a systemd unit (plus an optional Dockerfile) for the daemon/server.
- Versioned SQLite schema migrations with automatic pre-upgrade backup of Lockkeeper's own DB, and a
  documented backup/restore of that DB.
- Structured logs with redaction, bounded log/metric retention, no unbounded memory growth
  (soak test of the collector for ≥ 24h in CI-nightly), bounded concurrency and timeouts everywhere.
- Notifier delivery is retried with backoff, de-duplicated, and a dead-man alert exists ("Lockkeeper
  itself stopped collecting") so silence is never mistaken for health.
- Release engineering: reproducible static builds, checksums + signatures, SBOM, `govulncheck` gate,
  dependency-licence report, semantic versioning with a changelog.
- Documentation: install, upgrade, runbooks (slot cleanup, failed migration, rollback), and a
  security guide. Manual validation checklist against a **non-production** RDS instance before the
  first real migration.

## 14. Open questions (owner)

Decided 2026-11-06: module `github.com/wisnuvb/lockkeeper`, Apache-2.0, CDC = native subscription,
phase order as in section 5, **web UI + dynamic connections in scope (ADR 0005)**, **optional
CloudWatch reader approved**, "production-ready" bar in section 13.

Still open:
- **Credential storage for UI-created connections** (ADR 0005 item 4: references only / encrypted
  vault / session-only). Recommendation: encrypted vault + references. Needs owner approval because it
  relaxes the letter of security principle 3. Until answered, only `env:`/`file:` references are
  implemented.
- Data size and write rate: **unknown** (owner doesn't know yet). Handled by design: inventory and
  growth reporting come first, thresholds are relative to free storage when CloudWatch is on, and
  copy-time estimates are computed from measured throughput, not assumed.
- Where the server runs: assumption is the **destination server**, reached over loopback/SSH tunnel/VPN.
  Because the web server holds production credentials, it should not be exposed directly to the internet.
- No shipped short alias (name clash).

## Appendix A — Verification log (2026-11-06)

Source of truth: GitHub API (`gh api`), project docs, AWS docs. "Active" means a commit within the
last ~5 weeks.

| Item | Result |
|---|---|
| `jackc/pgx` | MIT, **v5.11.0** (2026-09-07), `go 1.25.0`, last push 2026-11-05, not archived |
| `jackc/pglogrepl` | MIT, last commit 2026-10-03, **no tags/releases** (use pseudo-version); still maintained |
| `go-mysql-org/go-mysql` | MIT, last push 2026-11-06, recent tag v1.16.0 (ordering of tag list not verified), `canal` and `replication` packages exist (not inspected) |
| `cybertec-postgresql/pgwatch` | **BSD-3-Clause**, v6.1.0 (2026-10-26), Postgres-only; README is Grafana-dashboard oriented → gap claim holds |
| `github/gh-ost` | MIT, v1.1.11 (2026-08-17); online schema change tool, not relevant to MVP |
| `dimitri/pgcopydb` | **PostgreSQL License** (GitHub API shows `NOASSERTION` but LICENSE file and README state PostgreSQL License), **v0.18** (2026-06-27), main active through 2026-11-03, bundles third-party deps (NOTICE file) → check NOTICE before redistributing. v0.18 moved CDC spool to SQLite (#715). **Open issue #1044 silent transaction loss; #1060 wal2json message stall (closed 2026-10-16).** Provides `--json` for `list`/`compare`, `list progress --json`, `stream sentinel` controls |
| `supabase/etl` (formerly `pg_replicate`) | Apache-2.0, Rust, active; not needed for a Go design |
| `mydumper/mydumper` | **GPL-3.0**, active (release 2026-11-05); use only as an external process, never link/bundle |
| `lk` name | **Clash:** LiveKit CLI installs `lk` (Homebrew `livekit-cli` 2.19.3, Apache-2.0). `lkp`, `lkr`, `lkpr`, `lkeep`, `lkc`, `lkd`: no Homebrew formula/cask, not in local PATH |
| `lockkeeper` name | No Homebrew formula. GitHub has ≥ 7 small unrelated repos with this name (an AI-agent skill router, an Android app locker, etc.), none in database tooling. Domain, Go module, Docker Hub, and trademark were **not** checked |
| AWS "Exporting data from a MySQL DB instance by using replication" | Read in full; facts in 8.6 |
| AWS binlog docs | `mysql.rds_set_configuration('binlog retention hours', N)`, `rds_show_configuration`; binary logging requires backup retention > 0; `binlog_format` deprecated since 8.0.34, row-based recommended for new replication setups |
| MySQL `CHANGE REPLICATION SOURCE TO` | Exists in 8.4 manual; option-level details (SSL, auto-position) not read |
| pgcopydb `--snapshot` | Documented: `clone --snapshot` re-uses an already-exported snapshot; `pgcopydb snapshot` exports one; with `--follow` pgcopydb itself creates the slot via `CREATE_REPLICATION_SLOT`. **Not verified:** that it accepts a snapshot exported by a different process (first item of the Phase 3 spike) |
| Not verified | RDS Postgres facts the owner supplied (taken as given); mydumper behaviour with RDS; pgcopydb `NOTICE` content; whether #1044 has a fix released after v0.18; exact IAM policy for the CloudWatch reader; mydumper/RDS interplay |
| Dependencies (verified 2026-11-06 via `go mod download`) | `modernc.org/sqlite` v1.61.1 BSD-3-Clause (pure Go); `aws-sdk-go-v2/service/cloudwatch` v1.75.5 Apache-2.0 (repo active 2026-11-05); `spf13/cobra` v1.10.2 Apache-2.0; `golang.org/x/crypto` v0.58.0 BSD-3-Clause; **`go-sql-driver/mysql` v1.10.1 is MPL-2.0** (file-level copyleft: fine to depend on unmodified under Apache-2.0, but modifications to its own files must be published; list it in the licence report) |
