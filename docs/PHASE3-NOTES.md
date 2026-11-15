# Phase 3 notes: PostgreSQL migration orchestrator

Status: working notes of the Phase 3 engineer. Section 1 (the spike) was written and
committed **before** the orchestrator was built on top of it. Later sections are added as the
build proceeds. Nothing here has been run against RDS or any non-container server.

## 1. Spike result (ADR 0002, item 7)

Verdict: **GO.** The exported-snapshot handoff is reliable in containers, with both candidate bulk
copiers, on pg17 -> pg17 and pg14 -> pg17. The documented fallback (native `copy_data=true`
subscriptions) is not needed. The evidence is a permanent regression test:
`internal/migrate/pgnative/spike_integration_test.go` and `spike_privileges_integration_test.go`
(`-tags integration`; they use raw SQL and the replication protocol, not Lockkeeper's orchestration,
so they stay valid as an independent check of the facts below).

Environment: Docker 29.7.2 on macOS/arm64 (so arm64 images), postgres:17-alpine 17.11,
postgres:14-alpine 14.24, `dimitri/pgcopydb:v0.18`
(digest `sha256:8d93b05602689a34cb66b0f2dc090c175646a6b2ce2c7d9804001703ae6218f8`, the multi-arch
index digest). Source `wal_level=logical`, target default settings, on a private Docker network.

### 1.1 What was proven

| # | Question | Result |
|---|---|---|
| a | A replication-protocol connection (`replication=database`) via plain `pgx/pgconn` can create a logical slot and export a snapshot, and stay idle | **Yes.** `CREATE_REPLICATION_SLOT s LOGICAL pgoutput (SNAPSHOT 'export')` returns `consistent_point` and `snapshot_name` in the result row. No `pglogrepl` needed (no extra dependency). **PostgreSQL 14 does not know the parenthesised syntax** (`syntax error`); it needs the legacy `... LOGICAL pgoutput EXPORT_SNAPSHOT`. The code picks by `server_version`. |
| b | Does `pgcopydb clone --snapshot <id>` accept a snapshot exported by another process? | **Yes**, verified on pg14 and pg17 sources: pgcopydb passes it straight to `pg_dump --snapshot` and uses it for the table-data workers. The target held exactly the snapshot's rows. |
| b2 | `pg_dump --snapshot=<id> -Fd -j 4` + `pg_restore -j 4` as the alternative | **Yes**, same results. |
| c | Gap-free and duplicate-free under concurrent writes | **Yes** for both copiers on both version pairs: 4 writer connections doing random insert/update/delete/rollback on a PK table, a ledger and a PK-less `REPLICA IDENTITY FULL` table (4,400 to 5,400 committed transactions per run); ordered-row md5 plus count equal on source and target for every table. Deterministic markers each appear exactly once on the target: a transaction that began **before** slot creation and committed while it waited (spans the snapshot point), C began first and committed last, D began second and committed first, E began after the snapshot and committed after the subscription was enabled. |
| d1 | Is the snapshot usable after the holder connection closes? | **No.** `SET TRANSACTION SNAPSHOT` fails: PG17 `snapshot "..." does not exist`, PG14 `invalid snapshot identifier`. While the holder is open another session can import it. |
| d2 | What happens to the slot when the copy (and holder) die? | The slot **survives, inactive, and keeps retaining WAL**; its `restart_lsn` does not move. |
| d3 | Recovery rule | **Never reuse a slot for a new copy.** A new copy's snapshot is later than the old slot's consistent point, so the subscription would replay changes the copy already contains. On a table without a primary key that is *silent duplication* (test: source 3,500 events, target 4,000); with a PK it is an apply error. The only reusable case is a copy that **completed** and whose data is exactly the slot's consistent snapshot (the process died after the copy but before the subscription existed). So: recovery = drop the old slot, reset the target database, take a new slot+snapshot, copy again; each of these is a confirmed Action. Resume reuses a slot only if the durable record says the copy finished. |
| e | Migration role privileges | The role in the subscription's connection string needs only `LOGIN REPLICATION`: no `SELECT` on the tables, no superuser, no ownership (pg14 and pg17). |
| f | Does a bulk copier create anything on the source? | With a snapshot supplied, **no**: a catalog fingerprint (schemas, relations, functions, triggers, event triggers, publications, extensions, roles, slots) is identical before and after both copiers. pgcopydb v0.18 keeps its state in a local work directory. (`--replicate-ddl` is never passed.) |
| g | Secrets in tool output and work directories | Neither pgcopydb's nor pg_dump/pg_restore's output and work directories contain the source or target password when they are given passwordless URIs and a `PGPASSFILE`. Scanned in the spike test (the passfile itself excluded; the process runner deletes it). |

### 1.2 What does NOT work, or needs care

1. **The stock pgcopydb image cannot clone a PostgreSQL 17 source.** It ships `pg_dump` 16, which
   aborts with `server version mismatch` (observed). pgcopydb runs the `pg_dump` it finds on `PATH`
   (it logs `/usr/bin/pg_dump`). With a PostgreSQL 17 client directory first on `PATH` it works
   (`lockkeeper-test/pgcopydb:0.18-pg17client`, built by `testutil.EnsurePgcopydbImage`). Rule: the
   client tools must be at least the source's major version. The Copier checks this before starting.
2. **`pgcopydb --version` prints an empty version in the official v0.18 image**
   (`pgcopydb version ` with nothing after it). Pinning by `--version` therefore cannot work for that
   image; the Copier pins by parsed version when there is one and otherwise requires an explicit
   `AllowUntested` opt-in. Pin the image digest if you run it in a container.
3. `pgcopydb clone` also resets sequences, and it reads them **live**, not as of the snapshot
   (sequences are not transactional): after the copy the target's sequence was ahead of the copied
   data (`nextval` returned 1051 with `max(id)=1000`). That is the safe direction, and Phase 4 still
   owns the final sequence handling with an explicit gap.
4. **Slot creation waits for open transactions.** `CREATE_REPLICATION_SLOT` blocks until every
   transaction that was running when it started has finished, so a long-running transaction on the
   source delays the start of a migration (and the holder connection is not idle during that wait).
   The orchestrator must run it with a timeout and say why it waits.
5. **The password lands in two more places on the target** (`TestSpikeSubscriptionPasswordVisibility`):
   - `pg_subscription.subconninfo` holds it in plaintext; only superusers can read the column
     (a normal role gets `permission denied`).
   - With `log_statement=all` the `CREATE SUBSCRIPTION` text, password included, is written to the
     server log. The session settings `SET log_statement='none'`, `SET log_min_duration_statement=-1`
     and `SET log_min_error_statement='panic'` (superuser only) keep it out of the log, **including
     the text of a failing statement** (without the last one, a failed `CREATE SUBSCRIPTION` logs the
     statement on error regardless of `log_statement`). Verified with a positive control.
   - **Residual risk, not mitigated:** if `pg_stat_statements` is loaded on the target it keeps the
     `CREATE SUBSCRIPTION` text, password included, readable by superusers and `pg_read_all_stats`.
     The plan warns when it is loaded; the migration role is per-migration and dropped at cleanup,
     which bounds the damage. (Observed with `track_utility` at its default.)
6. Not tested in the spike: `pgcopydb copy sequences` and `pgcopydb compare` (Phase 4), same-table
   split, large objects (logical replication does not carry them; pre-flight warns), and anything on
   amd64, Linux hosts or RDS.

### 1.3 Decisions that follow

- **Handoff accepted as designed in ADR 0002** with the changes in 1.1 d3 (no slot reuse) and the
  server-version-dependent slot command.
- **Copier:** both implementations sit behind `Copier`. Default `pgcopydb` (ADR 0002), `pgdump`
  (`pg_dump -Fd -j` + `pg_restore -j`) selectable; both passed the same handoff regression test, and
  the pg_dump route needs no tool beyond the PostgreSQL client package.
- Tests run bulk-copy tools in containers on the private network (the host has no suitable
  `pg_dump`/`pgcopydb`); production runs them as local processes through the same runner.

## 2. What was built

Packages (all new unless marked): `internal/action` (Action, Plan with canonical JSON and SHA-256,
typed or hash confirmation, executor with intent-before-effect audit), `internal/store` (schema v2,
**edited**: `store.go` gets one appended migration entry; new files `schema_migrate.go`,
`migrations.go`), `internal/migrate` (shared types), `migrate/runner` (process runner),
`migrate/copier` (pgcopydb and pg_dump/pg_restore behind `migrate.Copier`), `migrate/machine` (state
machine, driver, lease, lock file), `migrate/pgnative` (plans, discovery and privilege checks, slot
handoff, subscription readers, engine), `migrate/itest` (end-to-end tests), `dbconn/migrate.go` (the
only read-write and the replication openers), `service/migrate_*.go`, `cli/migrate.go`, and test
helpers in `internal/testutil` (private network, containerised tool launcher, writers).
Edits to existing files: `service/service.go` (two `Deps` fields), `cli/root.go` (passes the version).

### 2.1 How a migration runs

`migrate plan` runs the pre-flight (BLOCKER findings refuse), reads both servers read-only, checks the
roles' privileges, and prints the plan and its hash. It writes only a draft to the local state
database. The migration id (`m` + 8 hex) is derived from the plan's inputs, so planning the same thing
again gives the same hash, and everything Lockkeeper creates carries that id.
`apply-source-changes` (dry run by default) creates the per-migration role, `REPLICA IDENTITY FULL` where
needed and one publication per database. `start` creates, per database, a slot with an exported
snapshot, copies inside it, drops the publication the schema copy brought along, creates the
subscription (`create_slot=false, copy_data=false, enabled=false`) and enables it, then waits until the
lag is within `--max-lag` for `--caught-up-for`. `resume` first reconciles with the servers.
`abort` disables the subscriptions only. `cleanup` (after abort only) drops exactly this migration's
subscriptions, slots, publications and role, each checked by name and marker.

### 2.2 Decisions made while building (each is open to the owner)

1. **Table list, not FOR ALL TABLES.** The publication lists the permanent ordinary tables and leaf
   partitions explicitly (no superuser needed, deterministic plan). A table created after approval is
   refused as schema drift before `apply` and before `start`.
2. **The publication must exist before the slot** (changes decoded before a table is published are not
   sent); the plan order enforces it. The schema copy brings the publication to the target;
   `pg_dump --no-publications` avoids it for the pg_dump copier, and a plan action drops it for
   pgcopydb (which cannot be told).
3. **Per-migration role, SCRAM verifier.** `CREATE ROLE ... PASSWORD '<SCRAM verifier>'`: the clear
   password never reaches the source (statement log, pg_stat_statements). It lives in a 0600 file in the
   0700 migration directory until `cleanup`, and in the target's `pg_subscription` (superusers only).
   On a target that is not a superuser the `SET log_statement` mitigations are impossible; the plan says so.
4. **Recovery instead of slot reuse** (1.1 d3): `resume` shows a recovery plan (drop the subscription and
   old slot, `DROP DATABASE ... WITH (FORCE)` and recreate the target database with its properties, copy
   again under a new slot `..._a2`). It is applied only with `--recovery-plan-hash` or a typed phrase. A
   crash that loses the "copy finished" marker is treated the same way (conservative). The marker is
   written right after the copy returns, before the step result, to keep that window tiny.
5. **Approval model.** `apply-source-changes --plan-hash H --apply` is the approval of the whole plan,
   including `start`; its method and approver are in the audit log (`plan.approved`) and `start` reads
   them back. `abort`, `cleanup` and recovery have their own plans and hashes. There is no `--yes`.
6. **Plan input is stored** (`migrations.input_json`, no secrets) so the plan can be rebuilt exactly after
   the source changed (a table that now has `REPLICA IDENTITY FULL` would otherwise change the plan).
   Every command re-derives the plan from it and refuses if it no longer hashes to the stored hash.
7. **Audit table is `audit_events`**, not `events`: `events` already holds alert events that retention
   prunes.
8. **Two address views.** Lockkeeper and its tools use the configured address; the subscription (target
   to source) uses `--source-peer-addr/--source-peer-sslmode/--source-peer-sslrootcert`, because the two
   can differ (tunnel, VPN). A peer that would not authenticate the source is refused unless the source
   connection has `tls.allow_insecure`.
9. **Caught up** = every database within `--max-lag` (default 4 MiB, measured as source WAL position
   minus the slot's confirmed flush) with a running apply worker for `--caught-up-for` (default 2 min).
10. **No `migrations:` config section** (SPEC section 7): tool locations and options are flags.
    Adding the section means touching `internal/config`.

### 2.3 Tests

- Unit: action tamper tests (one SQL character, endpoint, database entry, order, notice, version all
  change the hash and `Authorize` refuses), store (CAS, lease, append-only triggers, upgrade from schema
  v1 keeps data and the pre-upgrade backup), state table and guards for every pair, runner (empty env,
  modes, `ps`, SIGTERM then SIGKILL of the process group), copiers, plan content, SCRAM, password file.
- Crash injection (`machine/driver_test.go`): the driver is "killed" at every persistence boundary (one
  test per boundary, 30+) and inside the copy; resume reaches `caught_up` with every effect exactly once
  per attempt. A mutation of the recovery rule makes it fail.
- Integration (`migrate/itest`, real CLI in-process, containers for servers and tools): happy path under
  concurrent writes with row-level md5 equality, abort/cleanup with decoy slots/publication/role,
  kill mid-copy (tool killed; driver cancelled) and resume through the recovery plan, kill during
  following with a broken replication connection, plan tamper/drift/typed confirmation/missing
  privileges, canary scan, `REPLICA IDENTITY FULL`.

## 3. Not verified, known risks, open questions

- **Nothing was run against RDS**: `rds_replication` instead of `REPLICATION`, `rds_superuser`
  detection, the SCRAM verifier on RDS, parameter-group changes, the TLS and security-group path from
  the target, `DROP DATABASE ... WITH (FORCE)` on a managed target. These come from documentation.
- Only arm64 containers on macOS were used; Linux and amd64 are untested.
- `pgcopydb copy sequences` and `compare` (Phase 4) were never exercised. The sequence values the copy
  sets are the live ones, ahead of the data; the final handling is Phase 4.
- `CREATE_REPLICATION_SLOT` waits for open transactions: a long transaction on the source delays `start`
  (`--slot-timeout`, default 10 minutes, bounds it).
- If `pg_stat_statements` is loaded on the target it keeps the `CREATE SUBSCRIPTION` text including the
  migration password (plan notice). The role is per migration and dropped at cleanup.
- Recovery drops and recreates a target database: it relies on the target having been empty at plan time
  (checked then) and on the operator's confirmation. It does not prove the database holds only our copy.
- `REPLICA IDENTITY FULL` takes a brief ACCESS EXCLUSIVE lock per table (`lock_timeout` 10s, so it fails
  instead of blocking) and is not reverted by cleanup (stated in the cleanup plan).
- Open questions for the owner: the default for `--max-lag`/`--caught-up-for`; whether `cleanup` should
  also be allowed from `caught_up` after Phase 4 only; whether to add the SPEC `migrations:` config block;
  whether `abort` of a running migration should be allowed to stop the driver itself (now it refuses and
  asks you to stop it); the policy for an optional `guardrail.action: drop_slot` (not built).

## 4. Security review: fixed

An independent review of this branch led to these changes (each has a test that fails without it):

- **M1 Config edited after approval.** Execution connects through the live configuration, while the stored
  plan only fixes what was shown. `loadMigration` (used by apply, start/resume, status, abort, cleanup) now
  compares host, port, user, database, TLS mode and CA file of the source and target with the stored plan
  and refuses before any connection; the server versions are compared after connecting (start/resume/apply).
  The CA file is now part of the displayed (and hashed) copy command line.
- **M2 Subscription sslmode** is a whitelist: verify-full and verify-ca always; require and disable only for a
  loopback peer or with `tls.allow_insecure`; allow, prefer and unknown strings are refused at plan time.
- **M3 Tool output in persisted errors.** pg_restore and pgcopydb quote rows (`DETAIL: Failing row...`,
  `CONTEXT: COPY t, line N`). A failed tool now yields a `runner.ToolError` whose text is the tool, the exit
  status and the log path only; that is what reaches `audit_events`, `steps.error`, `failed_reason` and
  `actions.error`. A tail with the row-quoting lines removed is printed to the terminal only. The raw logs
  stay under `migrations/<id>/logs` (0700) for diagnosis; **cleanup deletes the logs and work directories
  together with the generated password file**, and the cleanup plan says so.
- **L1** A target that already has tables (or a stray slot or subscription with the migration's name) when
  this migration never started a copy of that database is a hard error ("refusing to plan a DROP DATABASE"),
  not a recovery plan. Recovery is only for a copy Lockkeeper itself started (a recorded copy intent).
- **L2** abort and cleanup take the driver lock before reading the state and building the plan.
- **L3** Every plan builder refuses names that contain `{{` or `}}` (a database called `x{{password}}` would
  have received the real password when the template was rendered).
- **L6** start/resume end with a loud warning, naming the status/abort/cleanup commands and the retained WAL
  when known, whenever a slot of the migration is still on the source. Informational: nothing is dropped.
  (It is not printed when the command stops before it has connected, for example on a config edit refusal.)

## 5. Known gaps from the security review (not fixed, on purpose)

- **L4** The ownership marker (`COMMENT ON ROLE/PUBLICATION`) is a separate statement after the `CREATE`: a
  crash between the two leaves an object without its marker, which every later step then refuses to touch
  (safe, but stuck until removed by hand).
- **L5** The read-only observations of the driver (`Observe`, `Progress`, the slot listings for recovery,
  cleanup and the exit warning) use the write-capable session opener, the same as the actions. Nothing writes
  through them, but the session policy does not enforce it. (`migrate status` itself uses read-only sessions.)
- **L7** `action.Approval` is a plain struct: anything in the process can construct one. The real gate is the
  `Approver` callback (`--plan-hash` or the typed phrase) plus `Executor.Authorize` checking the hash; a
  compromised Lockkeeper process is outside the threat model.
- **L8** The state database has no integrity protection against someone who can write the file: `INSERT OR
  REPLACE`, `DROP TRIGGER` and a replaced file bypass the append-only audit triggers. The hash check of stored
  plans detects edits of the plan, not of the audit trail.
- Speculative, not built: the per-migration role has no `VALID UNTIL`; tools have no `Pdeathsig`, so an
  orphaned pgcopydb can outlive a SIGKILLed driver (the lock is released by the kernel, the tool is not);
  stale run directories (passfiles) are swept only at the next `Begin`; a backslash in a database name with
  `standard_conforming_strings=off` is not handled in the subscription conninfo literal.
