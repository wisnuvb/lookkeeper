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
