# ADR 0002: pgcopydb for bulk copy, native logical replication for CDC

- Status: **Accepted** by the owner on 2026-11-06 (option "native subscription"). The handoff
  mechanism in the Decision is a design, **not yet proven**: it is the first deliverable of Phase 3.
- Deciders: owner

## Context

The owner's original decision: use mature tools, call pgcopydb via `os/exec`, don't rewrite it.

Verification on 2026-11-06 found a significant problem in pgcopydb's CDC (`clone --follow`):

- pgcopydb v0.18 (released 2026-06-27) replaced the file-based CDC spool with SQLite (PR #715).
- **Issue #1044 (open):** with `test_decoding`, when transaction A begins first but transaction B
  begins later and commits first, a committed transaction can silently disappear while building the
  replay DB. The CDC checkpoint advances past it, re-running catch-up does not recover it, and the
  exit code is 0. A second reporter reproduced it on a real RDS migration with `wal2json` (2 of
  ~5000 transactions lost) and says it was still present on `main` on 2026-10-16.
- **Issue #1060 (closed 2026-10-16):** on RDS with `wal2json`, a transactional
  `pg_logical_emit_message()` (e.g. heartbeats from other replication tools on the same instance)
  stalled apply, and on `main` follow then reported "endpos reached" with rows missing.
- Heavy churn on `main` (many CDC fixes 2026-10-27…11-03). One maintainer has 509 commits; the next
  contributor has 53 (bus-factor risk).
- Not found: whether #1044 is fixed in a tagged release after v0.18 (unverified).

pgcopydb's bulk-copy side (parallel table copy, index after data, `copy schema/roles/extensions/
sequences`, `compare`) is a different code path and is not implicated by these issues.

## Decision

**Split the job.** pgcopydb does what it is best at; Postgres core does the continuous replication.

1. **pgcopydb (pinned version, external process)**: pre-data schema, parallel table copy, index and
   constraint build, roles, extensions, sequences, and `compare`. It is *not* used for CDC
   (`--follow` is not passed).
2. **Native logical replication for CDC:** a publication on the source, a subscription on the target
   using `pgoutput` and core Postgres's apply workers.
3. **Consistent handoff (the part that must be proven):**
   a. Lockkeeper opens a replication-protocol connection to the source (`replication=database`;
      needs `rds_replication`/`REPLICATION`) and runs
      `CREATE_REPLICATION_SLOT <name> LOGICAL pgoutput (SNAPSHOT 'export')`. This returns the slot's
      consistent point and an exported snapshot id. **That connection must stay open and idle** so
      the snapshot stays valid (Postgres protocol rule).
   b. Run `pgcopydb clone --snapshot <id> …` (no `--follow`). pgcopydb's docs say `--snapshot` re-uses
      an already-exported snapshot. Whether it accepts a snapshot created by another process is
      **unverified**.
   c. When the copy finishes, release the snapshot connection (the slot persists).
   d. On the target: `CREATE SUBSCRIPTION … CONNECTION … PUBLICATION … WITH (create_slot = false,
      slot_name = '<name>', copy_data = false, enabled = false)`, then enable it. Streaming starts at
      the slot's consistent point, which equals the snapshot used for the copy.
   e. Slot creation and the publication are source-mutating actions (plan hash, confirmation, audit).
4. **Cutover wait:** after writes are frozen, read source `pg_current_wal_lsn()` and wait until the
   target subscription's remote LSN (`pg_replication_origin_status` / `pg_stat_subscription`) is at
   or past it. Then reset sequences, verify, and switch apps.
5. **Verification remains a hard gate** (per-table row counts, content checksums — full for small
   tables, range-sampled for large — schema compare, sequences, extensions). A cutover with a failed
   or skipped verification is refused. This guards against *any* engine's bugs, including ours.
6. **Seam kept.** CDC stays behind the Go `Replicator` interface. A `pgcopydb-follow` engine may be
   added later if upstream fixes mature; it is not built now (YAGNI).
7. **Phase 3 begins with a time-boxed spike** in containers that must prove:
   - (3a–3d) the handoff is gap-free and duplicate-free under concurrent writes, including
     overlapping transactions (a permanent regression test), and survives killing pgcopydb mid-copy;
   - `pgcopydb clone --snapshot` accepts an externally exported snapshot — if not, fall back to
     `pg_dump --snapshot` / `pg_restore` for the copy step (parallel `pg_dump -j` supports `--snapshot`;
     unverified here) and keep pgcopydb for `compare`/`sequences` only;
   - every object pgcopydb creates on the **source** (v0.18 keeps its sentinel in local SQLite; some
     older versions kept it in the source; `--replicate-ddl` installs event triggers and stays off);
   - the canary-secret scan over pgcopydb's work dir and logs (ADR 0004);
   - whether the slot can be created over a replication connection on **RDS** with `rds_replication`
     (manual run by the owner against a non-production RDS instance).
8. `pglogrepl` (MIT, active, no tagged releases) or plain `pgx/pgconn` in replication mode can issue
   the `CREATE_REPLICATION_SLOT` command; prefer `pgconn` first (no extra dependency), decide in the
   spike. We do **not** write our own WAL stream decoder.

## Alternatives considered

- **pgcopydb `clone --follow` + mandatory verification.** The earlier recommendation. Rejected by
  the owner in favour of removing the known-buggy component from the CDC path; verification would
  detect loss but not recover from it.
- **Native `CREATE SUBSCRIPTION … copy_data = true` end to end.** Fully core Postgres, no external
  tool, trivial handoff. But initial sync is slower (indexes exist during load; table sync limited by
  `max_sync_workers_per_subscription`; a single huge table is not split) and schema must be
  pre-created. Kept as the **fallback** if the snapshot handoff can't be made reliable, and
  acceptable for small databases.
- **Own CDC reader on `pglogrepl`.** Rejected: this is the "rewrite pgcopydb" path with the highest
  bug risk.
- **Debezium, pglogical, AWS DMS:** heavy dependencies or AWS lock-in; contradict the single-binary
  goal. Not evaluated in depth.

## Consequences

- Most orchestration code we write is in the handoff, the cutover wait, sequence handling and the
  subscription lifecycle — more than wrapping `--follow`, less than a replication engine.
- Native logical replication limits become *our* preflight checks: DDL not replicated (schema
  freeze), sequences not synced, **large objects not replicated**, tables without PK need
  `REPLICA IDENTITY FULL`, target needs `max_logical_replication_workers` / `max_worker_processes`
  headroom, and **the target server (not the tool) opens the connection to the source**, so
  target→source network access must be allowed (the RDS security group must admit the OVH IP).
- The subscription's connection string lives in the target's `pg_subscription` catalog, and may
  appear in server logs if statement logging is on. See ADR 0004.
- pgcopydb is pinned and its bulk-copy path is still validated, but a CDC bug there can no longer
  silently cost data.
