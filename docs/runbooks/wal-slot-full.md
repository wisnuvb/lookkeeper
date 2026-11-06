# Runbook: the source is retaining too much WAL (replication slot)

Applies while a migration is `copying` or `following` (and after `abort`, until `cleanup`).

## Why it matters

A replication slot makes the source keep every WAL segment the slot has not yet confirmed. If the
consumer (the target's subscription) stops or falls far behind, WAL piles up on the source's disk.
On a full disk the source stops accepting writes. Pausing the consumer does not help: an unread slot
grows faster, not slower. Only two things stop the growth: make the consumer read again, or drop
the slot.

Lockkeeper never acts on this by itself. The guardrail is **alert-only**: it records an audit event and
prints a warning when the level changes, and it never drops a slot or pauses anything. Dropping a slot
changes the source and abandons the migration's change stream, so it is always your decision.

## Where you see it

- `lockkeeper migrate status` shows per database `RETAINED WAL`, `LAG`, `GUARDRAIL` (ok, warning,
  critical) and the subscription/worker state, plus a `WARNING:` line when the level is not ok. After
  `abort` it also warns that the slot still retains WAL.
- `lockkeeper slots list --target <source>` lists every slot of the source and its retained WAL.
- `lockkeeper migrate start`/`resume` print the warning while they wait; `monitor run` raises the usual
  `pg.slot.retained_wal_bytes` alert.

The thresholds are the effective `pg.slot.retained_wal_bytes` rule (defaults: warning 5 GiB, critical
20 GiB; override them under `alerts.rules`). A slot whose `wal_status` is `lost` is always critical: the
WAL it needed is gone and the stream has a gap.

## What to do

1. **Find out why the consumer stopped.** In `migrate status` look at `SUBSCRIPTION` and `WORKER`.
   - Subscription `disabled` after you aborted: expected; go to step 3.
   - Subscription `enabled` but `WORKER false`: the apply worker is crashing. On the target:
     `SELECT * FROM pg_stat_subscription_stats;` (PostgreSQL 15+) and the target's server log. Typical
     causes: a unique-violation (data was written on the target), a missing table or column (a schema
     change on the source after the plan), a full target disk, `max_logical_replication_workers`.
   - The target server is down or unreachable from the source's network: bring it back; the worker
     reconnects by itself.
2. **Fix the cause and let it catch up** if the retained WAL is still below the free disk space. Watch
   `RETAINED WAL` fall in `migrate status`. `lockkeeper migrate resume` is safe at any time: it
   reconciles with the servers first.
3. **If the disk is about to fill and the consumer cannot be fixed in time, give up the stream:**
   1. `lockkeeper migrate abort` (dry run), review, then `--apply --plan-hash <hash>`. This disables the
      subscription on the target and leaves the source untouched.
   2. `lockkeeper migrate cleanup` (dry run), review, then `--apply --plan-hash <hash>`. This drops this
      migration's slots on the source (and its publications, role and subscriptions). WAL is released
      as soon as the slot is gone, at the next checkpoint.
   3. Plan again later: a new migration starts from a new snapshot.
4. **Emergency, by hand** (only if Lockkeeper cannot run): on the source,
   `SELECT pg_drop_replication_slot('<slot name>');` for a slot named `lk_<migration id>_d<n>_a<n>`.
   The slot must be inactive (disable or drop the subscription on the target first). Afterwards mark the
   migration with `lockkeeper migrate abort`/`cleanup`, which treat the missing slot as already done.

## What you must not do

- Do not drop slots that are not named `lk_<migration id>_...`: they belong to someone else. Lockkeeper's
  cleanup only drops slots with this migration's exact prefix and refuses an active one.
- Do not restart a migration into a target database that still holds data from the interrupted one:
  `resume` shows a recovery plan (drop the old slot, drop and recreate the target database, copy again
  under a new slot) and applies it only with your confirmation.

## RDS

RDS exposes no disk-free figure over SQL. Use the `FreeStorageSpace` CloudWatch metric (see
docs/cloudwatch-iam.md) or `disk_total_gb` so the thresholds can be judged against the real disk.
Everything RDS-specific in this runbook comes from documentation and has not been run against RDS.
