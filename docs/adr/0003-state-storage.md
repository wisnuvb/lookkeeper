# ADR 0003: Local state in SQLite (pure Go driver)

- Status: **Proposed**
- Deciders: owner

## Context

We need durable, resumable migration state, a light metrics history for alert evaluation
(rates, "for 5 minutes" conditions), and an append-only audit log, all without a server. Constraint:
single static binary, no mandatory services.

## Decision

Use one SQLite database file (WAL mode) with a pure-Go driver so `CGO_ENABLED=0` builds work
(`modernc.org/sqlite`, BSD-3-Clause, v1.61.1, verified 2026-11-06; re-check maintenance and the
SQLite version it embeds when adding the dependency). The same database will also hold users,
sessions, the connection registry and the encrypted vault if the web UI is built (ADR 0005); the
vault stores ciphertext only. Access goes through a `store` package with narrow interfaces
(`MetricStore`, `MigrationStore`, `AuditLog`) so another backend (e.g. Postgres for a SaaS
control plane) can replace it.

Schema sketch (full model in `docs/SPEC.md`): `metrics` (ring-buffer with retention),
`migrations`, `steps`, `checkpoints`, `actions` (every source-mutating action: plan hash, approver,
time), `events` (append-only audit). **No secret values, no passwords inside connection strings.**

Permissions: file mode `0600`, directory `0700`, refuse to start otherwise.

Note: pgcopydb keeps its *own* SQLite catalog in its work directory. Lockkeeper's DB is separate
and treats pgcopydb's directory as an opaque working area (but still scans it for secrets in tests).

## Alternatives considered

- **Plain JSON/YAML files:** simplest, but no atomic multi-row transactions or queryable history;
  crash-consistency of the state machine would be hand-rolled.
- **BoltDB/bbolt:** fine KV store, but no ad-hoc queries for metrics windows.
- **Postgres/MySQL as state store:** violates the "light, no services" goal and creates a chicken-and-egg
  problem when the thing being monitored is the database.
- **cgo SQLite (`mattn/go-sqlite3`):** more mature, but breaks static cross-compiled builds.

## Consequences

- Crash-safe transitions: write the *intent* in a transaction before performing a side effect, then
  reconcile against real-world state on resume (see ARCHITECTURE).
- Metrics are not a long-term TSDB. Users who want that use the optional Prometheus exporter.
