# ADR 0001: Use Go

- Status: **Accepted** (owner decision, 2026-11-06; reviewed, no objection)
- Deciders: owner

## Context

Lockkeeper is I/O-bound (database queries, long-running child processes, network alerts), must be
deployable as one binary to a VPS/dedicated server, and may later be open-sourced.

## Decision

Implement in Go. Minimum toolchain: the Go version required by our newest dependency
(`jackc/pgx/v5` v5.11.0 declares `go 1.25.0`; local toolchain is Go 1.27.1).

## Alternatives considered

- **Rust** (`tokio-postgres`, `supabase/etl`, formerly `pg_replicate`, Apache-2.0, active as of
  2026-11-06): strong for a replication engine, but we are deliberately *not* writing a replication
  engine (ADR 0002), so Rust's main advantage does not apply, and iteration speed and reviewability
  matter more for a tool built with AI assistance.
- **Python:** easy, but no single static binary; distribution to arbitrary VPS hosts is harder.

## Consequences

- Single static binary, `CGO_ENABLED=0` where possible (so the SQLite driver must be pure Go, see
  ADR 0003).
- Good drivers: `pgx/v5` (MIT, active), `go-sql-driver/mysql` (v1.10.1, **MPL-2.0**: acceptable as an
  unmodified dependency of an Apache-2.0 project; record it in the licence report), `go-mysql-org/go-mysql` (MIT, active) if we ever need binlog access.
- We must not drift into reimplementing pgcopydb/mydumper in Go: that is the failure mode this
  language choice makes tempting.
