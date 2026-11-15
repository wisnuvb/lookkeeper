# Lockkeeper

A single-binary tool that **monitors PostgreSQL and MySQL health** and alerts you, and is being built
to **migrate databases between servers** (first target: AWS RDS PostgreSQL → a server you control) with
minimal downtime and strong verification.

> **Status: early.** Working and tested against real PostgreSQL 14/16/17 and MySQL 8.0/8.4 containers:
> monitoring, alerting, read-only `inventory` and `preflight pg`. **Not built yet:** the migration itself
> (copy, replication, cutover, verification), MySQL migration, and the web UI. **Nothing has been
> validated against real RDS/Aurora yet**, and the optional CloudWatch reader has never run against real
> AWS. See [docs/SPEC.md](docs/SPEC.md) for the plan.

Lockkeeper is **read-only**: no command here changes a monitored database. It never deletes data on a
source.

## What it checks

### PostgreSQL 12+

Connection usage, idle-in-transaction age, longest query, lock waits, **replication slots and the WAL
each one retains** (an unread slot can fill a server's disk), replication/standby lag, transaction-ID
and multixact age (wraparound risk), buffer cache hit ratio, and reachability. Defaults and the
reasoning are in [docs/SPEC.md](docs/SPEC.md#10-metrics-and-alert-rules); every threshold can be
overridden.

Also: table dead-tuple ratio, autovacuum age of large tables, checkpoint pressure, temp-file rate,
database size and (if `pg_stat_statements` is installed) the top statements by `queryid` only, never by query text.

### MySQL 8.0 and 8.4

Connections, running threads, oldest InnoDB transaction, replication thread state and lag, slow-query and
row-lock rates, buffer-pool hit ratio, history list length and binlog size. Create the account with exactly:

```sql
CREATE USER 'lockkeeper'@'<host>' IDENTIFIED BY '...' REQUIRE SSL;
GRANT PROCESS, REPLICATION CLIENT ON *.* TO 'lockkeeper'@'<host>';
```

Alerts go to **Telegram**, **Slack** and **email (SMTP, TLS verified)** with de-duplication, `for` durations, hysteresis, cooldown,
reminders, and persisted state (a restart does not re-send an active alert). An optional heartbeat URL
acts as a dead-man switch for Lockkeeper itself.

## Quick start

```sh
make build                     # or: go build -o lockkeeper ./cmd/lockkeeper
./lockkeeper init              # writes lockkeeper.yaml (mode 600, no secrets)
```

1. **Create a least-privilege role** on the database (do not use an admin account):

   ```sql
   CREATE ROLE lockkeeper LOGIN PASSWORD '...';
   GRANT pg_monitor TO lockkeeper;
   ```

   Lockkeeper warns if the role is a superuser, can replicate, or lacks `pg_monitor`. (Sessions are
   forced read-only, but that is defence in depth, not a security boundary: a read-only session can
   still create replication slots if the role is allowed to. The role's privileges are the boundary.)

2. **Edit `lockkeeper.yaml`** and export the secrets it references, for example
   `export LK_RDS_MAIN_PASSWORD=...`. Secrets are never written in the file: each is a reference
   (`{ env: NAME }`, `{ file: /path }` with mode 600, or `{ prompt: true }`).

3. **Validate, then look once, then run:**

   ```sh
   ./lockkeeper config validate        # checks syntax and that every referenced secret exists
   ./lockkeeper check                  # one-shot; exit 0 ok, 2 warning, 3 critical, 1 error
   ./lockkeeper slots list             # replication slots and retained WAL
   ./lockkeeper alerts test            # sends a test notification
   ./lockkeeper monitor run            # the daemon; SIGTERM shuts down gracefully
   ```

Planning a migration (read-only; changes nothing on either server):

```sh
./lockkeeper inventory --source rds-main
./lockkeeper preflight pg --source rds-main --target ovh-main   # exit 0 ok, 2 warnings, 3 blockers
```

### Web interface (preview)

```sh
make build-ui                 # needs Node 22 to build the UI; the result is one binary
./lockkeeper serve            # http://127.0.0.1:8443, loopback only
```

This is a **preview with invented demo data**: it talks to no database and has no login yet, so it
refuses to listen anywhere but loopback (use an SSH tunnel to look at it remotely). Sign-in, saved
connections and real data arrive next; see [docs/adr/0006](docs/adr/0006-web-ui-stack-scope-and-delivery.md).
The UI is available in English and Indonesian.

Optional extras: a Prometheus endpoint (`monitor.metrics`, loopback only by default; note port 9187 is
also postgres_exporter's default), and a CloudWatch reader for RDS free storage
([docs/cloudwatch-iam.md](docs/cloudwatch-iam.md), **never validated against real AWS**).

A systemd unit is in [deploy/lockkeeper.service](deploy/lockkeeper.service) (untested on a real host).

## Security model in short

- TLS is required for remote databases and the server certificate is verified (`verify-full`) by default;
  weaker modes need an explicit, warned opt-in.
- Passwords and tokens never appear in logs, errors, process arguments or the state database; this is
  checked by tests that scan real output for canary secrets.
- The local state file is created with mode 600 and refused if group/others can access it.
- Ambient `PG*` environment variables are ignored, so they cannot weaken a connection.

Full threat model: [docs/SPEC.md](docs/SPEC.md#12-threat-model).

## Development

```sh
make test                # unit tests with -race
make test-integration    # needs Docker; throwaway Postgres containers on loopback only
LK_TEST_PG_IMAGE=postgres:14-alpine make test-integration    # another server version
make ci                  # format, vet, staticcheck, govulncheck, tests
```

Integration tests only ever connect to containers they start themselves on loopback.
`staticcheck` and `govulncheck` are installed with `go install` (see the CI workflow). `go.mod` pins a
patched Go toolchain; `govulncheck` is part of CI.

## Documentation

- [docs/SPEC.md](docs/SPEC.md): goals, scope, configuration, CLI, state model, metrics and alerts, threat model
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): modules, boundaries, testing strategy
- [docs/adr/](docs/adr/): decision records

## Licence

Apache-2.0. See [LICENSE](LICENSE).
