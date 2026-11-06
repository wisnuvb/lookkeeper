# ADR 0004: Secrets are references, never values; TLS verified by default

- Status: **Proposed**
- Deciders: owner

## Context

Lockkeeper holds credentials for production databases and must pass them to child processes
(pgcopydb, later mydumper/myloader). Passwords must not appear in logs, `ps` output, state files, or
error messages.

## Decision

1. **Config and state store only references:** `{ env: NAME }`, `{ file: /path }` (mode must be
   `0600` or stricter, else refuse), or `{ prompt: true }` (TTY only). Inline plaintext passwords in
   YAML are rejected by the validator (an `--allow-inline-secret` escape hatch exists for local
   tests only and warns loudly).
2. **Resolve late, hold briefly:** secrets are resolved at the moment of connection and kept in a
   `secret.Value` type whose `String()`/`MarshalJSON`/`%v` return `***`. Revealing requires an explicit
   `.Reveal()` call, which is greppable and lint-checked.
3. **Child processes:** never put a secret in `argv`. Build the child's environment from an empty
   map (not `os.Environ()`), and give libpq-based tools passwordless URIs plus `PGPASSFILE` pointing
   to a `0600` file in a `0700` per-run temp directory, deleted on exit (including signals). Env
   variables are not visible in plain `ps` but can be read by the same user/root via
   `/proc/<pid>/environ` (Linux) or `ps eww` (same user), which is why the passfile is preferred.
   Whether pgcopydb copies connection strings into its own catalog/logs is **unverified** — the
   spike in ADR 0002 must test it.
4. **Redaction layer:** a single `redact` writer wraps every log sink and child-process output
   capture; it scrubs known secret values and URI passwords (`://user:pass@`).
5. **TLS:** remote databases require TLS. Default mode `verify-full` with a CA file (RDS CA bundle
   provided by the user or downloaded explicitly). Weaker modes need explicit config and print a
   warning in every command's header. Loopback and unix sockets are exempt.
6. **Acceptance test (permanent):** run an integration scenario with a canary password
   (`CANARY_<random>`), then assert it is absent from logs, `ps` output, `/proc/*/environ` of
   children where readable, the lockkeeper SQLite file, and pgcopydb's work directory.

7. **Native subscription exception (ADR 0002):** `CREATE SUBSCRIPTION` needs a connection string the
   *target server* uses to reach the source. Postgres stores it in `pg_subscription.subconninfo`
   (readable by superusers) and it can be echoed in server logs if `log_statement` or
   `log_min_duration_statement` captures the DDL. Mitigations: use a dedicated, time-limited
   migration user whose password is generated per migration and rotated/dropped at `cleanup`; set
   `log_statement` handling guidance in the pre-flight (warn if target logs all statements); run the
   statement in a session with `SET log_statement = 'none'` where the server permits (superuser
   only); never reuse an application or admin password here. If the pre-flight cannot confirm the
   target will not log it, require operator acknowledgement.

## Alternatives considered

- **OS keychain integration:** nice on desktop, useless on headless servers; may be added as another
  resolver later.
- **Env vars only:** simplest, but the child-process visibility caveat above applies, and shells
  persist history.
- **Encrypted secrets file (age/sops):** possible future resolver; not needed for MVP.

## Consequences

- A little more plumbing (resolvers, passfile lifecycle, redactor) before the first migration, in
  return for a mechanically testable "no leaks" claim.
- Some pgcopydb features that accept only URIs-with-passwords on argv must be avoided or wrapped.
