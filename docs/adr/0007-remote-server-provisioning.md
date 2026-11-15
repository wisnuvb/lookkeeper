# ADR 0007: Remote server provisioning and management

- Status: **Accepted** by the owner on 2026-11-15, with the answers recorded in "Owner decisions" below
  (these amend the items they touch). Implementation order is in "Delivery order".
- Deciders: owner
- Builds on: ADR 0004 (secrets), ADR 0005 (web UI, vault, server hardening), ADR 0006 (server-centric UI,
  T21 SSRF guard). It **reverses** one non-goal of SPEC section 4 ("Not a hosting/provisioning tool for the
  target server") **for an opt-in module only**. Nothing else in those ADRs is relaxed.

## Context

On 2026-11-15 the owner asked to manage a VPS or dedicated server from the web UI: connect to it, install
PostgreSQL or MySQL (on the host or in Docker) and control it "fully remotely", simply, with **security as
the top priority**. Until now Lockkeeper is read-only by default and never holds credentials that can change
a server; the owner's real first use case (one dedicated OVH server) is the first target.

Honest framing: this feature gives Lockkeeper the ability to run privileged operations on remote machines.
Whatever the design, **the stored credential for a managed server is root-equivalent** (a user that can run
Docker is root on that host). So the design cannot rely on "limited privileges" alone. It must limit what
Lockkeeper itself is able to ask for, make every action reviewable before it runs, and keep the blast radius
of a compromised Lockkeeper small.

## Owner decisions (2026-11-15) — these override the matching items below

1. **Scope is databases only**, end to end: **discover** whether a database already exists on a host
   (read-only: packages, systemd units, listening ports, Docker containers, data directories), **install**
   it, and **manage** it. Both **host-native (apt)** and **Docker** installs are in scope. Nothing else
   (no shell, files, OS management).
2. **A super account exists** (role `owner`, above `admin`) that can do everything, including approving
   plans it created itself ("break-glass"). Everyone else is bound by separation of duties (item 9 of the
   Decision). Owner actions that bypass separation of duties are audited with a distinct marker. At least one
   active owner must always exist (same protection as the last admin). The `owner` role is a change to
   `internal/auth` and the user store, to be made inside the U1-B work stream, not in this module.
3. **Hosts: Debian and Ubuntu LTS only** (x86_64) for the MVP.
4. **Lockkeeper installs Docker itself** (item 6 below is amended): from Docker's official apt repository,
   with the repository key fingerprint pinned in the code, as a plan the operator approves like any other
   change. It never installs Docker silently as a side effect of another operation.
5. **Direction: personal use first, then open source, then possibly SaaS.** Consequences: the `Transport`
   interface is a hard seam; a resident-agent transport is expected to be needed for SaaS (a hosted service
   must not keep root-equivalent SSH keys for customers, see T12); SaaS custody of such keys is **not
   accepted** by this ADR and needs its own ADR before any hosted offering. Keep dependency licences
   permissive and the module free of owner-specific assumptions.
6. **A VPS is available** for the spike and for real validation; a new DigitalOcean droplet can be created
   when needed. No stage is called production-ready before it ran on a real, disposable VPS. Nothing in this
   repo may connect to a real server without the owner handing over the target explicitly for that run.

## Decision (originally proposed; amended by the owner decisions above)

1. **Separate, opt-in module** `internal/provision` (registered through `commandFactories`, like `serve`).
   Disabled by default: monitoring and migration stay read-only for anyone who does not turn it on with an
   explicit config flag. The core must not import it.
2. **Scope is database-centric, not a general server manager.** In: host facts, Docker-based PostgreSQL
   (then MySQL) install and configuration, databases and roles, TLS, lifecycle (start/stop/restart/logs),
   automatic registration with monitoring. **Out: web terminal / free-form shell, file manager, arbitrary
   package or service management, firewall changes (MVP), anything that deletes data.**
3. **Transport: SSH with a forced-command helper (no free shell, no daemon).**
   - Lockkeeper generates one **Ed25519 key per server**; the private key goes into the vault; the public key
     is shown to the operator.
   - **Bootstrap** needs one-time root access: the operator enters a bootstrap credential in the UI; it is
     held in memory, used to install the helper and the restricted key, then discarded. It is **never stored**.
   - The installed key is restricted in `authorized_keys`:
     `restrict,command="/usr/local/sbin/lockkeeper-helper",from="<lockkeeper address>"` (no pty, no
     forwarding, no agent forwarding, one fixed command, source-address bound).
   - `lockkeeper-helper` is a small static Go binary, uploaded over the bootstrap session and verified by a
     pinned checksum. It reads **one typed JSON operation from stdin**, validates it against a schema, runs
     it with `exec` and an argv array (**never through a shell**), and returns structured JSON. It exposes
     only the operations in item 4.
   - **Host key pinning:** the operator confirms the server's fingerprint at bootstrap; it is stored; a later
     mismatch is a hard failure that needs an explicit admin re-pin. No "accept any host key" mode.
   - Key authentication only; no passwords for the managed session; SSH targets go through `netguard` (T21).
   - Alternative kept open behind a `Transport` interface: a resident agent (better for a future SaaS, much
     more work). Not in scope now.
4. **Operations are typed, versioned and finite.** Examples: `host.facts`, `docker.check`,
   `pg.install`, `pg.config.apply`, `pg.role.create`, `pg.db.create`, `tls.issue`, `container.start|stop|restart`,
   `container.logs`. Each declares a risk class:

   | Class | Examples | Gate |
   |---|---|---|
   | read | `host.facts`, `container.logs` | role `operator`+ |
   | change | `pg.install`, `pg.config.apply`, `pg.role.create` | plan + dry-run + **plan hash** + typed confirmation |
   | destructive | drop database, remove container with volume, reinstall | **not implemented in the MVP**; later: plan hash + typed confirmation of the target name + a different approver |

   Parameters are validated against a strict grammar (identifiers, versions, paths under a fixed root);
   anything else is rejected before it reaches the helper, and again inside the helper.
5. **Plan, approve, apply.** Every change operation first produces a plan: the exact files to be written, the
   exact container/compose definition, the commands the helper will run, and what stays untouched. The plan is
   hashed; apply requires the hash back (same rule as source-mutating migration steps; there is no blanket
   `--yes`). Operations are idempotent, recorded in the state DB as a resumable state machine, and a partial
   failure never leaves a half-configured server marked as healthy.
6. **Docker only for the MVP.** Official `postgres` (then `mysql`) images **pinned by digest**; the compose
   file is generated from a reviewed template. Data lives in a named volume or bind mount and **is never
   removed by Lockkeeper**. The database port binds to `127.0.0.1` by default; binding to a private or public
   interface requires an explicit plan item, TLS `verify-full` for clients and a restricted `pg_hba.conf`.
   Installing Docker itself is **not** done in the MVP: the host check reports it and prints the official
   instructions (see open question 4).
7. **Secrets.** Database passwords are generated on the server side of the operation, stored in the vault,
   and handed to the container through `*_PASSWORD_FILE` (mode 0600, root-owned), not through environment
   variables (visible in `docker inspect`). (Support for the file variants in the pinned images is to be
   verified in the spike.) Passwords never appear in plans, logs, process arguments or the audit log.
8. **TLS.** A Lockkeeper-managed CA per installation. The server key is generated **on the managed server**
   (CSR flow); only the certificate travels back. Clients then use `verify-full` against the pinned CA.
9. **Authentication and authorization.** Requires U1-B (users, sessions, roles). Feature needs: role
   `admin` for server registration and bootstrap; `operator` may plan, `admin` may approve; **step-up
   re-authentication** before approving any change; TOTP required before the module can be enabled.
   Separation of duties (planner differs from approver) is **mandatory in the module's "production" mode**
   (this resolves the open decision from the U1-A review for this module).
10. **Audit.** Every operation (plan, approval, each helper call, result) is written to an append-only,
    hash-chained audit log with actor, server, operation, plan hash and redacted output. Remote
    stdout/stderr is untrusted: size-capped, redacted, rendered as plain text only.
11. **Lockout safety.** The module never changes SSH, firewall or network configuration in the MVP. Where a
    change would be needed, it reports it and prints the exact commands for the operator to run.

## New threats (to be added to SPEC section 12 when accepted)

| ID | Threat | Mitigation |
|---|---|---|
| T22 | Compromised Lockkeeper (or vault + master key) = every managed server | per-server key; forced command + `from=` restriction means the key can only invoke typed helper operations from Lockkeeper's address; no destructive operations in MVP; audit; key rotation operation |
| T23 | MITM on first or later SSH connection | explicit fingerprint confirmation at bootstrap, pinning, hard fail on mismatch |
| T24 | Command or argument injection through UI parameters | typed operations, strict grammars, argv exec with no shell, validation on both sides, fuzz tests |
| T25 | Malicious or tampered helper / images (supply chain) | helper checksum pinned and verified at upload; images pinned by digest; reproducible build of the helper; licences recorded |
| T26 | Bootstrap credential leakage | memory only, never persisted or logged, zeroed after use, not accepted via URL/query |
| T27 | Remote output used for XSS, log injection or secret exfiltration | untrusted-output handling (item 10) and the existing strict CSP |
| T28 | Operator mistake or lockout (wrong target, exposed port) | plan + hash + typed confirmation, loopback-only default, no firewall/SSH changes in MVP |
| T29 | Helper version skew / replay of an old approved plan | plan bound to server, operation version and a short expiry; helper rejects unknown versions |

## Delivery order

Each stage ends in something runnable and tested. **No stage is "production-ready" until validated on a
disposable real VPS**, not only in containers (the same caveat as RDS).

| Stage | Content | Needs |
|---|---|---|
| S0 | This ADR accepted; SPEC non-goal and threat model updated; spike on a throw-away VM for the open "to verify" items | owner answers |
| S1 | Transport, host-key pinning, bootstrap, helper skeleton, **read-only** ops (`host.facts`, `docker.check`), audit log | U1-B |
| S2 | `pg.install` in Docker with plan/hash/apply, loopback-only, password files | S1 |
| S3 | Roles and databases, TLS via managed CA, config apply, auto-registration into monitoring and pre-flight | S2 |
| S4 | Lifecycle (start/stop/restart/logs), health integration, key rotation | S3 |
| S5 | MySQL equivalent of S2-S4 | S4 |
| later | Backup/restore, minor upgrades, firewall with timed auto-revert: **each needs its own ADR** | S5 |

Integration tests use an `sshd` container and Docker-in-container targets; the test helper must refuse
non-loopback / non-container hosts, as for databases. The e2e canary-secret scan is extended to cover
bootstrap credentials and generated passwords.

## Alternatives considered

- **Plain SSH with sudo allow-list:** rejected. Allow-lists are routinely escapable (wildcards, `docker`
  group is root) and give false assurance.
- **Free-form remote shell / web terminal:** rejected. It turns the tool into a remote root console and
  makes every UI bug a server compromise.
- **Resident agent:** better long-term (SaaS, pull model), but a daemon, update channel and enrolment
  protocol are a project of their own. Kept behind the `Transport` seam.
- **Ansible or Terraform underneath:** adds a heavy runtime and a second language/permission model; plans
  are harder to hash and review. Rejected for the MVP.
- **Host-package install (apt/dnf):** differs per distro and version; deferred, Docker first.

## Consequences

- Lockkeeper gains a feature class with a much larger security surface; the module must stay isolated and
  off by default, and gets its own security review (use the `security-reviewer` agent) before S2 ships.
- The critical path stays: U1-B and Phase 4 first (the owner's RDS to OVH migration depends on them);
  this module starts at S1 after U1-B.
- A root-equivalent credential per server lives in the vault; operators must understand and accept that.

## Open questions (owner)

1. **Scope of "full remote server":** is database-centric management (item 2) enough, or is general server
   management (web terminal, files, OS updates) expected? Recommendation: database-centric only.
2. **Separation of duties:** accept mandatory distinct approver in production mode? (needs a second account)
3. **Supported hosts for the MVP:** Debian/Ubuntu LTS x86_64 only? (recommended)
4. **Docker installation:** only check and print instructions (recommended for the MVP), or let Lockkeeper
   install Docker from the official repository too?
5. **Direction:** personal/OVH use only, or open source / SaaS later? This decides whether the agent
   transport and multi-distro support are worth planning for now.
6. **Testing target:** is a disposable VPS available for the S0 spike and the real validation?
