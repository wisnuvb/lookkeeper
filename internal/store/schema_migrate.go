package store

// migrationSchemaV2 adds the migration state model (SPEC section 9): the
// migration record with its compare-and-swap state and single-driver lease,
// steps (intent then result), checkpoints, the actions that were attempted and
// an append-only audit trail.
//
// The audit table is named audit_events because `events` already holds alert
// events (and those are pruned by retention). audit_events is append-only:
// triggers abort every UPDATE and DELETE, so even a bug in Lockkeeper cannot
// rewrite history through this connection.
//
// No secret is ever stored in these tables: only names, hashes, masked SQL
// text and error text that was scrubbed by the caller.
const migrationSchemaV2 = `
CREATE TABLE migrations (
	id               TEXT PRIMARY KEY,
	state            TEXT NOT NULL,
	failed_from      TEXT NOT NULL DEFAULT '',
	failed_step      TEXT NOT NULL DEFAULT '',
	failed_resumable INTEGER NOT NULL DEFAULT 0,
	failed_reason    TEXT NOT NULL DEFAULT '',
	source_name      TEXT NOT NULL,
	target_name      TEXT NOT NULL,
	databases        TEXT NOT NULL,
	plan_hash        TEXT NOT NULL UNIQUE,
	plan_json        TEXT NOT NULL,
	approved_hash    TEXT NOT NULL DEFAULT '',
	lease_owner      TEXT NOT NULL DEFAULT '',
	lease_until      INTEGER NOT NULL DEFAULT 0,
	created_at       INTEGER NOT NULL,
	updated_at       INTEGER NOT NULL
);

CREATE TABLE steps (
	id           INTEGER PRIMARY KEY,
	migration_id TEXT NOT NULL REFERENCES migrations (id),
	db           TEXT NOT NULL DEFAULT '',
	name         TEXT NOT NULL,
	attempt      INTEGER NOT NULL,
	status       TEXT NOT NULL,
	detail       TEXT NOT NULL DEFAULT '',
	error        TEXT NOT NULL DEFAULT '',
	started_at   INTEGER NOT NULL,
	finished_at  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX steps_migration ON steps (migration_id, id);

CREATE TABLE checkpoints (
	migration_id TEXT NOT NULL REFERENCES migrations (id),
	db           TEXT NOT NULL DEFAULT '',
	key          TEXT NOT NULL,
	value        TEXT NOT NULL,
	updated_at   INTEGER NOT NULL,
	PRIMARY KEY (migration_id, db, key)
);

CREATE TABLE actions (
	id           INTEGER PRIMARY KEY,
	migration_id TEXT NOT NULL,
	plan_hash    TEXT NOT NULL,
	action_id    TEXT NOT NULL,
	phase        TEXT NOT NULL,
	endpoint     TEXT NOT NULL,
	sql_text     TEXT NOT NULL,
	mutates      INTEGER NOT NULL,
	status       TEXT NOT NULL,
	method       TEXT NOT NULL,
	approver     TEXT NOT NULL,
	at           INTEGER NOT NULL,
	error        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX actions_migration ON actions (migration_id, id);

CREATE TABLE audit_events (
	id           INTEGER PRIMARY KEY,
	ts           INTEGER NOT NULL,
	migration_id TEXT NOT NULL DEFAULT '',
	actor        TEXT NOT NULL DEFAULT '',
	kind         TEXT NOT NULL,
	action_id    TEXT NOT NULL DEFAULT '',
	plan_hash    TEXT NOT NULL DEFAULT '',
	method       TEXT NOT NULL DEFAULT '',
	detail       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX audit_events_migration ON audit_events (migration_id, id);

CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;

CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
`
