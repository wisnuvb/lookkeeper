package store

// webSchemaV3 adds what the web server needs to know who is calling: user accounts, browser sessions
// and an append-only trail of what those users did (ADR 0005, ADR 0006 slice U1-B).
//
// Secrets: the only credential-like values are the argon2id PHC string of a password (a salted hash,
// never the password) and the SHA-256 digest of a session token (never the token). Nothing here can
// be used to log in without brute-forcing the hash.
//
// Times are Unix milliseconds, like the migration tables. Usernames are stored in their canonical form
// (auth.CanonicalUsername) so the UNIQUE constraint is the single source of truth for "same user".
//
// Users are disabled, not deleted: audit rows and migrations name them, and a deleted account that is
// recreated under the same name would inherit that history.
//
// (Trigger bodies are lower case on purpose, see schema_migrate.go.)
const webSchemaV3 = `
CREATE TABLE users (
	id                  TEXT PRIMARY KEY,
	username            TEXT NOT NULL UNIQUE CHECK (length(username) BETWEEN 1 AND 64),
	role                TEXT NOT NULL CHECK (role IN ('viewer', 'operator', 'admin')),
	password_hash       TEXT NOT NULL,
	disabled            INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
	created_at          INTEGER NOT NULL,
	updated_at          INTEGER NOT NULL,
	password_changed_at INTEGER NOT NULL,
	last_login_at       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE sessions (
	token_hash BLOB PRIMARY KEY CHECK (length(token_hash) = 32),
	user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
	created_at INTEGER NOT NULL,
	last_seen  INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	idle_until INTEGER NOT NULL
);
CREATE INDEX sessions_user ON sessions (user_id);
CREATE INDEX sessions_expiry ON sessions (expires_at);

CREATE TABLE web_audit (
	id       INTEGER PRIMARY KEY,
	ts       INTEGER NOT NULL,
	actor_id TEXT NOT NULL DEFAULT '',
	actor    TEXT NOT NULL DEFAULT '',
	action   TEXT NOT NULL,
	target   TEXT NOT NULL DEFAULT '',
	outcome  TEXT NOT NULL CHECK (outcome IN ('ok', 'denied', 'error')),
	remote   TEXT NOT NULL DEFAULT '',
	detail   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX web_audit_ts ON web_audit (ts, id);

CREATE TRIGGER web_audit_no_update BEFORE UPDATE ON web_audit
BEGIN select raise(abort, 'web_audit is append-only'); END;

CREATE TRIGGER web_audit_no_delete BEFORE DELETE ON web_audit
BEGIN select raise(abort, 'web_audit is append-only'); END;
`
