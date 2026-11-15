package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/auth"
)

var (
	// ErrUserNotFound means no such user.
	ErrUserNotFound = errors.New("user not found")
	// ErrUserExists means the (canonical) username is taken.
	ErrUserExists = errors.New("username already in use")
	// ErrSetupDone means the first administrator already exists, so first-run setup is closed.
	ErrSetupDone = errors.New("setup already completed")
	// ErrLastAdmin means the change would leave no active administrator, which would lock everyone out
	// of user and connection management with no way back except editing the database by hand.
	ErrLastAdmin = errors.New("this would remove the last active administrator")
	// ErrBadUser means the input is not acceptable (empty name, unknown role, missing hash).
	ErrBadUser = errors.New("invalid user")
)

// User is an account. PasswordHash is an argon2id PHC string and must never leave the server.
type User struct {
	ID                string
	Username          string // canonical form
	Role              auth.Role
	PasswordHash      string
	Disabled          bool
	CreatedAt         time.Time
	UpdatedAt         time.Time
	PasswordChangedAt time.Time
	LastLoginAt       time.Time // zero until the first login
}

// Active reports whether the account may log in.
func (u User) Active() bool { return !u.Disabled }

const userCols = `id, username, role, password_hash, disabled, created_at, updated_at, password_changed_at, last_login_at`

func scanUser(r scanner) (User, error) {
	var (
		u                         User
		role                      string
		dis                       int
		created, updated, pw, lgn int64
	)
	if err := r.Scan(&u.ID, &u.Username, &role, &u.PasswordHash, &dis, &created, &updated, &pw, &lgn); err != nil {
		return User{}, err
	}
	u.Role, u.Disabled = auth.Role(role), dis != 0
	u.CreatedAt, u.UpdatedAt, u.PasswordChangedAt = time.UnixMilli(created).UTC(), time.UnixMilli(updated).UTC(), time.UnixMilli(pw).UTC()
	if lgn != 0 {
		u.LastLoginAt = time.UnixMilli(lgn).UTC()
	}
	return u, nil
}

func newUserID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate user id: %w", err)
	}
	return "u" + hex.EncodeToString(b[:]), nil
}

func validateNewUser(username, hash string, role auth.Role) (string, error) {
	name := auth.CanonicalUsername(username)
	if name == "" || len(name) > 64 {
		return "", fmt.Errorf("%w: username must be 1 to 64 characters", ErrBadUser)
	}
	if _, err := auth.ParseRole(string(role)); err != nil {
		return "", fmt.Errorf("%w: %v", ErrBadUser, err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		return "", fmt.Errorf("%w: password hash is missing or not argon2id", ErrBadUser)
	}
	return name, nil
}

func insertUser(ctx context.Context, q interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, name string, role auth.Role, hash string, now time.Time) (string, error) {
	id, err := newUserID()
	if err != nil {
		return "", err
	}
	ms := now.UnixMilli()
	_, err = q.ExecContext(ctx, `INSERT INTO users (id, username, role, password_hash, disabled, created_at, updated_at, password_changed_at, last_login_at)
		VALUES (?, ?, ?, ?, 0, ?, ?, ?, 0)`, id, name, string(role), hash, ms, ms, ms)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return "", ErrUserExists
		}
		return "", fmt.Errorf("create user: %w", err)
	}
	return id, nil
}

// CreateUser adds an account. The username is canonicalised, so "Alice" and "alice" are one name.
func (s *Store) CreateUser(ctx context.Context, username string, role auth.Role, passwordHash string, now time.Time) (User, error) {
	name, err := validateNewUser(username, passwordHash, role)
	if err != nil {
		return User{}, err
	}
	id, err := insertUser(ctx, s.db, name, role, passwordHash, now)
	if err != nil {
		return User{}, err
	}
	return s.GetUser(ctx, id)
}

// CreateFirstAdmin creates the initial administrator only if no user exists, in one transaction, so
// two simultaneous setup requests cannot both succeed. Callers validate the bootstrap token first and
// consume it after this returns (ADR 0006, "Wiring requirements for U1-B").
func (s *Store) CreateFirstAdmin(ctx context.Context, username, passwordHash string, now time.Time) (User, error) {
	name, err := validateNewUser(username, passwordHash, auth.Admin)
	if err != nil {
		return User{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, fmt.Errorf("begin setup: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
		return User{}, fmt.Errorf("count users: %w", err)
	}
	if n != 0 {
		return User{}, ErrSetupDone
	}
	id, err := insertUser(ctx, tx, name, auth.Admin, passwordHash, now)
	if err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, fmt.Errorf("commit setup: %w", err)
	}
	return s.GetUser(ctx, id)
}

// GetUser returns the user with this id.
func (s *Store) GetUser(ctx context.Context, id string) (User, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrUserNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("get user: %w", err)
	}
	return u, nil
}

// GetUserByName looks a user up by username (any case; it is canonicalised here).
func (s *Store) GetUserByName(ctx context.Context, username string) (User, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE username = ?`, auth.CanonicalUsername(username)))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrUserNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("get user by name: %w", err)
	}
	return u, nil
}

// ListUsers returns every user ordered by username.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// CountUsers returns how many accounts exist (zero means first-run setup is open).
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return n, nil
}

// updateUser applies change to the user inside a transaction. If the user is an active admin before
// the change and not after, another active admin must exist, or ErrLastAdmin is returned.
func (s *Store) updateUser(ctx context.Context, id string, change func(*User), now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin user update: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	before, err := scanUser(tx.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUserNotFound
	}
	if err != nil {
		return fmt.Errorf("read user: %w", err)
	}
	after := before
	change(&after)
	wasAdmin := before.Role == auth.Admin && before.Active()
	isAdmin := after.Role == auth.Admin && after.Active()
	if wasAdmin && !isAdmin {
		var others int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE role = 'admin' AND disabled = 0 AND id <> ?`, id).Scan(&others); err != nil {
			return fmt.Errorf("count admins: %w", err)
		}
		if others == 0 {
			return ErrLastAdmin
		}
	}
	dis := 0
	if after.Disabled {
		dis = 1
	}
	pwAt := before.PasswordChangedAt.UnixMilli()
	if after.PasswordHash != before.PasswordHash {
		pwAt = now.UnixMilli()
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET role = ?, password_hash = ?, disabled = ?, updated_at = ?, password_changed_at = ? WHERE id = ?`,
		string(after.Role), after.PasswordHash, dis, now.UnixMilli(), pwAt, id); err != nil {
		return fmt.Errorf("update user: %w", err)
	}
	return tx.Commit()
}

// SetRole changes a user's role. It refuses to demote the last active administrator.
func (s *Store) SetRole(ctx context.Context, id string, role auth.Role, now time.Time) error {
	if _, err := auth.ParseRole(string(role)); err != nil {
		return fmt.Errorf("%w: %v", ErrBadUser, err)
	}
	return s.updateUser(ctx, id, func(u *User) { u.Role = role }, now)
}

// SetDisabled disables or re-enables an account. It refuses to disable the last active administrator.
// Callers also revoke the user's sessions (SessionStore.DeleteUser) when disabling.
func (s *Store) SetDisabled(ctx context.Context, id string, disabled bool, now time.Time) error {
	return s.updateUser(ctx, id, func(u *User) { u.Disabled = disabled }, now)
}

// SetPasswordHash replaces the password hash. Callers revoke the user's other sessions afterwards.
func (s *Store) SetPasswordHash(ctx context.Context, id, hash string, now time.Time) error {
	if !strings.HasPrefix(hash, "$argon2id$") {
		return fmt.Errorf("%w: password hash is missing or not argon2id", ErrBadUser)
	}
	return s.updateUser(ctx, id, func(u *User) { u.PasswordHash = hash }, now)
}

// RecordLogin stamps the time of a successful login.
func (s *Store) RecordLogin(ctx context.Context, id string, now time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET last_login_at = ? WHERE id = ?`, now.UnixMilli(), id)
	if err != nil {
		return fmt.Errorf("record login: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrUserNotFound
	}
	return nil
}
