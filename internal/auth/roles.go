package auth

import "fmt"

// Role is a user's authority (ADR 0005 item 3).
type Role string

const (
	// Viewer may read metrics, alerts and inventory-style reports. It cannot cause any connection to
	// be opened by the server beyond the monitoring that already runs.
	Viewer Role = "viewer"
	// Operator may also run read-only pre-flight checks and start or resume an approved migration.
	Operator Role = "operator"
	// Admin may also manage connections and users, approve source-changing plans, cut over and clean up.
	Admin Role = "admin"
)

// Permission is one thing a request may need to be allowed to do. Handlers name the permission they
// require; they never test roles directly, so authorisation lives in exactly one table.
type Permission string

const (
	PermViewMonitoring   Permission = "monitoring.view"
	PermRunPreflight     Permission = "preflight.run"
	PermPlanMigration    Permission = "migration.plan"
	PermRunMigration     Permission = "migration.run"     // start, resume (after approval)
	PermApproveMutation  Permission = "migration.approve" // approve a plan that changes the SOURCE
	PermCutover          Permission = "migration.cutover"
	PermCleanup          Permission = "migration.cleanup" // abort, drop slots/roles on the source
	PermManageConnection Permission = "connection.manage" // create, edit, delete
	PermTestConnection   Permission = "connection.test"   // makes the server dial out: SSRF surface (T21)
	PermManageUsers      Permission = "users.manage"
	PermViewAudit        Permission = "audit.view"
	PermManageAlerts     Permission = "alerts.manage" // thresholds, channels, test notification
)

// matrix is the single authorisation table. A permission absent from a role is DENIED.
var matrix = map[Permission]map[Role]bool{
	PermViewMonitoring:   {Viewer: true, Operator: true, Admin: true},
	PermRunPreflight:     {Operator: true, Admin: true},
	PermPlanMigration:    {Operator: true, Admin: true},
	PermRunMigration:     {Operator: true, Admin: true},
	PermApproveMutation:  {Admin: true},
	PermCutover:          {Admin: true},
	PermCleanup:          {Admin: true},
	PermManageConnection: {Admin: true},
	PermTestConnection:   {Admin: true},
	PermManageUsers:      {Admin: true},
	PermViewAudit:        {Admin: true},
	PermManageAlerts:     {Admin: true},
}

// Permissions lists every known permission (used by the exhaustive route/role tests).
func Permissions() []Permission {
	out := make([]Permission, 0, len(matrix))
	for p := range matrix {
		out = append(out, p)
	}
	return out
}

// Roles lists every known role, least to most privileged.
func Roles() []Role { return []Role{Viewer, Operator, Admin} }

// Can reports whether the role holds the permission. Unknown roles and unknown permissions are denied.
func (r Role) Can(p Permission) bool { return matrix[p][r] }

// ParseRole validates a role name coming from outside (API input, database).
func ParseRole(s string) (Role, error) {
	switch r := Role(s); r {
	case Viewer, Operator, Admin:
		return r, nil
	}
	return "", fmt.Errorf("auth: unknown role %q", s)
}
