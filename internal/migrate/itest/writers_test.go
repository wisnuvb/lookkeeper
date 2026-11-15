//go:build integration

package itest

import (
	"testing"

	"github.com/wisnuvb/lockkeeper/internal/testutil"
)

func startWriters(t *testing.T, r *rig) *testutil.Writers {
	t.Helper()
	return testutil.StartWriters(t, r.appDSN(), 4)
}
