//go:build darwin || linux

package deployment

import (
	"os"
	"strings"
	"testing"
)

func TestDeploymentLockIsExclusiveAndOwnerOnly(t *testing.T) {
	layout := testLayout(t)
	first, err := acquireDeploymentLock(layout)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := acquireDeploymentLock(layout); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("second lock error = %v", err)
	}
	info, err := os.Lstat(layout.LockPath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("lock mode = %v", info.Mode())
	}
	transactionID, err := newTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	if !transactionIDPattern.MatchString(transactionID) {
		t.Fatalf("transaction ID = %q", transactionID)
	}
}

func TestDeploymentLockRejectsSymlinkAndBroadMode(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(Layout) error
	}{
		{name: "symlink", setup: func(layout Layout) error { return os.Symlink(layout.StatePath, layout.LockPath) }},
		{name: "broad", setup: func(layout Layout) error {
			if err := os.WriteFile(layout.LockPath, nil, 0o600); err != nil {
				return err
			}
			return os.Chmod(layout.LockPath, 0o644)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			layout := testLayout(t)
			if err := test.setup(layout); err != nil {
				t.Fatal(err)
			}
			if _, err := acquireDeploymentLock(layout); err == nil {
				t.Fatal("unsafe lock unexpectedly accepted")
			}
		})
	}
}
