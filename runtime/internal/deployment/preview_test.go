//go:build darwin || linux

package deployment

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/kciceblue/sshserver/runtime/internal/buildinfo"
	"github.com/kciceblue/sshserver/runtime/internal/config"
	"github.com/kciceblue/sshserver/runtime/internal/instance"
)

func TestDeploymentPreviewClassifiesFreshIdempotentAndUpgrade(t *testing.T) {
	fixture := newLifecycleFixture(t, false)
	request, desired := fixture.release(t, "v1.2.3", "preview-a")
	previewRequest := requestForPreview(fixture.layout, request)

	fresh, err := fixture.lifecycle.Preview(context.Background(), previewRequest)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Classification != PreviewFresh || !fresh.ApplyAllowed || fresh.BlockReason != "" {
		t.Fatalf("fresh preview=%+v", fresh)
	}
	if fresh.Existing.LifecycleLockPresent || fresh.Existing.InitializationLockPresent {
		t.Fatal("fresh preview reported an absent lifecycle or initialization lock as present")
	}
	if fresh.Release.Release != desired.Release || fresh.Release.SourceRevision != desired.SourceRevision ||
		fresh.Target != (PreviewTargetIdentity{OS: fixture.target.OS, Architecture: fixture.target.Architecture}) {
		t.Fatalf("fresh identities=%+v target=%+v", fresh.Release, fresh.Target)
	}
	if fresh.Paths.HomeDir != fixture.layout.HomeDir || fresh.Paths.InstallRoot != fixture.layout.InstallRoot ||
		fresh.Paths.StateDir != fixture.layout.StateDir || fresh.Paths.BinaryPath != desired.BinaryPath ||
		fresh.Paths.LicensePath != filepath.Join(filepath.Dir(desired.BinaryPath), "LICENSE") ||
		fresh.Paths.NoticePath != filepath.Join(filepath.Dir(desired.BinaryPath), "NOTICE") ||
		fresh.Paths.InitializationLock != filepath.Join(fixture.layout.StateDir, ".instance.lock") ||
		fresh.Paths.ServiceDefinition != fixture.manager.definition {
		t.Fatalf("fresh paths=%+v", fresh.Paths)
	}
	assertPreviewSafety(t, fresh)
	assertPreviewActionsContain(t, fresh.Actions,
		"publish_verified_artifact", "initialize_or_resume_loopback_instance", "install_user_service_definition",
		"activate_user_service", "verify_running_release_identity_and_loopback_health", "commit_deployment_state",
	)
	assertPreviewActionPrefix(t, fresh.Actions,
		"acquire_bootstrap_lock", "prepare_install_root", "create_lifecycle_lock", "acquire_lifecycle_lock",
		"prepare_state_directory", "create_initialization_lock", "acquire_initialization_lock",
		"prepare_install_root", "prepare_versions_directory", "prepare_state_directory", "create_apply_journal",
		"prepare_release_directory", "publish_verified_artifact",
	)
	assertCanonicalPreview(t, fresh)
	if _, err := LoadState(fixture.layout); !errors.Is(err, ErrNoDeploymentState) {
		t.Fatalf("preview created deployment state: %v", err)
	}
	if _, err := LoadJournal(fixture.layout); !errors.Is(err, ErrNoDeploymentJournal) {
		t.Fatalf("preview created deployment journal: %v", err)
	}

	if _, err := applyConfirmed(t, fixture.lifecycle, request); err != nil {
		t.Fatal(err)
	}
	idempotent, err := fixture.lifecycle.Preview(context.Background(), previewRequest)
	if err != nil {
		t.Fatal(err)
	}
	if idempotent.Classification != PreviewIdempotent || !idempotent.ApplyAllowed {
		t.Fatalf("idempotent preview=%+v", idempotent)
	}
	if !idempotent.Existing.LifecycleLockPresent || !idempotent.Existing.InitializationLockPresent {
		t.Fatal("idempotent preview did not report the existing lifecycle and initialization locks")
	}
	assertPreviewActionPrefix(t, idempotent.Actions,
		"acquire_bootstrap_lock", "acquire_lifecycle_lock", "prepare_state_directory", "acquire_initialization_lock",
		"prepare_install_root", "prepare_versions_directory", "prepare_state_directory",
	)
	assertPreviewActionsContain(t, idempotent.Actions, "verify_or_reuse_artifact", "verify_user_service_active")
	for _, action := range idempotent.Actions {
		if action.Operation == "create_apply_journal" || action.Operation == "commit_deployment_state" {
			t.Fatalf("idempotent preview planned state mutation: %+v", action)
		}
	}

	upgradeRequest, upgradeDesired := fixture.release(t, "v1.2.4", "preview-b")
	upgrade, err := fixture.lifecycle.Preview(context.Background(), requestForPreview(fixture.layout, upgradeRequest))
	if err != nil {
		t.Fatal(err)
	}
	if upgrade.Classification != PreviewUpgrade || !upgrade.ApplyAllowed || upgrade.Release.Release != upgradeDesired.Release {
		t.Fatalf("upgrade preview=%+v", upgrade)
	}
	if !upgrade.Existing.LifecycleLockPresent {
		t.Fatal("upgrade preview did not report the existing lifecycle lock")
	}
	assertPreviewActionPrefix(t, upgrade.Actions,
		"acquire_bootstrap_lock", "acquire_lifecycle_lock", "prepare_state_directory", "acquire_initialization_lock",
		"prepare_install_root", "prepare_versions_directory", "prepare_state_directory", "create_apply_journal",
	)
	assertPreviewActionsContain(t, upgrade.Actions, "stop_prior_user_service", "commit_deployment_state")
}

func TestFreshPreviewDistinguishesExistingLifecycleLockAcquisition(t *testing.T) {
	fixture := newLifecycleFixture(t, false)
	request, _ := fixture.release(t, "v1.2.3", "fresh-existing-lock")
	if err := PrepareLayout(fixture.layout); err != nil {
		t.Fatal(err)
	}
	lock, err := acquireDeploymentLock(fixture.layout)
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}

	preview, err := fixture.lifecycle.Preview(context.Background(), requestForPreview(fixture.layout, request))
	if err != nil {
		t.Fatal(err)
	}
	if preview.Classification != PreviewFresh || !preview.ApplyAllowed || !preview.Existing.LifecycleLockPresent {
		t.Fatalf("fresh existing-lock preview=%+v", preview)
	}
	assertPreviewActionPrefix(t, preview.Actions,
		"acquire_bootstrap_lock", "acquire_lifecycle_lock", "prepare_state_directory",
		"create_initialization_lock", "acquire_initialization_lock",
		"prepare_install_root", "prepare_versions_directory", "prepare_state_directory", "create_apply_journal",
	)
}

func TestDeploymentPreviewDisclosesInitializationLeaseBeforeJournalOrIdempotentWork(t *testing.T) {
	t.Run("fresh apply", func(t *testing.T) {
		fixture := newLifecycleFixture(t, false)
		request, _ := fixture.release(t, "v1.2.3", "initialization-lease-plan-fresh")
		preview, err := fixture.lifecycle.Preview(context.Background(), request.previewRequest())
		if err != nil {
			t.Fatal(err)
		}
		initializationLock := filepath.Join(fixture.layout.StateDir, ".instance.lock")
		if preview.Paths.InitializationLock != initializationLock || preview.Existing.InitializationLockPresent {
			t.Fatalf("fresh initialization-lock snapshot paths=%+v existing=%+v", preview.Paths, preview.Existing)
		}
		assertPreviewActionPrefix(t, preview.Actions,
			"acquire_bootstrap_lock", "prepare_install_root", "create_lifecycle_lock", "acquire_lifecycle_lock",
			"prepare_state_directory", "create_initialization_lock", "acquire_initialization_lock",
			"prepare_install_root", "prepare_versions_directory", "prepare_state_directory", "create_apply_journal",
		)

		originalAcquire := fixture.lifecycle.acquireInstanceLease
		acquiredBeforeJournal := false
		fixture.lifecycle.acquireInstanceLease = func(stateDir string, initializationLockPresent bool) (instanceInitializationLease, error) {
			if _, err := LoadJournal(fixture.layout); !errors.Is(err, ErrNoDeploymentJournal) {
				return nil, fmt.Errorf("initialization lease reached after journal creation: %w", err)
			}
			acquiredBeforeJournal = true
			return originalAcquire(stateDir, initializationLockPresent)
		}
		canonical, err := preview.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		repeated, err := fixture.lifecycle.Preview(context.Background(), request.previewRequest())
		if err != nil {
			t.Fatal(err)
		}
		repeatedCanonical, err := repeated.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(canonical, repeatedCanonical) {
			t.Fatalf("fresh preview changed without target mutation\nfirst=%s\nsecond=%s", canonical, repeatedCanonical)
		}
		request.ConfirmedPreviewSHA256 = SHA256Hex(canonical)
		fixture.lifecycle.failAfterPhase = PhasePlanned
		if _, err := fixture.lifecycle.Apply(context.Background(), request); !errors.Is(err, ErrInjectedDeploymentCrash) {
			t.Fatalf("fresh planned crash error=%v acquired_before_journal=%t", err, acquiredBeforeJournal)
		}
		if !acquiredBeforeJournal {
			t.Fatal("fresh apply did not acquire its initialization lease")
		}
		if err := config.ValidateProtectedFile(initializationLock, 0o600); err != nil {
			t.Fatalf("fresh apply initialization lock: %v", err)
		}
	})

	t.Run("idempotent repair recreates missing lock", func(t *testing.T) {
		fixture := newLifecycleFixture(t, false)
		request, _ := fixture.release(t, "v1.2.3", "initialization-lease-plan-idempotent")
		if _, err := applyConfirmed(t, fixture.lifecycle, request); err != nil {
			t.Fatal(err)
		}
		initializationLock := filepath.Join(fixture.layout.StateDir, ".instance.lock")
		if err := os.Remove(initializationLock); err != nil {
			t.Fatal(err)
		}
		preview, err := fixture.lifecycle.Preview(context.Background(), requestForPreview(fixture.layout, request))
		if err != nil {
			t.Fatal(err)
		}
		if preview.Classification != PreviewIdempotent || preview.Existing.InitializationLockPresent {
			t.Fatalf("idempotent missing-lock preview=%+v", preview)
		}
		assertPreviewActionPrefix(t, preview.Actions,
			"acquire_bootstrap_lock", "acquire_lifecycle_lock", "prepare_state_directory",
			"create_initialization_lock", "acquire_initialization_lock",
			"prepare_install_root", "prepare_versions_directory", "prepare_state_directory", "prepare_release_directory",
		)
		if _, err := applyConfirmed(t, fixture.lifecycle, request); err != nil {
			t.Fatalf("idempotent missing-lock apply: %v", err)
		}
		if err := config.ValidateProtectedFile(initializationLock, 0o600); err != nil {
			t.Fatalf("recreated initialization lock: %v", err)
		}
	})
}

func TestFreshAndUpgradeDestinationCollisionsBlockBeforeJournal(t *testing.T) {
	for _, classification := range []string{"fresh", "upgrade"} {
		for _, destination := range []string{"binary", "LICENSE", "NOTICE"} {
			t.Run(classification+"/"+destination, func(t *testing.T) {
				fixture := newLifecycleFixture(t, false)
				if classification == "upgrade" {
					installed, _ := fixture.release(t, "v1.2.3", "destination-collision-installed")
					if _, err := applyConfirmed(t, fixture.lifecycle, installed); err != nil {
						t.Fatal(err)
					}
				}

				version := "v1.2.3"
				if classification == "upgrade" {
					version = "v1.2.4"
				}
				request, desired := fixture.release(t, version, "destination-collision-"+classification+"-"+destination)
				releaseDir, err := fixture.layout.VersionDir(desired.Release)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(releaseDir, directoryMode); err != nil {
					t.Fatal(err)
				}
				collisionPath := desired.BinaryPath
				mode := os.FileMode(0o700)
				if destination != "binary" {
					collisionPath, err = desired.SupportFilePath(fixture.layout, destination)
					if err != nil {
						t.Fatal(err)
					}
					mode = 0o600
				}
				if err := os.WriteFile(collisionPath, []byte("untrusted-existing-destination"), mode); err != nil {
					t.Fatal(err)
				}
				before := snapshotPreviewTree(t, fixture.layout.HomeDir)

				preview, err := fixture.lifecycle.Preview(context.Background(), requestForPreview(fixture.layout, request))
				if err != nil {
					t.Fatal(err)
				}
				if preview.Classification != PreviewBlocked || preview.ApplyAllowed ||
					preview.BlockReason != "installed_release_verification_failed" || len(preview.Actions) != 0 {
					t.Fatalf("destination-collision preview=%+v", preview)
				}
				if after := snapshotPreviewTree(t, fixture.layout.HomeDir); !reflect.DeepEqual(after, before) {
					t.Fatalf("destination-collision preview mutated target\n before=%+v\n after=%+v", before, after)
				}

				stageBefore, supportBefore, initializeBefore := fixture.stageCalls, fixture.supportStageCalls, fixture.initializeCalls
				managerCallsBefore := len(fixture.manager.calls)
				if _, err := applyConfirmed(t, fixture.lifecycle, request); err == nil ||
					!strings.Contains(err.Error(), "preflight desired release destinations") {
					t.Fatalf("destination-collision apply error=%v", err)
				}
				if fixture.stageCalls != stageBefore || fixture.supportStageCalls != supportBefore || fixture.initializeCalls != initializeBefore {
					t.Fatalf("destination collision reached mutation stage/support/init=%d/%d/%d", fixture.stageCalls-stageBefore, fixture.supportStageCalls-supportBefore, fixture.initializeCalls-initializeBefore)
				}
				if len(fixture.manager.calls) != managerCallsBefore {
					t.Fatalf("destination collision reached manager preflight: %v", fixture.manager.calls[managerCallsBefore:])
				}
				if after := snapshotPreviewTree(t, fixture.layout.HomeDir); !reflect.DeepEqual(after, before) {
					t.Fatalf("destination-collision apply preflight mutated target\n before=%+v\n after=%+v", before, after)
				}
			})
		}
	}
}

func TestDeploymentPreviewAllowsMissingInstalledFilesOnlyForMatchingIdempotentRequest(t *testing.T) {
	fixture := newLifecycleFixture(t, false)
	request, desired := fixture.release(t, "v1.2.3", "idempotent-missing")
	if _, err := applyConfirmed(t, fixture.lifecycle, request); err != nil {
		t.Fatal(err)
	}
	fixture.lifecycle.verifyPreviewRelease = func(context.Context, InstalledRelease) error {
		return errInstalledReleaseFilesMissing
	}

	preview, err := fixture.lifecycle.Preview(context.Background(), requestForPreview(fixture.layout, request))
	if err != nil {
		t.Fatal(err)
	}
	if preview.Classification != PreviewIdempotent || !preview.ApplyAllowed || preview.BlockReason != "" {
		t.Fatalf("matching missing-file preview=%+v", preview)
	}
	licensePath, err := desired.SupportFilePath(fixture.layout, "LICENSE")
	if err != nil {
		t.Fatal(err)
	}
	noticePath, err := desired.SupportFilePath(fixture.layout, "NOTICE")
	if err != nil {
		t.Fatal(err)
	}
	assertPreviewAction(t, preview.Actions, "verify_or_reuse_artifact", desired.BinaryPath, request.ArtifactPath)
	assertPreviewAction(t, preview.Actions, "verify_or_reuse_license", licensePath, request.LicensePath)
	assertPreviewAction(t, preview.Actions, "verify_or_reuse_notice", noticePath, request.NoticePath)
	fixture.manager.current = buildinfo.Identity{}
	runningIdentityBlocked, err := fixture.lifecycle.Preview(context.Background(), requestForPreview(fixture.layout, request))
	if err != nil {
		t.Fatal(err)
	}
	if runningIdentityBlocked.Classification != PreviewBlocked || runningIdentityBlocked.ApplyAllowed ||
		runningIdentityBlocked.BlockReason != "running_release_identity_does_not_match" {
		t.Fatalf("missing-file preview accepted mismatched running identity=%+v", runningIdentityBlocked)
	}
	fixture.manager.current = identityFor(desired)

	upgradeRequest, _ := fixture.release(t, "v1.2.4", "nonmatching-missing")
	blocked, err := fixture.lifecycle.Preview(context.Background(), requestForPreview(fixture.layout, upgradeRequest))
	if err != nil {
		t.Fatal(err)
	}
	if blocked.Classification != PreviewBlocked || blocked.ApplyAllowed || blocked.BlockReason != "installed_release_verification_failed" {
		t.Fatalf("nonmatching missing-file preview=%+v", blocked)
	}
}

func TestIdempotentRepairPreviewIncludesDirectoryPreparationWithoutMutation(t *testing.T) {
	fixture := newLifecycleFixture(t, false)
	request, desired := fixture.release(t, "v1.2.3", "idempotent-directory-repair")
	if _, err := applyConfirmed(t, fixture.lifecycle, request); err != nil {
		t.Fatal(err)
	}
	releaseDir, err := fixture.layout.VersionDir(desired.Release)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(fixture.layout.VersionsDir); err != nil {
		t.Fatal(err)
	}
	fixture.lifecycle.verifyPreviewRelease = func(ctx context.Context, release InstalledRelease) error {
		return verifyInstalledReleaseForPreview(ctx, fixture.layout, release)
	}
	before := snapshotPreviewTree(t, fixture.layout.HomeDir)

	preview, err := fixture.lifecycle.Preview(context.Background(), requestForPreview(fixture.layout, request))
	if err != nil {
		t.Fatal(err)
	}
	if preview.Classification != PreviewIdempotent || !preview.ApplyAllowed || preview.BlockReason != "" {
		t.Fatalf("directory-repair preview=%+v", preview)
	}
	assertPreviewActionPrefix(t, preview.Actions,
		"acquire_bootstrap_lock", "acquire_lifecycle_lock", "prepare_state_directory", "acquire_initialization_lock",
		"prepare_install_root", "prepare_versions_directory", "prepare_state_directory", "prepare_release_directory",
		"verify_or_reuse_artifact", "verify_or_reuse_license", "verify_or_reuse_notice", "verify_installed_release_identity",
	)
	if after := snapshotPreviewTree(t, fixture.layout.HomeDir); !reflect.DeepEqual(after, before) {
		t.Fatalf("idempotent repair preview mutated the target tree\n before=%+v\n after=%+v", before, after)
	}
	for _, path := range []string{fixture.layout.VersionsDir, releaseDir} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("preview recreated %s: %v", path, err)
		}
	}

	if _, err := applyConfirmed(t, fixture.lifecycle, request); err != nil {
		t.Fatalf("idempotent directory repair: %v", err)
	}
	for _, path := range []string{fixture.layout.VersionsDir, releaseDir} {
		if info, err := os.Lstat(path); err != nil || !info.IsDir() || info.Mode().Perm() != directoryMode {
			t.Fatalf("repaired directory %s info=%v error=%v", path, info, err)
		}
	}
	if _, err := LoadJournal(fixture.layout); !errors.Is(err, ErrNoDeploymentJournal) {
		t.Fatalf("idempotent repair created a journal: %v", err)
	}
}

func TestReadyInstancePreflightValidatesEveryRequiredFileBeforeJournal(t *testing.T) {
	cases := []struct {
		name        string
		blockReason string
		mutate      func(*testing.T, config.Paths)
	}{
		{
			name: "missing config", blockReason: "completed_instance_configuration_is_missing",
			mutate: func(t *testing.T, paths config.Paths) { t.Helper(); mustRemovePreviewPath(t, paths.Config) },
		},
		{
			name: "missing secret", blockReason: "completed_instance_secret_is_invalid",
			mutate: func(t *testing.T, paths config.Paths) { t.Helper(); mustRemovePreviewPath(t, paths.InstanceSecret) },
		},
		{
			name: "insecure secret", blockReason: "completed_instance_secret_is_invalid",
			mutate: func(t *testing.T, paths config.Paths) {
				t.Helper()
				if err := os.Chmod(paths.InstanceSecret, 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "missing database", blockReason: "completed_instance_database_is_invalid",
			mutate: func(t *testing.T, paths config.Paths) { t.Helper(); mustRemovePreviewPath(t, paths.Database) },
		},
		{
			name: "insecure database", blockReason: "completed_instance_database_is_invalid",
			mutate: func(t *testing.T, paths config.Paths) {
				t.Helper()
				if err := os.Chmod(paths.Database, 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "inconsistent ready marker", blockReason: "instance_install_marker_is_invalid",
			mutate: func(t *testing.T, paths config.Paths) {
				t.Helper()
				if err := os.WriteFile(paths.InstallMarker, []byte("{\"generation\":\"1\",\"phase\":\"ready\",\"state\":\"resume\"}\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			template := newLifecycleFixture(t, false)
			request, _ := template.release(t, "v1.2.3", "ready-instance-preflight-"+testCase.name)
			lifecycle, layout, manager := missingLayoutLifecycle(t, request)
			if _, err := instance.Initialize(context.Background(), layout.StateDir, nil); err != nil {
				t.Fatal(err)
			}
			paths := config.ForStateDir(layout.StateDir)
			testCase.mutate(t, paths)
			before := snapshotPreviewTree(t, layout.StateDir)

			preview, err := lifecycle.Preview(context.Background(), requestForPreview(layout, request))
			if err != nil {
				t.Fatal(err)
			}
			if preview.Classification != PreviewBlocked || preview.ApplyAllowed || preview.BlockReason != testCase.blockReason || len(preview.Actions) != 0 {
				t.Fatalf("invalid completed-instance preview=%+v", preview)
			}
			if after := snapshotPreviewTree(t, layout.StateDir); !reflect.DeepEqual(after, before) {
				t.Fatalf("preview mutated invalid completed instance\n before=%+v\n after=%+v", before, after)
			}
			managerCallsBeforeApply := len(manager.calls)
			if _, err := applyConfirmed(t, lifecycle, request); err == nil || !strings.Contains(err.Error(), testCase.blockReason) {
				t.Fatalf("invalid completed-instance apply error=%v", err)
			}
			if len(manager.calls) != managerCallsBeforeApply {
				t.Fatalf("invalid completed instance reached apply manager preflight: %v", manager.calls[managerCallsBeforeApply:])
			}
			if after := snapshotPreviewTree(t, layout.StateDir); !reflect.DeepEqual(after, before) {
				t.Fatalf("apply preflight mutated invalid completed instance\n before=%+v\n after=%+v", before, after)
			}
			for _, path := range []string{layout.InstallRoot, layout.JournalPath, layout.LockPath} {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("invalid completed-instance preflight created %s: %v", path, err)
				}
			}
		})
	}
}

func TestResumableInstancePreflightValidatesExistingFilesBeforeJournal(t *testing.T) {
	cases := []struct {
		name        string
		blockReason string
		mutate      func(*testing.T, config.Paths)
	}{
		{
			name: "short secret", blockReason: "resumable_instance_secret_is_invalid",
			mutate: func(t *testing.T, paths config.Paths) {
				t.Helper()
				if err := os.Chmod(paths.InstanceSecret, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(paths.InstanceSecret, []byte("short"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "broad secret mode", blockReason: "resumable_instance_secret_is_invalid",
			mutate: func(t *testing.T, paths config.Paths) {
				t.Helper()
				if err := os.Chmod(paths.InstanceSecret, 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "secret symlink", blockReason: "resumable_instance_secret_is_invalid",
			mutate: func(t *testing.T, paths config.Paths) {
				t.Helper()
				mustRemovePreviewPath(t, paths.InstanceSecret)
				target := filepath.Join(paths.StateDir, "secret-target")
				if err := os.WriteFile(target, bytes.Repeat([]byte{'s'}, 32), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, paths.InstanceSecret); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "secret hard link", blockReason: "resumable_instance_secret_is_invalid",
			mutate: func(t *testing.T, paths config.Paths) {
				t.Helper()
				if err := os.Link(paths.InstanceSecret, filepath.Join(paths.StateDir, "secret-second-link")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "broad database mode", blockReason: "resumable_instance_database_is_invalid",
			mutate: func(t *testing.T, paths config.Paths) {
				t.Helper()
				if err := os.Chmod(paths.Database, 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "malformed database contents", blockReason: "resumable_instance_database_is_invalid",
			mutate: func(t *testing.T, paths config.Paths) {
				t.Helper()
				if err := os.WriteFile(paths.Database, []byte("not sqlite"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "database belongs to different instance", blockReason: "resumable_instance_database_is_invalid",
			mutate: func(t *testing.T, paths config.Paths) {
				t.Helper()
				settings, err := config.LoadSettings(paths.Config)
				if err != nil {
					t.Fatal(err)
				}
				settings.VaultID = "00000000-0000-4000-8000-000000000004"
				if err := config.SaveSettings(paths.Config, settings); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "sidecar without database", blockReason: "resumable_instance_database_is_invalid",
			mutate: func(t *testing.T, paths config.Paths) {
				t.Helper()
				for _, path := range []string{paths.Database, paths.Database + "-wal", paths.Database + "-shm", paths.Database + "-journal"} {
					removePreviewPathIfPresent(t, path)
				}
				if err := os.WriteFile(paths.Database+"-wal", []byte("orphaned-sidecar"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "wal symlink", blockReason: "resumable_instance_database_is_invalid",
			mutate: func(t *testing.T, paths config.Paths) {
				t.Helper()
				candidate := paths.Database + "-wal"
				removePreviewPathIfPresent(t, candidate)
				target := filepath.Join(paths.StateDir, "wal-target")
				if err := os.WriteFile(target, []byte("wal"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, candidate); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "shm hard link", blockReason: "resumable_instance_database_is_invalid",
			mutate: func(t *testing.T, paths config.Paths) {
				t.Helper()
				candidate := paths.Database + "-shm"
				removePreviewPathIfPresent(t, candidate)
				if err := os.WriteFile(candidate, []byte("shm"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(candidate, filepath.Join(paths.StateDir, "shm-second-link")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "journal directory", blockReason: "resumable_instance_database_is_invalid",
			mutate: func(t *testing.T, paths config.Paths) {
				t.Helper()
				candidate := paths.Database + "-journal"
				removePreviewPathIfPresent(t, candidate)
				if err := os.Mkdir(candidate, 0o700); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "sidecar without configuration", blockReason: "partial_instance_has_unrecoverable_data_without_configuration",
			mutate: func(t *testing.T, paths config.Paths) {
				t.Helper()
				for _, path := range []string{paths.Config, paths.InstanceSecret, paths.Database, paths.Database + "-wal", paths.Database + "-shm", paths.Database + "-journal"} {
					removePreviewPathIfPresent(t, path)
				}
				if err := os.WriteFile(paths.Database+"-wal", []byte("orphaned-sidecar"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			template := newLifecycleFixture(t, false)
			request, _ := template.release(t, "v1.2.3", "resumable-instance-preflight-"+testCase.name)
			lifecycle, layout, manager := missingLayoutLifecycle(t, request)
			if _, err := instance.Initialize(context.Background(), layout.StateDir, nil); err != nil {
				t.Fatal(err)
			}
			paths := config.ForStateDir(layout.StateDir)
			if err := config.SaveMarker(paths.InstallMarker, config.InstallMarker{Generation: "1", Phase: "initializing", State: "resume"}); err != nil {
				t.Fatal(err)
			}
			testCase.mutate(t, paths)
			before := snapshotPreviewTree(t, layout.HomeDir)

			preview, err := lifecycle.Preview(context.Background(), requestForPreview(layout, request))
			if err != nil {
				t.Fatal(err)
			}
			if preview.Classification != PreviewBlocked || preview.ApplyAllowed || preview.BlockReason != testCase.blockReason || len(preview.Actions) != 0 {
				t.Fatalf("invalid resumable-instance preview=%+v", preview)
			}
			if after := snapshotPreviewTree(t, layout.HomeDir); !reflect.DeepEqual(after, before) {
				t.Fatalf("preview mutated invalid resumable instance\n before=%+v\n after=%+v", before, after)
			}
			managerCallsBeforeApply := len(manager.calls)
			if _, err := applyConfirmed(t, lifecycle, request); err == nil || !strings.Contains(err.Error(), testCase.blockReason) {
				t.Fatalf("invalid resumable-instance apply error=%v", err)
			}
			if len(manager.calls) != managerCallsBeforeApply {
				t.Fatalf("invalid resumable instance reached apply manager preflight: %v", manager.calls[managerCallsBeforeApply:])
			}
			if after := snapshotPreviewTree(t, layout.HomeDir); !reflect.DeepEqual(after, before) {
				t.Fatalf("apply preflight mutated invalid resumable instance\n before=%+v\n after=%+v", before, after)
			}
			for _, path := range []string{layout.InstallRoot, layout.JournalPath, layout.LockPath} {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("invalid resumable-instance preflight created %s: %v", path, err)
				}
			}
		})
	}
}

func TestResumableInstancePreflightDoesNotRequireFilesInitializationMayCreate(t *testing.T) {
	for _, markerState := range []string{"initializing", "absent"} {
		for _, databaseState := range []string{"missing", "empty"} {
			t.Run(markerState+"/"+databaseState, func(t *testing.T) {
				template := newLifecycleFixture(t, false)
				request, _ := template.release(t, "v1.2.3", "resumable-missing-files-"+markerState+"-"+databaseState)
				lifecycle, layout, _ := missingLayoutLifecycle(t, request)
				if _, err := instance.Initialize(context.Background(), layout.StateDir, nil); err != nil {
					t.Fatal(err)
				}
				paths := config.ForStateDir(layout.StateDir)
				if markerState == "initializing" {
					if err := config.SaveMarker(paths.InstallMarker, config.InstallMarker{Generation: "1", Phase: "initializing", State: "resume"}); err != nil {
						t.Fatal(err)
					}
				} else {
					mustRemovePreviewPath(t, paths.InstallMarker)
				}
				for _, path := range []string{paths.InstanceSecret, paths.Database, paths.Database + "-wal", paths.Database + "-shm", paths.Database + "-journal"} {
					removePreviewPathIfPresent(t, path)
				}
				if databaseState == "empty" {
					if err := os.WriteFile(paths.Database, nil, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				before := snapshotPreviewTree(t, layout.HomeDir)

				preview, err := lifecycle.Preview(context.Background(), requestForPreview(layout, request))
				if err != nil {
					t.Fatal(err)
				}
				wantInstanceState := markerState
				if markerState == "absent" {
					wantInstanceState = "resume"
				}
				if preview.Classification != PreviewFresh || !preview.ApplyAllowed || preview.Existing.InstanceState != wantInstanceState {
					t.Fatalf("resumable creatable-file preview=%+v", preview)
				}
				if after := snapshotPreviewTree(t, layout.HomeDir); !reflect.DeepEqual(after, before) {
					t.Fatalf("resumable creatable-file preview mutated the target\n before=%+v\n after=%+v", before, after)
				}
			})
		}
	}
}

func TestPreviewAndApplyRejectUnsafeExistingServiceDefinitionBeforeMutation(t *testing.T) {
	unsafeDefinitions := []struct {
		name      string
		wantError string
		prepare   func(*testing.T, string, string)
	}{
		{
			name: "symlink", wantError: "validate existing service definition",
			prepare: func(t *testing.T, home, definition string) {
				t.Helper()
				target := filepath.Join(home, "unsafe-definition-target")
				if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, definition); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "hard link", wantError: "exactly one hard link",
			prepare: func(t *testing.T, home, definition string) {
				t.Helper()
				target := filepath.Join(home, "unsafe-definition-hardlink-target")
				if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(target, definition); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "broad mode", wantError: "broader than 0600",
			prepare: func(t *testing.T, _, definition string) {
				t.Helper()
				if err := os.WriteFile(definition, []byte("definition"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(definition, 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, classification := range []string{"fresh", "upgrade"} {
		for _, unsafeDefinition := range unsafeDefinitions {
			t.Run(classification+"/"+unsafeDefinition.name, func(t *testing.T) {
				fixture := newLifecycleFixture(t, false)
				request, _ := fixture.release(t, "v1.2.3", "unsafe-definition-fresh")
				if classification == "upgrade" {
					if _, err := applyConfirmed(t, fixture.lifecycle, request); err != nil {
						t.Fatal(err)
					}
					request, _ = fixture.release(t, "v1.2.4", "unsafe-definition-upgrade")
				}
				if err := os.MkdirAll(filepath.Dir(fixture.manager.definition), directoryMode); err != nil {
					t.Fatal(err)
				}
				unsafeDefinition.prepare(t, fixture.layout.HomeDir, fixture.manager.definition)
				before := snapshotPreviewTree(t, fixture.layout.HomeDir)
				stageBefore, supportBefore, initializeBefore := fixture.stageCalls, fixture.supportStageCalls, fixture.initializeCalls
				managerCallsBefore := len(fixture.manager.calls)

				if _, err := fixture.lifecycle.Preview(context.Background(), requestForPreview(fixture.layout, request)); err == nil || !strings.Contains(err.Error(), unsafeDefinition.wantError) {
					t.Fatalf("unsafe service-definition preview error=%v", err)
				}
				if _, err := applyConfirmed(t, fixture.lifecycle, request); err == nil || !strings.Contains(err.Error(), unsafeDefinition.wantError) {
					t.Fatalf("unsafe service-definition apply error=%v", err)
				}
				if fixture.stageCalls != stageBefore || fixture.supportStageCalls != supportBefore || fixture.initializeCalls != initializeBefore {
					t.Fatalf("unsafe service definition reached mutation stage/support/init=%d/%d/%d", fixture.stageCalls-stageBefore, fixture.supportStageCalls-supportBefore, fixture.initializeCalls-initializeBefore)
				}
				for _, call := range fixture.manager.calls[managerCallsBefore:] {
					if call == "install" || call == "activate" || call == "stop" || call == "remove" {
						t.Fatalf("unsafe service definition reached manager mutation: %v", fixture.manager.calls[managerCallsBefore:])
					}
				}
				if after := snapshotPreviewTree(t, fixture.layout.HomeDir); !reflect.DeepEqual(after, before) {
					t.Fatalf("unsafe service-definition preflight mutated the target tree\n before=%+v\n after=%+v", before, after)
				}
				if _, err := LoadJournal(fixture.layout); !errors.Is(err, ErrNoDeploymentJournal) {
					t.Fatalf("unsafe service-definition preflight created a journal: %v", err)
				}
			})
		}
	}
}

func TestDeploymentPreviewClassifiesEveryTargetAndManagerMode(t *testing.T) {
	for _, target := range SupportedTargets() {
		for _, foreground := range []bool{false, true} {
			name := fmt.Sprintf("%s-%s-foreground-%t", target.OS, target.Architecture, foreground)
			t.Run(name, func(t *testing.T) {
				fixture := newLifecycleFixture(t, false)
				fixture.target = target
				fixture.lifecycle.target = target
				managerKind := ManagerSystemd
				definition := filepath.Join(fixture.layout.HomeDir, ".config", "systemd", "user", "com.kciceblue.sshserver.service")
				if target.OS == "darwin" {
					managerKind = ManagerLaunchd
					definition = filepath.Join(fixture.layout.HomeDir, "Library", "LaunchAgents", "com.kciceblue.sshserver.plist")
				}
				fixture.manager.kind = managerKind
				fixture.manager.definition = definition
				fixture.manager.availability = ManagerAvailability{Manager: managerKind, Available: true, ServiceDefinition: definition}
				if foreground {
					fixture.manager.availability = foregroundAvailability(fixture.layout, "/rewritten-by-probe")
				}
				request, desired := fixture.release(t, "v1.2.3", name)
				preview, err := fixture.lifecycle.Preview(context.Background(), requestForPreview(fixture.layout, request))
				if err != nil {
					t.Fatal(err)
				}
				if preview.Target.OS != target.OS || preview.Target.Architecture != target.Architecture || preview.Paths.BinaryPath != desired.BinaryPath {
					t.Fatalf("target preview=%+v", preview)
				}
				if foreground {
					want := []string{desired.BinaryPath, "serve", "--state-dir", fixture.layout.StateDir}
					if preview.Manager.Manager != ManagerForeground || preview.Manager.Foreground == nil || !reflect.DeepEqual(preview.Manager.Foreground.Command, want) {
						t.Fatalf("foreground manager=%+v", preview.Manager)
					}
				} else if preview.Manager.Manager != managerKind || !preview.Manager.Available || preview.Paths.ServiceDefinition != definition {
					t.Fatalf("native manager=%+v paths=%+v", preview.Manager, preview.Paths)
				}
				assertCanonicalPreview(t, preview)
			})
		}
	}
}

func TestDeploymentPreviewReportsResumeRecoveryAndBlockedStates(t *testing.T) {
	t.Run("matching apply resumes", func(t *testing.T) {
		fixture := newLifecycleFixture(t, false)
		request, _ := fixture.release(t, "v1.2.3", "resume")
		fixture.lifecycle.failAfterPhase = PhaseArtifactStaged
		if _, err := applyConfirmed(t, fixture.lifecycle, request); !errors.Is(err, ErrInjectedDeploymentCrash) {
			t.Fatalf("injected apply error=%v", err)
		}
		fixture.lifecycle.failAfterPhase = ""
		preview, err := fixture.lifecycle.Preview(context.Background(), requestForPreview(fixture.layout, request))
		if err != nil {
			t.Fatal(err)
		}
		if preview.Classification != PreviewResumeOrRecoveryRequired || !preview.ApplyAllowed || preview.Existing.Journal == nil ||
			preview.Existing.Journal.Phase != PhaseArtifactStaged {
			t.Fatalf("resume preview=%+v", preview)
		}
		assertPreviewActionPrefix(t, preview.Actions,
			"acquire_bootstrap_lock", "acquire_lifecycle_lock", "prepare_state_directory", "acquire_initialization_lock",
			"prepare_install_root", "prepare_versions_directory", "prepare_state_directory", "resume_apply_journal",
		)
		assertPreviewActionsContain(t, preview.Actions, "resume_apply_journal", "initialize_or_resume_loopback_instance", "remove_apply_journal")
	})

	t.Run("matching recovery locks before remaining layout repair", func(t *testing.T) {
		fixture := newLifecycleFixture(t, false)
		request, _ := fixture.release(t, "v1.2.3", "resume-lock-order")
		fixture.lifecycle.failAfterPhase = PhasePlanned
		if _, err := applyConfirmed(t, fixture.lifecycle, request); !errors.Is(err, ErrInjectedDeploymentCrash) {
			t.Fatalf("injected planned apply error=%v", err)
		}
		fixture.lifecycle.failAfterPhase = ""
		if err := os.Remove(fixture.layout.VersionsDir); err != nil {
			t.Fatal(err)
		}

		preview, err := fixture.lifecycle.Preview(context.Background(), request.previewRequest())
		if err != nil {
			t.Fatal(err)
		}
		assertPreviewActionPrefix(t, preview.Actions,
			"acquire_bootstrap_lock", "acquire_lifecycle_lock", "prepare_state_directory", "acquire_initialization_lock",
			"prepare_install_root", "prepare_versions_directory", "prepare_state_directory", "resume_apply_journal",
		)
		canonical, err := preview.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		request.ConfirmedPreviewSHA256 = SHA256Hex(canonical)
		originalAcquire := fixture.lifecycle.acquireInstanceLease
		acquiredBeforeRemainingLayout := false
		fixture.lifecycle.acquireInstanceLease = func(stateDir string, initializationLockPresent bool) (instanceInitializationLease, error) {
			if _, err := os.Lstat(fixture.layout.VersionsDir); !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("versions directory was prepared before initialization lease: %v", err)
			}
			bootstrapProbe, bootstrapErr := acquireDeploymentBootstrapLock(fixture.layout)
			if bootstrapErr == nil {
				bootstrapProbe.Close()
				return nil, errors.New("initialization lease reached without bootstrap admission")
			}
			lifecycleProbe, lifecycleErr := acquireExistingDeploymentLock(fixture.layout)
			if lifecycleErr == nil {
				lifecycleProbe.Close()
				return nil, errors.New("initialization lease reached without lifecycle lock")
			}
			acquiredBeforeRemainingLayout = true
			return originalAcquire(stateDir, initializationLockPresent)
		}
		if _, err := fixture.lifecycle.Apply(context.Background(), request); err != nil {
			t.Fatalf("resume with locked layout repair: %v", err)
		}
		if !acquiredBeforeRemainingLayout {
			t.Fatal("matching recovery did not acquire the initialization lease")
		}
		if info, err := os.Lstat(fixture.layout.VersionsDir); err != nil || !info.IsDir() {
			t.Fatalf("matching recovery did not repair versions directory: %v", err)
		}
	})

	t.Run("planned recovery records verified input rebind", func(t *testing.T) {
		fixture := newLifecycleFixture(t, false)
		request, _ := fixture.release(t, "v1.2.3", "resume-rebind")
		fixture.lifecycle.failAfterPhase = PhasePlanned
		if _, err := applyConfirmed(t, fixture.lifecycle, request); !errors.Is(err, ErrInjectedDeploymentCrash) {
			t.Fatalf("injected apply error=%v", err)
		}
		fixture.lifecycle.failAfterPhase = ""
		alternateDirectory := filepath.Join(fixture.layout.HomeDir, "alternate-upload")
		request.ArtifactPath = filepath.Join(alternateDirectory, "sshserver")
		request.LicensePath = filepath.Join(alternateDirectory, "LICENSE")
		request.NoticePath = filepath.Join(alternateDirectory, "NOTICE")
		preview, err := fixture.lifecycle.Preview(context.Background(), requestForPreview(fixture.layout, request))
		if err != nil {
			t.Fatal(err)
		}
		assertPreviewActionPrefix(t, preview.Actions,
			"acquire_bootstrap_lock", "acquire_lifecycle_lock", "prepare_state_directory", "acquire_initialization_lock",
			"prepare_install_root", "prepare_versions_directory", "prepare_state_directory", "resume_apply_journal", "rebind_apply_journal_inputs",
		)
		var rebind *PreviewAction
		for index := range preview.Actions {
			if preview.Actions[index].Operation == "rebind_apply_journal_inputs" {
				rebind = &preview.Actions[index]
				break
			}
		}
		if rebind == nil || !reflect.DeepEqual(rebind.Arguments, []string{request.ArtifactPath, request.LicensePath, request.NoticePath}) {
			t.Fatalf("rebind action=%+v", rebind)
		}
		assertCanonicalPreview(t, preview)
	})

	t.Run("state-saved recovery requires exact committed state", func(t *testing.T) {
		for _, testCase := range []struct {
			name   string
			mutate func(*testing.T, *lifecycleFixture)
		}{
			{
				name: "missing state",
				mutate: func(t *testing.T, fixture *lifecycleFixture) {
					t.Helper()
					if err := os.Remove(fixture.layout.StatePath); err != nil {
						t.Fatal(err)
					}
				},
			},
			{
				name: "individually valid mismatched state",
				mutate: func(t *testing.T, fixture *lifecycleFixture) {
					t.Helper()
					state, err := LoadState(fixture.layout)
					if err != nil {
						t.Fatal(err)
					}
					state.Generation++
					if err := SaveState(fixture.layout, state); err != nil {
						t.Fatal(err)
					}
				},
			},
		} {
			t.Run(testCase.name, func(t *testing.T) {
				fixture := newLifecycleFixture(t, false)
				request, _ := fixture.release(t, "v1.2.3", "state-saved-"+testCase.name)
				fixture.lifecycle.failAfterPhase = PhaseStateSaved
				if _, err := applyConfirmed(t, fixture.lifecycle, request); !errors.Is(err, ErrInjectedDeploymentCrash) {
					t.Fatalf("injected state-saved apply error=%v", err)
				}
				fixture.lifecycle.failAfterPhase = ""

				exact, err := fixture.lifecycle.Preview(context.Background(), request.previewRequest())
				if err != nil {
					t.Fatal(err)
				}
				if !exact.ApplyAllowed || exact.Existing.Journal == nil || exact.Existing.Journal.Phase != PhaseStateSaved {
					t.Fatalf("exact state-saved preview=%+v", exact)
				}
				assertPreviewActionsContain(t, exact.Actions, "resume_apply_journal", "remove_apply_journal")
				assertPreviewActionsExclude(t, exact.Actions, "commit_deployment_state", "checkpoint_apply_journal")

				testCase.mutate(t, fixture)
				blocked, err := fixture.lifecycle.Preview(context.Background(), request.previewRequest())
				if err != nil {
					t.Fatal(err)
				}
				if blocked.Classification != PreviewResumeOrRecoveryRequired || blocked.ApplyAllowed ||
					blocked.BlockReason != "saved_deployment_state_does_not_match_recovering_transaction" || len(blocked.Actions) != 0 {
					t.Fatalf("mismatched state-saved preview=%+v", blocked)
				}
				canonical, err := blocked.CanonicalBytes()
				if err != nil {
					t.Fatal(err)
				}
				request.ConfirmedPreviewSHA256 = SHA256Hex(canonical)
				before := snapshotPreviewTree(t, fixture.layout.HomeDir)
				if _, err := fixture.lifecycle.Apply(context.Background(), request); err == nil ||
					!strings.Contains(err.Error(), "confirmed deployment preview is not applicable") {
					t.Fatalf("blocked state-saved apply error=%v", err)
				}
				if after := snapshotPreviewTree(t, fixture.layout.HomeDir); !reflect.DeepEqual(after, before) {
					t.Fatalf("blocked state-saved apply mutated target\n before=%+v\n after=%+v", before, after)
				}
				journal, err := LoadJournal(fixture.layout)
				if err != nil || journal.Phase != PhaseStateSaved {
					t.Fatalf("blocked state-saved journal=%+v err=%v", journal, err)
				}
			})
		}
	})

	t.Run("different release requires matching recovery", func(t *testing.T) {
		fixture := newLifecycleFixture(t, false)
		first, _ := fixture.release(t, "v1.2.3", "recovery-first")
		fixture.lifecycle.failAfterPhase = PhasePlanned
		if _, err := applyConfirmed(t, fixture.lifecycle, first); !errors.Is(err, ErrInjectedDeploymentCrash) {
			t.Fatalf("injected apply error=%v", err)
		}
		fixture.lifecycle.failAfterPhase = ""
		second, _ := fixture.release(t, "v1.2.4", "recovery-second")
		preview, err := fixture.lifecycle.Preview(context.Background(), requestForPreview(fixture.layout, second))
		if err != nil {
			t.Fatal(err)
		}
		if preview.Classification != PreviewResumeOrRecoveryRequired || preview.ApplyAllowed ||
			preview.BlockReason != "different_deployment_transaction_requires_matching_recovery" {
			t.Fatalf("recovery preview=%+v", preview)
		}
	})

	t.Run("damaged installed release blocks", func(t *testing.T) {
		fixture := newLifecycleFixture(t, false)
		request, _ := fixture.release(t, "v1.2.3", "damaged")
		if _, err := applyConfirmed(t, fixture.lifecycle, request); err != nil {
			t.Fatal(err)
		}
		fixture.lifecycle.verifyPreviewRelease = func(context.Context, InstalledRelease) error { return errors.New("damaged") }
		preview, err := fixture.lifecycle.Preview(context.Background(), requestForPreview(fixture.layout, request))
		if err != nil {
			t.Fatal(err)
		}
		if preview.Classification != PreviewBlocked || preview.ApplyAllowed || preview.BlockReason != "installed_release_verification_failed" {
			t.Fatalf("blocked preview=%+v", preview)
		}
	})

	t.Run("native to foreground transition blocks", func(t *testing.T) {
		fixture := newLifecycleFixture(t, false)
		first, _ := fixture.release(t, "v1.2.3", "native")
		if _, err := applyConfirmed(t, fixture.lifecycle, first); err != nil {
			t.Fatal(err)
		}
		fixture.manager.availability = foregroundAvailability(fixture.layout, "/rewritten")
		second, _ := fixture.release(t, "v1.2.4", "foreground")
		preview, err := fixture.lifecycle.Preview(context.Background(), requestForPreview(fixture.layout, second))
		if err != nil {
			t.Fatal(err)
		}
		if preview.Classification != PreviewBlocked || preview.BlockReason != "active_native_manager_unavailable" {
			t.Fatalf("transition preview=%+v", preview)
		}
	})
}

func TestNonApplyRecoveryPreviewMirrorsMutationAdmissionAndLayoutOrder(t *testing.T) {
	for _, operation := range []Operation{OperationRollback, OperationUninstall} {
		for _, lifecycleLockPresent := range []bool{true, false} {
			name := fmt.Sprintf("%s/lifecycle-lock-present-%t", operation, lifecycleLockPresent)
			t.Run(name, func(t *testing.T) {
				fixture := newLifecycleFixture(t, false)
				request, _ := fixture.release(t, "v1.2.3", name+"-installed")
				if _, err := applyConfirmed(t, fixture.lifecycle, request); err != nil {
					t.Fatal(err)
				}
				if operation == OperationRollback {
					request, _ = fixture.release(t, "v1.2.4", name+"-active")
					if _, err := applyConfirmed(t, fixture.lifecycle, request); err != nil {
						t.Fatal(err)
					}
				}

				fixture.lifecycle.failAfterPhase = PhasePlanned
				var err error
				if operation == OperationRollback {
					_, err = fixture.lifecycle.Rollback(context.Background())
				} else {
					_, err = fixture.lifecycle.Uninstall(context.Background())
				}
				if !errors.Is(err, ErrInjectedDeploymentCrash) {
					t.Fatalf("injected %s error=%v", operation, err)
				}
				fixture.lifecycle.failAfterPhase = ""
				if !lifecycleLockPresent {
					if err := os.Remove(fixture.layout.LockPath); err != nil {
						t.Fatal(err)
					}
				}

				before := snapshotPreviewTree(t, fixture.layout.HomeDir)
				preview, err := fixture.lifecycle.Preview(context.Background(), request.previewRequest())
				if err != nil {
					t.Fatal(err)
				}
				if preview.Classification != PreviewResumeOrRecoveryRequired || preview.ApplyAllowed ||
					preview.BlockReason != "different_deployment_transaction_requires_matching_recovery" ||
					preview.Existing.Journal == nil || preview.Existing.Journal.Operation != operation ||
					preview.Existing.LifecycleLockPresent != lifecycleLockPresent {
					t.Fatalf("%s recovery preview=%+v", operation, preview)
				}
				expectedPrefix := []string{"acquire_bootstrap_lock"}
				if lifecycleLockPresent {
					expectedPrefix = append(expectedPrefix, "acquire_lifecycle_lock")
				} else {
					expectedPrefix = append(expectedPrefix, "prepare_install_root", "create_lifecycle_lock", "acquire_lifecycle_lock")
				}
				expectedPrefix = append(expectedPrefix,
					"prepare_install_root", "prepare_versions_directory", "prepare_state_directory", "recover_existing_transaction",
				)
				assertPreviewActionPrefix(t, preview.Actions, expectedPrefix...)
				assertPreviewActionsExclude(t, preview.Actions, "create_initialization_lock", "acquire_initialization_lock")
				recovery := preview.Actions[len(preview.Actions)-1]
				if recovery.Path != fixture.layout.JournalPath || len(recovery.Arguments) != 2 ||
					recovery.Arguments[0] != string(operation) || recovery.Arguments[1] != string(PhasePlanned) {
					t.Fatalf("%s recovery action=%+v", operation, recovery)
				}
				assertCanonicalPreview(t, preview)
				if after := snapshotPreviewTree(t, fixture.layout.HomeDir); !reflect.DeepEqual(after, before) {
					t.Fatalf("%s recovery preview mutated target\n before=%+v\n after=%+v", operation, before, after)
				}
			})
		}
	}
}

func TestDeploymentPreviewAndApplyManagerPreflightDoNotMutateOnCancelOrFailure(t *testing.T) {
	template := newLifecycleFixture(t, false)
	request, _ := template.release(t, "v1.2.3", "zero-mutation")

	t.Run("successful preview then cancel", func(t *testing.T) {
		lifecycle, layout, manager := missingLayoutLifecycle(t, request)
		preview, err := lifecycle.Preview(context.Background(), requestForPreview(layout, request))
		if err != nil || preview.Classification != PreviewFresh || len(manager.calls) != 1 {
			t.Fatalf("preview=%+v manager=%v error=%v", preview, manager.calls, err)
		}
		assertMissingPreviewTargets(t, layout)
	})

	t.Run("preview input failure", func(t *testing.T) {
		lifecycle, layout, manager := missingLayoutLifecycle(t, request)
		lifecycle.verifySourceArtifact = func(string, InstalledRelease) error { return errors.New("bad artifact") }
		if _, err := lifecycle.Preview(context.Background(), requestForPreview(layout, request)); err == nil || !strings.Contains(err.Error(), "bad artifact") {
			t.Fatalf("preview failure=%v", err)
		}
		if len(manager.calls) != 0 {
			t.Fatalf("invalid input reached manager probe: %v", manager.calls)
		}
		assertMissingPreviewTargets(t, layout)
	})

	t.Run("initial apply manager failure", func(t *testing.T) {
		lifecycle, layout, manager := missingLayoutLifecycle(t, request)
		manager.failures["detect"] = 1
		if _, err := applyConfirmed(t, lifecycle, request); err == nil || !strings.Contains(err.Error(), "detect") {
			t.Fatalf("apply manager failure=%v", err)
		}
		assertMissingPreviewTargets(t, layout)
	})
}

func TestApplyRevalidatesManagerBeforeDeploymentActions(t *testing.T) {
	template := newLifecycleFixture(t, false)
	request, _ := template.release(t, "v1.2.3", "manager-race")
	lifecycle, layout, manager := missingLayoutLifecycle(t, request)
	native := cloneManagerAvailability(manager.availability)
	foreground := foregroundAvailability(layout, "/rewritten")
	manager.detectResults = []ManagerAvailability{native, foreground}
	stageCalls, leaseCalls := 0, 0
	lifecycle.stageArtifact = func(string, string, string, int64, string) (string, error) {
		stageCalls++
		return "", errors.New("unexpected stage")
	}
	lifecycle.acquireInstanceLease = func(string, bool) (instanceInitializationLease, error) {
		leaseCalls++
		return nil, errors.New("unexpected initialization lease")
	}
	if _, err := applyConfirmed(t, lifecycle, request); err == nil || !strings.Contains(err.Error(), "changed during apply preflight") {
		t.Fatalf("manager race error=%v", err)
	}
	if stageCalls != 0 || leaseCalls != 0 {
		t.Fatalf("manager race reached deployment actions stage/lease=%d/%d", stageCalls, leaseCalls)
	}
	if _, err := LoadJournal(layout); !errors.Is(err, ErrNoDeploymentJournal) {
		t.Fatalf("manager race created journal: %v", err)
	}
	if _, err := LoadState(layout); !errors.Is(err, ErrNoDeploymentState) {
		t.Fatalf("manager race created state: %v", err)
	}
	assertMissingPreviewTargets(t, layout)
	if !reflect.DeepEqual(manager.calls, []string{"detect", "detect"}) {
		t.Fatalf("manager race calls=%v", manager.calls)
	}
}

func TestDeploymentPreviewForegroundJournalRecoveryRequiresStoppedRuntime(t *testing.T) {
	for _, phase := range []Phase{PhasePlanned, PhaseArtifactStaged, PhaseInstanceReady} {
		for _, running := range []bool{false, true} {
			name := fmt.Sprintf("%s/running-%t", phase, running)
			t.Run(name, func(t *testing.T) {
				fixture := newLifecycleFixture(t, true)
				firstRequest, firstRelease := fixture.release(t, "v1.2.3", name+"-prior")
				if _, err := applyConfirmed(t, fixture.lifecycle, firstRequest); err != nil {
					t.Fatal(err)
				}
				fixture.manager.active = false
				secondRequest, _ := fixture.release(t, "v1.2.4", name+"-desired")
				fixture.lifecycle.failAfterPhase = phase
				if _, err := applyConfirmed(t, fixture.lifecycle, secondRequest); !errors.Is(err, ErrInjectedDeploymentCrash) {
					t.Fatalf("injected apply error=%v", err)
				}
				fixture.lifecycle.failAfterPhase = ""
				fixture.manager.active = running
				fixture.manager.current = identityFor(firstRelease)

				preview, err := fixture.lifecycle.Preview(context.Background(), requestForPreview(fixture.layout, secondRequest))
				if err != nil {
					t.Fatal(err)
				}
				if preview.Classification != PreviewResumeOrRecoveryRequired || preview.Existing.Journal == nil ||
					preview.Existing.Journal.Phase != phase {
					t.Fatalf("recovery preview=%+v", preview)
				}
				if running {
					if preview.ApplyAllowed || preview.BlockReason != "supervised_foreground_runtime_must_stop_before_apply" || len(preview.Actions) != 0 {
						t.Fatalf("running foreground recovery was not blocked: %+v", preview)
					}
					return
				}
				if !preview.ApplyAllowed || preview.BlockReason != "" {
					t.Fatalf("stopped foreground recovery was not allowed: %+v", preview)
				}
				assertPreviewActionsContain(t, preview.Actions, "verify_prior_foreground_stopped")
				if phase == PhasePlanned {
					assertPreviewActionPrefix(t, preview.Actions,
						"acquire_bootstrap_lock", "acquire_lifecycle_lock", "prepare_state_directory", "acquire_initialization_lock",
						"prepare_install_root", "prepare_versions_directory", "prepare_state_directory",
						"resume_apply_journal", "prepare_release_directory", "publish_verified_artifact",
					)
				} else {
					assertPreviewActionsExclude(t, preview.Actions, "prepare_release_directory")
				}
			})
		}
	}
}

func TestPreviewAndApplyRejectUnsafeExistingLockBeforeMutation(t *testing.T) {
	template := newLifecycleFixture(t, false)
	request, _ := template.release(t, "v1.2.3", "unsafe-lock")
	lifecycle, layout, manager := missingLayoutLifecycle(t, request)
	if err := os.Mkdir(layout.InstallRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.LockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(layout.LockPath, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := lifecycle.Preview(context.Background(), requestForPreview(layout, request)); err == nil || !strings.Contains(err.Error(), "deployment lock") {
		t.Fatalf("unsafe-lock preview error=%v", err)
	}
	if _, err := applyConfirmed(t, lifecycle, request); err == nil || !strings.Contains(err.Error(), "deployment lock") {
		t.Fatalf("unsafe-lock apply error=%v", err)
	}
	if len(manager.calls) != 0 {
		t.Fatalf("unsafe lock reached manager probe: %v", manager.calls)
	}
	for _, path := range []string{layout.VersionsDir, layout.StateDir, layout.StatePath, layout.JournalPath} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unsafe-lock preflight created %s: %v", path, err)
		}
	}
}

func TestDeploymentPreviewRetriesWhenFirstApplyCreatesLifecycleLock(t *testing.T) {
	fixture := newLifecycleFixture(t, false)
	request, desired := fixture.release(t, "v1.2.3", "first-apply-lock-race")
	if _, err := applyConfirmed(t, fixture.lifecycle, request); err != nil {
		t.Fatal(err)
	}
	state, err := LoadState(fixture.layout)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(fixture.layout.LockPath); err != nil {
		t.Fatal(err)
	}
	fixture.manager.calls = nil

	verificationCalls := 0
	fixture.lifecycle.verifyPreviewRelease = func(context.Context, InstalledRelease) error {
		verificationCalls++
		if verificationCalls != 1 {
			return nil
		}
		// Interleave first apply after preview has loaded both state and the
		// absent journal. The tentative snapshot would otherwise classify the
		// old state and miss this newly durable transaction.
		lock, err := acquireDeploymentLock(fixture.layout)
		if err != nil {
			return err
		}
		journal := DeploymentJournal{
			StateVersion:      DeploymentStateVersion,
			TransactionID:     strings.Repeat("a", 32),
			Operation:         OperationApply,
			Phase:             PhasePlanned,
			Manager:           state.Manager,
			ServiceDefinition: state.ServiceDefinition,
			SourcePath:        request.ArtifactPath,
			LicenseSourcePath: request.LicensePath,
			NoticeSourcePath:  request.NoticePath,
			Desired:           &desired,
			PriorState:        &state,
		}
		if err := SaveJournal(fixture.layout, journal); err != nil {
			_ = lock.Close()
			return err
		}
		return lock.Close()
	}

	preview, err := fixture.lifecycle.Preview(context.Background(), requestForPreview(fixture.layout, request))
	if err != nil {
		t.Fatal(err)
	}
	if preview.Classification != PreviewResumeOrRecoveryRequired || !preview.ApplyAllowed ||
		preview.Existing.Journal == nil || preview.Existing.Journal.Phase != PhasePlanned {
		t.Fatalf("preview returned mixed pre-transaction snapshot: %+v", preview)
	}
	detectCalls := 0
	for _, call := range fixture.manager.calls {
		if call == "detect" {
			detectCalls++
		}
	}
	if detectCalls != 2 || verificationCalls != 2 {
		t.Fatalf("preview did not discard and rebuild tentative snapshot: manager=%v verification_calls=%d", fixture.manager.calls, verificationCalls)
	}
}

func TestApplyRejectsMalformedManagerOutcomeBeforeMutation(t *testing.T) {
	template := newLifecycleFixture(t, false)
	request, _ := template.release(t, "v1.2.3", "malformed-manager")
	lifecycle, layout, manager := missingLayoutLifecycle(t, request)
	manager.availability.Available = false
	if _, err := applyConfirmed(t, lifecycle, request); err == nil || !strings.Contains(err.Error(), "invalid foreground outcome") {
		t.Fatalf("malformed manager error=%v", err)
	}
	assertMissingPreviewTargets(t, layout)
}

func TestDeploymentPreviewRejectsMalformedInputsAndNoncanonicalOutput(t *testing.T) {
	fixture := newLifecycleFixture(t, false)
	request, _ := fixture.release(t, "v1.2.3", "canonical")
	valid := requestForPreview(fixture.layout, request)
	preview, err := fixture.lifecycle.Preview(context.Background(), valid)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := preview.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseDeploymentPreview(append([]byte(" "), canonical...)); err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("noncanonical preview error=%v", err)
	}
	trailing := append(append([]byte(nil), canonical...), []byte("{}")...)
	if _, err := ParseDeploymentPreview(trailing); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("trailing preview error=%v", err)
	}
	tamperedIdentity := preview
	tamperedIdentity.Release.BuildIdentity = strings.Repeat("0", 64)
	if _, err := tamperedIdentity.CanonicalBytes(); err == nil || !strings.Contains(err.Error(), "build identity") {
		t.Fatalf("tampered build identity error=%v", err)
	}
	tamperedActions := preview
	tamperedActions.Actions = append([]PreviewAction(nil), preview.Actions...)
	tamperedActions.Actions[0].Operation = "prepare_versions_directory"
	if _, err := tamperedActions.CanonicalBytes(); err == nil || !strings.Contains(err.Error(), "exact classified lifecycle plan") {
		t.Fatalf("tampered action plan error=%v", err)
	}

	duplicate := valid
	duplicate.NoticePath = duplicate.LicensePath
	if _, err := fixture.lifecycle.Preview(context.Background(), duplicate); err == nil || !strings.Contains(err.Error(), "distinct") {
		t.Fatalf("duplicate path error=%v", err)
	}
	badManifest := valid
	badManifest.ManifestPayload = append([]byte(" "), badManifest.ManifestPayload...)
	badManifest.ManifestSHA256 = SHA256Hex(badManifest.ManifestPayload)
	if _, err := fixture.lifecycle.Preview(context.Background(), badManifest); err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("malformed manifest error=%v", err)
	}
}

func requestForPreview(layout Layout, request ApplyRequest) PreviewRequest {
	return PreviewRequest{
		ManifestPath:    filepath.Join(layout.HomeDir, "verified-upload", "release-manifest.json"),
		ManifestPayload: request.ManifestPayload,
		ManifestSHA256:  request.ManifestSHA256,
		ArtifactPath:    request.ArtifactPath,
		LicensePath:     request.LicensePath,
		NoticePath:      request.NoticePath,
	}
}

func missingLayoutLifecycle(t *testing.T, request ApplyRequest) (*Lifecycle, Layout, *fakeServiceManager) {
	t.Helper()
	home := secureTestHome(t)
	layout, err := NewLayout(home, filepath.Join(home, "deployment"), filepath.Join(home, "state"))
	if err != nil {
		t.Fatal(err)
	}
	definition := filepath.Join(home, ".config", "systemd", "user", "com.kciceblue.sshserver.service")
	manager := &fakeServiceManager{
		kind: ManagerSystemd, definition: definition,
		availability: ManagerAvailability{Manager: ManagerSystemd, Available: true, ServiceDefinition: definition},
		failures:     make(map[string]int), identities: make(map[string]buildinfo.Identity),
	}
	lifecycle := newLifecycle(layout, Target{OS: "linux", Architecture: "amd64"}, manager)
	lifecycle.verifySourceArtifact = func(string, InstalledRelease) error { return nil }
	lifecycle.verifySourceReleaseFile = func(string, int64, string) error { return nil }
	lifecycle.verifyPreviewRelease = func(context.Context, InstalledRelease) error { return nil }
	return lifecycle, layout, manager
}

func assertMissingPreviewTargets(t *testing.T, layout Layout) {
	t.Helper()
	for _, path := range []string{layout.InstallRoot, layout.StateDir, layout.StatePath, layout.JournalPath, layout.LockPath} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("read-only preflight created %s: %v", path, err)
		}
	}
}

func assertPreviewSafety(t *testing.T, preview DeploymentPreview) {
	t.Helper()
	if !preview.Assertions.Data.PreserveStateDirectory || !preview.Assertions.Data.PreserveInstanceIDs ||
		!preview.Assertions.Data.PreserveDatabase || !preview.Assertions.Data.PreserveDeviceRegistry ||
		!preview.Assertions.Data.PreserveInstanceSecret || preview.Assertions.Data.DestructivePurgePlanned ||
		!preview.Assertions.Network.LoopbackOnly || preview.Assertions.Network.PublicListenerPlanned ||
		!preview.Assertions.Scope.CurrentUserOnly || preview.Assertions.Scope.SudoRequired {
		t.Fatalf("unsafe preview assertions=%+v", preview.Assertions)
	}
	for _, listener := range preview.Assertions.Network.Listeners {
		if err := config.ValidateListener(listener); err != nil {
			t.Fatalf("preview listener %q is not loopback-only: %v", listener, err)
		}
	}
}

func assertPreviewActionsContain(t *testing.T, actions []PreviewAction, operations ...string) {
	t.Helper()
	seen := make(map[string]bool, len(actions))
	for _, action := range actions {
		seen[action.Operation] = true
	}
	for _, operation := range operations {
		if !seen[operation] {
			t.Fatalf("preview actions do not contain %q: %+v", operation, actions)
		}
	}
}

func assertPreviewActionsExclude(t *testing.T, actions []PreviewAction, operations ...string) {
	t.Helper()
	for _, action := range actions {
		for _, operation := range operations {
			if action.Operation == operation {
				t.Fatalf("preview actions unexpectedly contain %q: %+v", operation, actions)
			}
		}
	}
}

func assertPreviewActionPrefix(t *testing.T, actions []PreviewAction, operations ...string) {
	t.Helper()
	if len(actions) < len(operations) {
		t.Fatalf("preview actions are shorter than prefix %v: %+v", operations, actions)
	}
	got := make([]string, len(operations))
	for index := range operations {
		got[index] = actions[index].Operation
	}
	if !reflect.DeepEqual(got, operations) {
		t.Fatalf("preview action prefix=%v want=%v actions=%+v", got, operations, actions)
	}
}

func assertPreviewAction(t *testing.T, actions []PreviewAction, operation, path string, arguments ...string) {
	t.Helper()
	for _, action := range actions {
		if action.Operation == operation {
			if action.Path != path || !reflect.DeepEqual(action.Arguments, arguments) {
				t.Fatalf("preview action %q=%+v want path=%q arguments=%v", operation, action, path, arguments)
			}
			return
		}
	}
	t.Fatalf("preview actions do not contain %q: %+v", operation, actions)
}

func assertCanonicalPreview(t *testing.T, preview DeploymentPreview) {
	t.Helper()
	first, err := preview.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	second, err := preview.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) || bytes.Count(first, []byte{'\n'}) != 1 || first[len(first)-1] != '\n' {
		t.Fatalf("preview output is not deterministic canonical one-line JSON: %q", first)
	}
	parsed, err := ParseDeploymentPreview(first)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(parsed, preview) {
		t.Fatalf("preview round trip changed model\n got=%+v\nwant=%+v", parsed, preview)
	}
}

type previewTreeEntry struct {
	Mode    os.FileMode
	Payload []byte
	Link    string
}

func snapshotPreviewTree(t *testing.T, root string) map[string]previewTreeEntry {
	t.Helper()
	snapshot := make(map[string]previewTreeEntry)
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		value := previewTreeEntry{Mode: info.Mode()}
		if info.Mode().IsRegular() {
			value.Payload, err = os.ReadFile(path)
			if err != nil {
				return err
			}
		} else if info.Mode()&os.ModeSymlink != 0 {
			value.Link, err = os.Readlink(path)
			if err != nil {
				return err
			}
		}
		snapshot[relative] = value
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func mustRemovePreviewPath(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

func removePreviewPathIfPresent(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}
