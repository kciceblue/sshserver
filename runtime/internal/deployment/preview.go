//go:build darwin || linux

package deployment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"slices"

	"golang.org/x/sys/unix"

	"github.com/kciceblue/sshserver/runtime/internal/config"
	"github.com/kciceblue/sshserver/runtime/internal/store"
)

const (
	DeploymentPreviewVersion  = "1"
	maxDeploymentPreviewBytes = 512 * 1024
)

var previewReasonPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_]{0,127}$`)

var errInstalledReleaseFilesMissing = errors.New("installed release files are missing but repairable from verified inputs")

var previewActionOperations = map[string]bool{
	"prepare_install_root": true, "prepare_versions_directory": true, "prepare_release_directory": true,
	"prepare_state_directory": true, "acquire_bootstrap_lock": true, "create_lifecycle_lock": true, "acquire_lifecycle_lock": true,
	"create_initialization_lock": true, "acquire_initialization_lock": true,
	"create_apply_journal": true, "resume_apply_journal": true, "rebind_apply_journal_inputs": true,
	"recover_existing_transaction": true, "publish_verified_artifact": true, "publish_verified_license": true,
	"publish_verified_notice": true, "checkpoint_apply_journal": true, "initialize_or_resume_loopback_instance": true,
	"stop_prior_user_service": true, "verify_prior_foreground_stopped": true, "return_supervised_foreground_command": true,
	"install_user_service_definition": true, "activate_user_service": true,
	"verify_running_release_identity_and_loopback_health": true, "defer_health_until_supervised_foreground_start": true,
	"commit_deployment_state": true, "remove_apply_journal": true, "verify_or_reuse_artifact": true,
	"verify_or_reuse_license": true, "verify_or_reuse_notice": true, "verify_installed_release_identity": true,
	"verify_user_service_active": true,
}

var previewBlockReasons = map[string]bool{
	"active_native_manager_unavailable":                             true,
	"active_service_definition_does_not_match_current_user_manager": true,
	"completed_instance_configuration_is_missing":                   true,
	"completed_instance_database_is_invalid":                        true,
	"completed_instance_secret_is_invalid":                          true,
	"different_deployment_transaction_requires_matching_recovery":   true,
	"foreground_runtime_status_is_unavailable":                      true,
	"installed_release_verification_failed":                         true,
	"installed_release_verification_failed_during_recovery":         true,
	"instance_configuration_is_invalid":                             true,
	"instance_initialization_lock_is_invalid":                       true,
	"instance_install_marker_is_invalid":                            true,
	"instance_state_directory_is_invalid":                           true,
	"partial_instance_has_unrecoverable_data_without_configuration": true,
	"resumable_instance_database_is_invalid":                        true,
	"resumable_instance_secret_is_invalid":                          true,
	"recorded_user_service_is_not_active":                           true,
	"recovery_release_verification_failed":                          true,
	"running_release_identity_does_not_match":                       true,
	"service_manager_changed_during_recovery":                       true,
	"saved_deployment_state_does_not_match_recovering_transaction":  true,
	"supervised_foreground_runtime_must_stop_before_apply":          true,
	"unknown_foreground_runtime_uses_protected_instance":            true,
}

var previewForegroundReasons = map[string]bool{
	"user_service_manager_not_installed": true,
	"user_service_manager_unavailable":   true,
}

type PreviewClassification string

const (
	PreviewFresh                    PreviewClassification = "fresh"
	PreviewIdempotent               PreviewClassification = "idempotent"
	PreviewUpgrade                  PreviewClassification = "upgrade"
	PreviewResumeOrRecoveryRequired PreviewClassification = "resume_or_recovery_required"
	PreviewBlocked                  PreviewClassification = "blocked"
)

type PreviewRequest struct {
	ManifestPath    string
	ManifestPayload []byte
	ManifestSHA256  string
	ArtifactPath    string
	LicensePath     string
	NoticePath      string
}

type previewInstanceSnapshot struct {
	state                     string
	listeners                 []string
	blockReason               string
	initializationLockPresent bool
}

type PreviewReleaseIdentity struct {
	Release         string `json:"release"`
	SourceRevision  string `json:"source_revision"`
	BuildToolchain  string `json:"build_toolchain"`
	BuildIdentity   string `json:"build_identity"`
	ProtocolVersion string `json:"protocol_version"`
	StorageSchema   string `json:"storage_schema"`
}

type PreviewTargetIdentity struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
}

type PreviewManifestIdentity struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type PreviewArtifactIdentity struct {
	SourcePath string `json:"source_path"`
	URL        string `json:"url"`
	Bytes      int64  `json:"bytes"`
	SHA256     string `json:"sha256"`
}

type PreviewSupportFileIdentity struct {
	SourcePath string `json:"source_path"`
	URL        string `json:"url"`
	Bytes      int64  `json:"bytes"`
	SHA256     string `json:"sha256"`
}

type PreviewInputs struct {
	Manifest PreviewManifestIdentity    `json:"manifest"`
	Artifact PreviewArtifactIdentity    `json:"artifact"`
	License  PreviewSupportFileIdentity `json:"license"`
	Notice   PreviewSupportFileIdentity `json:"notice"`
}

type PreviewPaths struct {
	HomeDir            string `json:"home_dir"`
	InstallRoot        string `json:"install_root"`
	VersionsDir        string `json:"versions_dir"`
	ReleaseDir         string `json:"release_dir"`
	StateDir           string `json:"state_dir"`
	BinaryPath         string `json:"binary_path"`
	LicensePath        string `json:"license_path"`
	NoticePath         string `json:"notice_path"`
	ServiceDefinition  string `json:"service_definition_path"`
	DeploymentState    string `json:"deployment_state_path"`
	DeploymentJournal  string `json:"deployment_journal_path"`
	LifecycleLock      string `json:"lifecycle_lock_path"`
	InitializationLock string `json:"initialization_lock_path"`
	AdminSocket        string `json:"admin_socket_path"`
}

type PreviewExisting struct {
	InstanceState             string             `json:"instance_state"`
	LifecycleLockPresent      bool               `json:"lifecycle_lock_present"`
	InitializationLockPresent bool               `json:"initialization_lock_present"`
	State                     *DeploymentState   `json:"state"`
	Journal                   *DeploymentJournal `json:"journal"`
}

type PreviewAction struct {
	Sequence  int      `json:"sequence"`
	Category  string   `json:"category"`
	Operation string   `json:"operation"`
	Path      string   `json:"path"`
	Arguments []string `json:"arguments"`
}

type PreviewDataAssertions struct {
	PreserveStateDirectory  bool `json:"preserve_state_directory"`
	PreserveInstanceIDs     bool `json:"preserve_instance_ids"`
	PreserveDatabase        bool `json:"preserve_database"`
	PreserveDeviceRegistry  bool `json:"preserve_device_registry"`
	PreserveInstanceSecret  bool `json:"preserve_instance_secret"`
	DestructivePurgePlanned bool `json:"destructive_purge_planned"`
}

type PreviewNetworkAssertions struct {
	LoopbackOnly          bool     `json:"loopback_only"`
	Listeners             []string `json:"listeners"`
	PublicListenerPlanned bool     `json:"public_listener_planned"`
}

type PreviewScopeAssertions struct {
	CurrentUserOnly bool `json:"current_user_only"`
	SudoRequired    bool `json:"sudo_required"`
}

type PreviewAssertions struct {
	Data    PreviewDataAssertions    `json:"data_preservation"`
	Network PreviewNetworkAssertions `json:"network"`
	Scope   PreviewScopeAssertions   `json:"scope"`
}

type DeploymentPreview struct {
	Version        string                 `json:"version"`
	Classification PreviewClassification  `json:"classification"`
	ApplyAllowed   bool                   `json:"apply_allowed"`
	BlockReason    string                 `json:"block_reason"`
	Release        PreviewReleaseIdentity `json:"release_identity"`
	Target         PreviewTargetIdentity  `json:"target_identity"`
	Inputs         PreviewInputs          `json:"inputs"`
	Paths          PreviewPaths           `json:"paths"`
	Manager        ManagerAvailability    `json:"manager"`
	Existing       PreviewExisting        `json:"existing"`
	Actions        []PreviewAction        `json:"actions"`
	Assertions     PreviewAssertions      `json:"assertions"`
}

func (lifecycle *Lifecycle) Preview(ctx context.Context, request PreviewRequest) (DeploymentPreview, error) {
	if lifecycle == nil || lifecycle.manager == nil || lifecycle.verifySourceArtifact == nil || lifecycle.verifySourceReleaseFile == nil ||
		lifecycle.verifyPreviewRelease == nil || lifecycle.probeRunning == nil {
		return DeploymentPreview{}, errors.New("deployment preview dependencies are incomplete")
	}
	manifest, desired, artifact, err := lifecycle.previewDesired(request)
	if err != nil {
		return DeploymentPreview{}, err
	}
	if err := ValidateLayoutReadOnly(lifecycle.layout); err != nil {
		return DeploymentPreview{}, err
	}
	if err := lifecycle.verifySourceArtifact(request.ArtifactPath, desired); err != nil {
		return DeploymentPreview{}, fmt.Errorf("verify preview artifact: %w", err)
	}
	if err := lifecycle.verifySourceReleaseFile(request.LicensePath, desired.LicenseBytes, desired.LicenseSHA256); err != nil {
		return DeploymentPreview{}, fmt.Errorf("verify preview LICENSE: %w", err)
	}
	if err := lifecycle.verifySourceReleaseFile(request.NoticePath, desired.NoticeBytes, desired.NoticeSHA256); err != nil {
		return DeploymentPreview{}, fmt.Errorf("verify preview NOTICE: %w", err)
	}
	previewLock, _, err := acquireDeploymentSharedLockIfPresent(lifecycle.layout)
	if err != nil {
		return DeploymentPreview{}, err
	}
	if previewLock != nil {
		return lifecycle.previewWhileLocked(ctx, request, manifest, desired, artifact, previewLock)
	}

	// A missing lifecycle lock is the valid fresh-install state, so preview must
	// not create one merely to synchronize its read. Build the tentative
	// snapshot, then recheck the no-create lock path. If first apply created the
	// lock at any point during the snapshot, discard the tentative result and
	// rebuild it while sharing that lock. If apply owns the lock, the recheck
	// fails closed. If the lock is still absent, the recheck is the snapshot's
	// linearization point: a later apply can only begin after every preview read
	// has completed.
	tentative, tentativeErr := lifecycle.previewSnapshot(ctx, request, manifest, desired, artifact, false)
	previewLock, _, err = acquireDeploymentSharedLockIfPresent(lifecycle.layout)
	if err != nil {
		return DeploymentPreview{}, err
	}
	if previewLock == nil {
		return tentative, tentativeErr
	}
	return lifecycle.previewWhileLocked(ctx, request, manifest, desired, artifact, previewLock)
}

func (lifecycle *Lifecycle) previewWhileLocked(
	ctx context.Context,
	request PreviewRequest,
	manifest ReleaseManifest,
	desired InstalledRelease,
	artifact ReleaseArtifact,
	lock *deploymentLock,
) (preview DeploymentPreview, returnErr error) {
	defer func() {
		if closeErr := lock.Close(); closeErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("release deployment preview lock: %w", closeErr))
		}
	}()
	return lifecycle.previewSnapshot(ctx, request, manifest, desired, artifact, true)
}

func (lifecycle *Lifecycle) previewSnapshot(
	ctx context.Context,
	request PreviewRequest,
	manifest ReleaseManifest,
	desired InstalledRelease,
	artifact ReleaseArtifact,
	lifecycleLockPresent bool,
) (DeploymentPreview, error) {
	return lifecycle.previewSnapshotWithInstance(ctx, request, manifest, desired, artifact, lifecycleLockPresent, nil)
}

// previewSnapshotWithInstance rebuilds the canonical plan without acquiring a
// lifecycle lock. Apply uses it while already holding the exclusive lifecycle
// and initialization locks, supplying the narrowly normalized instance state
// caused by acquiring those structural locks itself.
func (lifecycle *Lifecycle) previewSnapshotWithInstance(
	ctx context.Context,
	request PreviewRequest,
	manifest ReleaseManifest,
	desired InstalledRelease,
	artifact ReleaseArtifact,
	lifecycleLockPresent bool,
	instanceOverride *previewInstanceSnapshot,
) (DeploymentPreview, error) {
	// Repeat the read-only layout validation inside the synchronized snapshot.
	// The preliminary validation in Preview makes opening an existing lock safe;
	// this validation covers directories created by a racing first apply.
	if err := ValidateLayoutReadOnly(lifecycle.layout); err != nil {
		return DeploymentPreview{}, err
	}
	availability, err := lifecycle.manager.Detect(ctx, desired.BinaryPath, lifecycle.layout.StateDir)
	if err != nil {
		return DeploymentPreview{}, err
	}
	if err := validateManagerAvailability(lifecycle, desired, availability); err != nil {
		return DeploymentPreview{}, err
	}
	availability = cloneManagerAvailability(availability)
	if availability.ServiceDefinition != "" {
		if err := validateProspectiveServiceDefinition(lifecycle.layout, availability.ServiceDefinition); err != nil {
			return DeploymentPreview{}, err
		}
	}

	state, statePresent, err := loadPreviewState(lifecycle.layout)
	if err != nil {
		return DeploymentPreview{}, err
	}
	journal, journalPresent, err := loadPreviewJournal(lifecycle.layout)
	if err != nil {
		return DeploymentPreview{}, err
	}
	instance := previewInstanceSnapshot{}
	if instanceOverride == nil {
		instance = inspectPreviewInstance(ctx, lifecycle.layout.StateDir)
	} else {
		instance = *instanceOverride
		instance.listeners = slices.Clone(instance.listeners)
	}
	preview, err := lifecycle.basePreview(
		request, manifest, desired, artifact, availability, state, statePresent, journal, journalPresent,
		instance.state, lifecycleLockPresent, instance.initializationLockPresent, instance.listeners,
	)
	if err != nil {
		return DeploymentPreview{}, err
	}

	if journalPresent {
		if statePresent && state.Active != nil && state.Status != StatusUninstalled {
			if err := lifecycle.verifyPreviewRelease(ctx, *state.Active); err != nil {
				return finishRecoveryUnavailable(preview, "installed_release_verification_failed_during_recovery")
			}
		}
		if journal.Desired != nil && (journal.Operation == OperationRollback ||
			journal.Operation == OperationApply && applyPhaseReached(journal.Phase, PhaseArtifactStaged)) {
			if err := lifecycle.verifyPreviewRelease(ctx, *journal.Desired); err != nil {
				return finishRecoveryUnavailable(preview, "recovery_release_verification_failed")
			}
		}
		if instance.blockReason != "" {
			return finishRecoveryUnavailable(preview, instance.blockReason)
		}
		if journal.Operation == OperationApply && journal.Desired != nil && *journal.Desired == desired &&
			!applyPhaseReached(journal.Phase, PhaseArtifactStaged) {
			if err := preflightDesiredReleaseDestinations(ctx, lifecycle.layout, desired); err != nil {
				return finishRecoveryUnavailable(preview, "recovery_release_verification_failed")
			}
		}
		return lifecycle.classifyJournalPreview(ctx, preview, desired, availability, journal)
	}
	if statePresent && state.Active != nil && state.Status != StatusUninstalled {
		if err := lifecycle.verifyPreviewRelease(ctx, *state.Active); err != nil {
			matchingIdempotent := *state.Active == desired && state.Manager == availability.Manager
			if !matchingIdempotent || !errors.Is(err, errInstalledReleaseFilesMissing) {
				return lifecycle.finishBlockedPreview(preview, "installed_release_verification_failed")
			}
		}
	}
	if instance.blockReason != "" {
		return lifecycle.finishBlockedPreview(preview, instance.blockReason)
	}
	if err := preflightDesiredReleaseDestinations(ctx, lifecycle.layout, desired); err != nil {
		return lifecycle.finishBlockedPreview(preview, "installed_release_verification_failed")
	}
	return lifecycle.classifyStatePreview(ctx, preview, desired, availability, state, statePresent)
}

func (lifecycle *Lifecycle) previewDesired(request PreviewRequest) (ReleaseManifest, InstalledRelease, ReleaseArtifact, error) {
	manifest, err := ParsePinnedManifest(request.ManifestPayload, request.ManifestSHA256)
	if err != nil {
		return ReleaseManifest{}, InstalledRelease{}, ReleaseArtifact{}, err
	}
	desired, err := InstalledFromManifest(lifecycle.layout, manifest, request.ManifestSHA256, lifecycle.target)
	if err != nil {
		return ReleaseManifest{}, InstalledRelease{}, ReleaseArtifact{}, err
	}
	paths := []string{request.ManifestPath, request.ArtifactPath, request.LicensePath, request.NoticePath}
	seen := make(map[string]bool, len(paths))
	for _, path := range paths {
		if !canonicalAbsolutePath(path) {
			return ReleaseManifest{}, InstalledRelease{}, ReleaseArtifact{}, errors.New("deployment preview inputs must use canonical absolute paths")
		}
		if seen[path] {
			return ReleaseManifest{}, InstalledRelease{}, ReleaseArtifact{}, errors.New("deployment preview input paths must be distinct")
		}
		seen[path] = true
	}
	artifact, err := manifest.Artifact(lifecycle.target)
	return manifest, desired, artifact, err
}

func (lifecycle *Lifecycle) basePreview(
	request PreviewRequest,
	manifest ReleaseManifest,
	desired InstalledRelease,
	artifact ReleaseArtifact,
	availability ManagerAvailability,
	state DeploymentState,
	statePresent bool,
	journal DeploymentJournal,
	journalPresent bool,
	instanceState string,
	lifecycleLockPresent bool,
	initializationLockPresent bool,
	listeners []string,
) (DeploymentPreview, error) {
	releaseDir, err := lifecycle.layout.VersionDir(desired.Release)
	if err != nil {
		return DeploymentPreview{}, err
	}
	licensePath, err := desired.SupportFilePath(lifecycle.layout, "LICENSE")
	if err != nil {
		return DeploymentPreview{}, err
	}
	noticePath, err := desired.SupportFilePath(lifecycle.layout, "NOTICE")
	if err != nil {
		return DeploymentPreview{}, err
	}
	var statePointer *DeploymentState
	if statePresent {
		copy := state
		statePointer = &copy
	}
	var journalPointer *DeploymentJournal
	if journalPresent {
		copy := journal
		journalPointer = &copy
	}
	return DeploymentPreview{
		Version: DeploymentPreviewVersion,
		Release: PreviewReleaseIdentity{
			Release: desired.Release, SourceRevision: desired.SourceRevision, BuildToolchain: desired.BuildToolchain,
			BuildIdentity: desired.BuildIdentity, ProtocolVersion: desired.ProtocolVersion, StorageSchema: desired.StorageSchema,
		},
		Target: PreviewTargetIdentity{OS: desired.OS, Architecture: desired.Architecture},
		Inputs: PreviewInputs{
			Manifest: PreviewManifestIdentity{Path: request.ManifestPath, Bytes: int64(len(request.ManifestPayload)), SHA256: request.ManifestSHA256},
			Artifact: PreviewArtifactIdentity{SourcePath: request.ArtifactPath, URL: artifact.URL, Bytes: artifact.Bytes, SHA256: artifact.SHA256},
			License:  PreviewSupportFileIdentity{SourcePath: request.LicensePath, URL: manifest.ReleaseFiles[0].URL, Bytes: manifest.ReleaseFiles[0].Bytes, SHA256: manifest.ReleaseFiles[0].SHA256},
			Notice:   PreviewSupportFileIdentity{SourcePath: request.NoticePath, URL: manifest.ReleaseFiles[1].URL, Bytes: manifest.ReleaseFiles[1].Bytes, SHA256: manifest.ReleaseFiles[1].SHA256},
		},
		Paths: PreviewPaths{
			HomeDir: lifecycle.layout.HomeDir, InstallRoot: lifecycle.layout.InstallRoot, VersionsDir: lifecycle.layout.VersionsDir,
			ReleaseDir: releaseDir, StateDir: lifecycle.layout.StateDir, BinaryPath: desired.BinaryPath, LicensePath: licensePath,
			NoticePath: noticePath, ServiceDefinition: availability.ServiceDefinition, DeploymentState: lifecycle.layout.StatePath,
			DeploymentJournal: lifecycle.layout.JournalPath, LifecycleLock: lifecycle.layout.LockPath,
			InitializationLock: filepath.Join(lifecycle.layout.StateDir, ".instance.lock"),
			AdminSocket:        config.ForStateDir(lifecycle.layout.StateDir).AdminSocket,
		},
		Manager: availability,
		Existing: PreviewExisting{
			InstanceState: instanceState, LifecycleLockPresent: lifecycleLockPresent,
			InitializationLockPresent: initializationLockPresent,
			State:                     statePointer, Journal: journalPointer,
		},
		Actions: []PreviewAction{},
		Assertions: PreviewAssertions{
			Data: PreviewDataAssertions{
				PreserveStateDirectory: true, PreserveInstanceIDs: true, PreserveDatabase: true,
				PreserveDeviceRegistry: true, PreserveInstanceSecret: true, DestructivePurgePlanned: false,
			},
			Network: PreviewNetworkAssertions{LoopbackOnly: true, Listeners: listeners, PublicListenerPlanned: false},
			Scope:   PreviewScopeAssertions{CurrentUserOnly: true, SudoRequired: false},
		},
	}, nil
}

func (lifecycle *Lifecycle) classifyJournalPreview(ctx context.Context, preview DeploymentPreview, desired InstalledRelease, availability ManagerAvailability, journal DeploymentJournal) (DeploymentPreview, error) {
	preview.Classification = PreviewResumeOrRecoveryRequired
	if journal.Operation != OperationApply || journal.Desired == nil || *journal.Desired != desired {
		preview.ApplyAllowed = false
		preview.BlockReason = "different_deployment_transaction_requires_matching_recovery"
		preview.Actions = previewRecoveryActions(preview, journal)
		return finishPreview(preview)
	}
	if !managerMatchesJournal(availability, journal) {
		preview.ApplyAllowed = false
		preview.BlockReason = "service_manager_changed_during_recovery"
		preview.Actions = []PreviewAction{}
		return finishPreview(preview)
	}
	if err := lifecycle.verifyRecordedReleaseForApply(ctx, journal.PriorState, desired); err != nil {
		return finishRecoveryUnavailable(preview, "installed_release_verification_failed_during_recovery")
	}
	if journal.Phase == PhaseStateSaved {
		if preview.Existing.State == nil || lifecycle.validateCommittedStateValue(journal, *preview.Existing.State) != nil {
			return finishRecoveryUnavailable(preview, "saved_deployment_state_does_not_match_recovering_transaction")
		}
	}
	if journal.PriorState != nil && journal.PriorState.Status == StatusForeground &&
		!applyPhaseReached(journal.Phase, PhasePriorServiceStopped) {
		if reason := lifecycle.foregroundRuntimePreviewBlockReason(ctx, journal.PriorState); reason != "" {
			return finishRecoveryUnavailable(preview, reason)
		}
	}
	preview.ApplyAllowed = true
	preview.Actions = previewApplyActions(preview, journal.PriorState, &journal)
	return finishPreview(preview)
}

func (lifecycle *Lifecycle) classifyStatePreview(ctx context.Context, preview DeploymentPreview, desired InstalledRelease, availability ManagerAvailability, state DeploymentState, statePresent bool) (DeploymentPreview, error) {
	if statePresent {
		if err := lifecycle.verifyRetainedRollbackReleaseForApply(ctx, &state, desired); err != nil {
			return lifecycle.finishBlockedPreview(preview, "installed_release_verification_failed")
		}
	}
	if !statePresent || state.Status == StatusUninstalled {
		preview.Classification = PreviewFresh
		preview.ApplyAllowed = true
		preview.Actions = previewApplyActions(preview, nil, nil)
		return finishPreview(preview)
	}
	if state.Status == StatusActive && !availability.Available {
		return lifecycle.finishBlockedPreview(preview, "active_native_manager_unavailable")
	}
	if state.Status == StatusActive && (state.Manager != lifecycle.manager.Kind() || state.ServiceDefinition != lifecycle.manager.DefinitionPath()) {
		return lifecycle.finishBlockedPreview(preview, "active_service_definition_does_not_match_current_user_manager")
	}
	if state.Active != nil && *state.Active == desired && state.Manager == availability.Manager {
		preview.Classification = PreviewIdempotent
		if state.Status == StatusActive {
			active, err := lifecycle.manager.IsActive(ctx)
			if err != nil || !active {
				return lifecycle.finishBlockedPreview(preview, "recorded_user_service_is_not_active")
			}
			identity, err := lifecycle.probeRunning(ctx, lifecycle.layout.StateDir)
			if err != nil || ValidateReleaseIdentity(identity, desired) != nil {
				return lifecycle.finishBlockedPreview(preview, "running_release_identity_does_not_match")
			}
		}
		preview.ApplyAllowed = true
		preview.Actions = previewIdempotentActions(preview, state)
		return finishPreview(preview)
	}
	if state.Status == StatusForeground {
		if reason := lifecycle.foregroundRuntimePreviewBlockReason(ctx, &state); reason != "" {
			return lifecycle.finishBlockedPreview(preview, reason)
		}
	}
	preview.Classification = PreviewUpgrade
	preview.ApplyAllowed = true
	prior := state
	preview.Actions = previewApplyActions(preview, &prior, nil)
	return finishPreview(preview)
}

func (lifecycle *Lifecycle) foregroundRuntimePreviewBlockReason(ctx context.Context, state *DeploymentState) string {
	identity, err := lifecycle.probeRunning(ctx, lifecycle.layout.StateDir)
	if err == nil {
		if state == nil || state.Active == nil || ValidateReleaseIdentity(identity, *state.Active) != nil {
			return "unknown_foreground_runtime_uses_protected_instance"
		}
		return "supervised_foreground_runtime_must_stop_before_apply"
	}
	if !errors.Is(err, ErrRuntimeUnavailable) {
		return "foreground_runtime_status_is_unavailable"
	}
	return ""
}

func (lifecycle *Lifecycle) finishBlockedPreview(preview DeploymentPreview, reason string) (DeploymentPreview, error) {
	preview.Classification = PreviewBlocked
	preview.ApplyAllowed = false
	preview.BlockReason = reason
	preview.Actions = []PreviewAction{}
	return finishPreview(preview)
}

func finishRecoveryUnavailable(preview DeploymentPreview, reason string) (DeploymentPreview, error) {
	preview.Classification = PreviewResumeOrRecoveryRequired
	preview.ApplyAllowed = false
	preview.BlockReason = reason
	preview.Actions = []PreviewAction{}
	return finishPreview(preview)
}

func finishPreview(preview DeploymentPreview) (DeploymentPreview, error) {
	if err := preview.Validate(); err != nil {
		return DeploymentPreview{}, err
	}
	return preview, nil
}

func previewApplyActions(preview DeploymentPreview, prior *DeploymentState, journal *DeploymentJournal) []PreviewAction {
	actions := make([]PreviewAction, 0, 32)
	appendAction := func(category, operation, path string, arguments ...string) {
		actions = append(actions, PreviewAction{Sequence: len(actions) + 1, Category: category, Operation: operation, Path: path, Arguments: append([]string{}, arguments...)})
	}
	appendPreviewApplyPreparation(preview, appendAction)
	if journal == nil {
		appendAction("state", "create_apply_journal", preview.Paths.DeploymentJournal, string(PhasePlanned))
	} else {
		appendAction("state", "resume_apply_journal", preview.Paths.DeploymentJournal, journal.TransactionID, string(journal.Phase))
		if journal.Phase == PhasePlanned &&
			(journal.SourcePath != preview.Inputs.Artifact.SourcePath ||
				journal.LicenseSourcePath != preview.Inputs.License.SourcePath ||
				journal.NoticeSourcePath != preview.Inputs.Notice.SourcePath) {
			appendAction(
				"state", "rebind_apply_journal_inputs", preview.Paths.DeploymentJournal,
				preview.Inputs.Artifact.SourcePath, preview.Inputs.License.SourcePath, preview.Inputs.Notice.SourcePath,
			)
		}
		prior = journal.PriorState
	}
	phase := Phase("")
	if journal != nil {
		phase = journal.Phase
	}
	if journal == nil || !applyPhaseReached(phase, PhaseArtifactStaged) {
		appendAction("filesystem", "prepare_release_directory", preview.Paths.ReleaseDir)
		appendAction("filesystem", "publish_verified_artifact", preview.Paths.BinaryPath, preview.Inputs.Artifact.SourcePath)
		appendAction("filesystem", "publish_verified_license", preview.Paths.LicensePath, preview.Inputs.License.SourcePath)
		appendAction("filesystem", "publish_verified_notice", preview.Paths.NoticePath, preview.Inputs.Notice.SourcePath)
		appendAction("state", "checkpoint_apply_journal", preview.Paths.DeploymentJournal, string(PhaseArtifactStaged))
	}
	if journal == nil || !applyPhaseReached(phase, PhaseInstanceReady) {
		appendAction("init", "initialize_or_resume_loopback_instance", preview.Paths.StateDir, preview.Assertions.Network.Listeners...)
		appendAction("state", "checkpoint_apply_journal", preview.Paths.DeploymentJournal, string(PhaseInstanceReady))
	}
	if journal == nil || !applyPhaseReached(phase, PhasePriorServiceStopped) {
		if prior != nil && prior.Status == StatusActive {
			appendAction("service", "stop_prior_user_service", prior.ServiceDefinition, string(prior.Manager))
		} else if prior != nil && prior.Status == StatusForeground {
			appendAction("service", "verify_prior_foreground_stopped", preview.Paths.AdminSocket)
		}
		appendAction("state", "checkpoint_apply_journal", preview.Paths.DeploymentJournal, string(PhasePriorServiceStopped))
	}
	if journal == nil || !applyPhaseReached(phase, PhaseDefinitionInstalled) {
		if preview.Manager.Manager == ManagerForeground {
			appendAction("service", "return_supervised_foreground_command", "", preview.Manager.Foreground.Command...)
		} else {
			appendAction("service", "install_user_service_definition", preview.Paths.ServiceDefinition, string(preview.Manager.Manager), preview.Paths.BinaryPath, preview.Paths.StateDir)
		}
		appendAction("state", "checkpoint_apply_journal", preview.Paths.DeploymentJournal, string(PhaseDefinitionInstalled))
	}
	if preview.Manager.Manager != ManagerForeground {
		if journal == nil || !applyPhaseReached(phase, PhaseActivated) {
			appendAction("service", "activate_user_service", preview.Paths.ServiceDefinition, string(preview.Manager.Manager))
			appendAction("state", "checkpoint_apply_journal", preview.Paths.DeploymentJournal, string(PhaseActivated))
		}
		if journal == nil || !applyPhaseReached(phase, PhaseHealthVerified) {
			appendAction("health", "verify_running_release_identity_and_loopback_health", preview.Paths.AdminSocket, preview.Release.BuildIdentity)
			appendAction("state", "checkpoint_apply_journal", preview.Paths.DeploymentJournal, string(PhaseHealthVerified))
		}
	} else {
		appendAction("health", "defer_health_until_supervised_foreground_start", preview.Paths.AdminSocket)
	}
	if journal == nil || !applyPhaseReached(phase, PhaseCommitting) {
		appendAction("state", "checkpoint_apply_journal", preview.Paths.DeploymentJournal, string(PhaseCommitting))
	}
	if journal == nil || !applyPhaseReached(phase, PhaseStateSaved) {
		appendAction("state", "commit_deployment_state", preview.Paths.DeploymentState, preview.Release.Release, string(preview.Manager.Manager))
		appendAction("state", "checkpoint_apply_journal", preview.Paths.DeploymentJournal, string(PhaseStateSaved))
	}
	appendAction("state", "remove_apply_journal", preview.Paths.DeploymentJournal)
	return actions
}

func previewIdempotentActions(preview DeploymentPreview, state DeploymentState) []PreviewAction {
	actions := make([]PreviewAction, 0, 11)
	appendAction := func(category, operation, path string, arguments ...string) {
		actions = append(actions, PreviewAction{Sequence: len(actions) + 1, Category: category, Operation: operation, Path: path, Arguments: append([]string{}, arguments...)})
	}
	appendPreviewApplyPreparation(preview, appendAction)
	appendAction("filesystem", "prepare_release_directory", preview.Paths.ReleaseDir)
	appendAction("filesystem", "verify_or_reuse_artifact", preview.Paths.BinaryPath, preview.Inputs.Artifact.SourcePath)
	appendAction("filesystem", "verify_or_reuse_license", preview.Paths.LicensePath, preview.Inputs.License.SourcePath)
	appendAction("filesystem", "verify_or_reuse_notice", preview.Paths.NoticePath, preview.Inputs.Notice.SourcePath)
	appendAction("health", "verify_installed_release_identity", preview.Paths.BinaryPath, preview.Release.BuildIdentity)
	if state.Status == StatusActive {
		appendAction("service", "verify_user_service_active", state.ServiceDefinition, string(state.Manager))
		appendAction("health", "verify_running_release_identity_and_loopback_health", preview.Paths.AdminSocket, preview.Release.BuildIdentity)
	}
	return actions
}

func appendPreviewApplyPreparation(
	preview DeploymentPreview,
	appendAction func(category, operation, path string, arguments ...string),
) {
	appendPreviewMutationAdmission(preview, appendAction)

	// Under the lifecycle lock, Apply prepares only the state directory needed
	// for its initialization lease, then acquires that lease before rebuilding
	// the confirmed plan. Full layout preparation follows both locks.
	appendAction("filesystem", "prepare_state_directory", preview.Paths.StateDir)
	for _, operation := range previewInitializationLockOperations(preview) {
		appendAction("state", operation, preview.Paths.InitializationLock)
	}
	appendPreviewLayoutPreparation(preview, appendAction)
}

func appendPreviewMutationAdmission(
	preview DeploymentPreview,
	appendAction func(category, operation, path string, arguments ...string),
) {
	// Every lifecycle mutation takes the existing home directory as its
	// nonpersistent first-operation admission lock. A missing lifecycle lock
	// requires the install root before that lock can be created; an existing
	// lock does not.
	appendAction("state", "acquire_bootstrap_lock", preview.Paths.HomeDir)
	if !preview.Existing.LifecycleLockPresent {
		appendAction("filesystem", "prepare_install_root", preview.Paths.InstallRoot)
	}
	for _, operation := range previewLifecycleLockOperations(preview) {
		appendAction("state", operation, preview.Paths.LifecycleLock)
	}
}

func appendPreviewLayoutPreparation(
	preview DeploymentPreview,
	appendAction func(category, operation, path string, arguments ...string),
) {
	appendAction("filesystem", "prepare_install_root", preview.Paths.InstallRoot)
	appendAction("filesystem", "prepare_versions_directory", preview.Paths.VersionsDir)
	appendAction("filesystem", "prepare_state_directory", preview.Paths.StateDir)
}

func previewLifecycleLockOperations(preview DeploymentPreview) []string {
	if preview.Existing.LifecycleLockPresent {
		return []string{"acquire_lifecycle_lock"}
	}
	return []string{"create_lifecycle_lock", "acquire_lifecycle_lock"}
}

func previewInitializationLockOperations(preview DeploymentPreview) []string {
	if preview.Existing.InitializationLockPresent {
		return []string{"acquire_initialization_lock"}
	}
	return []string{"create_initialization_lock", "acquire_initialization_lock"}
}

func previewRecoveryActions(preview DeploymentPreview, journal DeploymentJournal) []PreviewAction {
	actions := make([]PreviewAction, 0, 9)
	appendAction := func(category, operation, path string, arguments ...string) {
		actions = append(actions, PreviewAction{
			Sequence: len(actions) + 1, Category: category, Operation: operation,
			Path: path, Arguments: append([]string{}, arguments...),
		})
	}
	if journal.Operation == OperationApply {
		appendPreviewApplyPreparation(preview, appendAction)
	} else {
		// Rollback and uninstall acquire the common bootstrap/lifecycle locks and
		// then run PrepareLayout before loading and resuming their journal.
		appendPreviewMutationAdmission(preview, appendAction)
		appendPreviewLayoutPreparation(preview, appendAction)
	}
	appendAction("state", "recover_existing_transaction", preview.Paths.DeploymentJournal, string(journal.Operation), string(journal.Phase))
	return actions
}

func installedReleaseFromPreview(preview DeploymentPreview) InstalledRelease {
	return InstalledRelease{
		Release:         preview.Release.Release,
		SourceRevision:  preview.Release.SourceRevision,
		BuildToolchain:  preview.Release.BuildToolchain,
		BuildIdentity:   preview.Release.BuildIdentity,
		ManifestSHA256:  preview.Inputs.Manifest.SHA256,
		ProtocolVersion: preview.Release.ProtocolVersion,
		StorageSchema:   preview.Release.StorageSchema,
		OS:              preview.Target.OS,
		Architecture:    preview.Target.Architecture,
		BinaryPath:      preview.Paths.BinaryPath,
		BinaryBytes:     preview.Inputs.Artifact.Bytes,
		BinarySHA256:    preview.Inputs.Artifact.SHA256,
		LicenseBytes:    preview.Inputs.License.Bytes,
		LicenseSHA256:   preview.Inputs.License.SHA256,
		NoticeBytes:     preview.Inputs.Notice.Bytes,
		NoticeSHA256:    preview.Inputs.Notice.SHA256,
	}
}

func expectedPreviewActions(preview DeploymentPreview) ([]PreviewAction, error) {
	switch preview.Classification {
	case PreviewFresh:
		return previewApplyActions(preview, nil, nil), nil
	case PreviewIdempotent:
		if preview.Existing.State == nil {
			return nil, errors.New("idempotent deployment preview has no state")
		}
		return previewIdempotentActions(preview, *preview.Existing.State), nil
	case PreviewUpgrade:
		if preview.Existing.State == nil {
			return nil, errors.New("upgrade deployment preview has no state")
		}
		return previewApplyActions(preview, preview.Existing.State, nil), nil
	case PreviewResumeOrRecoveryRequired:
		if preview.Existing.Journal == nil {
			return nil, errors.New("deployment recovery preview has no journal")
		}
		if preview.ApplyAllowed {
			return previewApplyActions(preview, preview.Existing.Journal.PriorState, preview.Existing.Journal), nil
		}
		if preview.BlockReason == "different_deployment_transaction_requires_matching_recovery" {
			return previewRecoveryActions(preview, *preview.Existing.Journal), nil
		}
		return []PreviewAction{}, nil
	case PreviewBlocked:
		return []PreviewAction{}, nil
	default:
		return nil, errors.New("deployment preview classification is invalid")
	}
}

func equalPreviewActions(first, second []PreviewAction) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index].Sequence != second[index].Sequence || first[index].Category != second[index].Category ||
			first[index].Operation != second[index].Operation || first[index].Path != second[index].Path ||
			!slices.Equal(first[index].Arguments, second[index].Arguments) {
			return false
		}
	}
	return true
}

func loadPreviewState(layout Layout) (DeploymentState, bool, error) {
	state, err := LoadState(layout)
	if errors.Is(err, ErrNoDeploymentState) {
		return DeploymentState{}, false, nil
	}
	return state, err == nil, err
}

func loadPreviewJournal(layout Layout) (DeploymentJournal, bool, error) {
	journal, err := LoadJournal(layout)
	if errors.Is(err, ErrNoDeploymentJournal) {
		return DeploymentJournal{}, false, nil
	}
	return journal, err == nil, err
}

func inspectPreviewInstance(ctx context.Context, stateDir string) previewInstanceSnapshot {
	listeners := config.DefaultListeners()
	slices.Sort(listeners)
	info, err := os.Lstat(stateDir)
	if errors.Is(err, os.ErrNotExist) {
		return previewInstanceSnapshot{state: "missing", listeners: listeners}
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || config.ValidateStateDirectory(stateDir) != nil {
		return previewInstanceSnapshot{state: "invalid", listeners: listeners, blockReason: "instance_state_directory_is_invalid"}
	}
	initializationLockPresent := false
	initializationLockPath := filepath.Join(stateDir, ".instance.lock")
	if err := config.ValidateProtectedFile(initializationLockPath, 0o600); err == nil {
		initializationLockPresent = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return previewInstanceSnapshot{state: "invalid", listeners: listeners, blockReason: "instance_initialization_lock_is_invalid"}
	}
	result := func(state, blockReason string) previewInstanceSnapshot {
		return previewInstanceSnapshot{
			state: state, listeners: listeners, blockReason: blockReason,
			initializationLockPresent: initializationLockPresent,
		}
	}
	paths := config.ForStateDir(stateDir)
	marker, markerErr := config.LoadMarker(paths.InstallMarker)
	settings, settingsErr := config.LoadSettings(paths.Config)
	if settingsErr == nil {
		listeners = slices.Clone(settings.Listeners)
		slices.Sort(listeners)
	} else if !errors.Is(settingsErr, config.ErrUninitialized) {
		return result("invalid", "instance_configuration_is_invalid")
	}
	if markerErr == nil {
		if marker.Phase == "ready" {
			if settingsErr != nil {
				return result("invalid", "completed_instance_configuration_is_missing")
			}
			secret, err := config.ReadSecret(paths.InstanceSecret)
			if err != nil {
				return result("invalid", "completed_instance_secret_is_invalid")
			}
			clear(secret)
			for _, databasePath := range []string{paths.Database, paths.Database + "-wal", paths.Database + "-shm", paths.Database + "-journal"} {
				if err := config.ValidateProtectedFile(databasePath, 0o600); err != nil &&
					(databasePath == paths.Database || !errors.Is(err, os.ErrNotExist)) {
					return result("invalid", "completed_instance_database_is_invalid")
				}
			}
			if err := store.ValidateExisting(ctx, paths.Database, store.Identity{
				InstanceID: settings.InstanceID,
				VaultID:    settings.VaultID,
			}); err != nil {
				return result("invalid", "completed_instance_database_is_invalid")
			}
			return result("ready", "")
		}
		if settingsErr != nil && partialInstanceDataExists(paths) {
			return result("invalid", "partial_instance_has_unrecoverable_data_without_configuration")
		}
		if settingsErr == nil {
			if blockReason := validateResumableInstanceFiles(ctx, paths, settings); blockReason != "" {
				return result("invalid", blockReason)
			}
		}
		return result("initializing", "")
	}
	if !errors.Is(markerErr, os.ErrNotExist) {
		return result("invalid", "instance_install_marker_is_invalid")
	}
	if settingsErr != nil && partialInstanceDataExists(paths) {
		return result("invalid", "partial_instance_has_unrecoverable_data_without_configuration")
	}
	if settingsErr == nil {
		if blockReason := validateResumableInstanceFiles(ctx, paths, settings); blockReason != "" {
			return result("invalid", blockReason)
		}
		return result("resume", "")
	}
	return result("uninitialized", "")
}

func pathExists(path string) bool {
	_, err := os.Lstat(path)
	return !errors.Is(err, os.ErrNotExist)
}

func partialInstanceDataExists(paths config.Paths) bool {
	for _, path := range []string{
		paths.InstanceSecret,
		paths.Database,
		paths.Database + "-wal",
		paths.Database + "-shm",
		paths.Database + "-journal",
	} {
		if pathExists(path) {
			return true
		}
	}
	return false
}

func validateResumableInstanceFiles(ctx context.Context, paths config.Paths, settings config.Settings) string {
	secret, err := config.ReadSecret(paths.InstanceSecret)
	if err == nil {
		clear(secret)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "resumable_instance_secret_is_invalid"
	}
	databasePaths := []string{paths.Database, paths.Database + "-wal", paths.Database + "-shm", paths.Database + "-journal"}
	for _, databasePath := range databasePaths {
		if err := config.ValidateProtectedFile(databasePath, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
			return "resumable_instance_database_is_invalid"
		}
	}
	if !pathExists(paths.Database) {
		for _, sidecar := range databasePaths[1:] {
			if pathExists(sidecar) {
				return "resumable_instance_database_is_invalid"
			}
		}
		return ""
	}
	if err := store.ValidateExisting(ctx, paths.Database, store.Identity{
		InstanceID: settings.InstanceID,
		VaultID:    settings.VaultID,
	}); err != nil {
		return "resumable_instance_database_is_invalid"
	}
	return ""
}

func preflightDesiredReleaseDestinations(ctx context.Context, layout Layout, desired InstalledRelease) error {
	err := verifyInstalledReleaseForPreview(ctx, layout, desired)
	if errors.Is(err, errInstalledReleaseFilesMissing) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("preflight desired release destinations: %w", err)
	}
	return nil
}

func verifyInstalledReleaseForPreview(_ context.Context, layout Layout, desired InstalledRelease) error {
	releaseDir, err := layout.VersionDir(desired.Release)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(releaseDir); errors.Is(err, os.ErrNotExist) {
		return errInstalledReleaseFilesMissing
	} else if err != nil {
		return err
	}
	verifiedReleaseDir, err := openVerifiedDirectory(releaseDir, true)
	if err != nil {
		return fmt.Errorf("validate installed release directory: %w", err)
	}
	if err := verifiedReleaseDir.Close(); err != nil {
		return fmt.Errorf("close installed release directory: %w", err)
	}

	missing := false
	binaryMissing, err := verifyPreviewInstalledPath(desired.BinaryPath, func() error {
		if err := VerifyStagedArtifact(desired.BinaryPath, desired.BinaryBytes, desired.BinarySHA256); err != nil {
			return err
		}
		return VerifyArtifactSource(desired.BinaryPath, desired)
	})
	if err != nil {
		return err
	}
	missing = missing || binaryMissing
	licensePath, err := desired.SupportFilePath(layout, "LICENSE")
	if err != nil {
		return err
	}
	licenseMissing, err := verifyPreviewInstalledPath(licensePath, func() error {
		return VerifyStagedReleaseFile(licensePath, desired.LicenseBytes, desired.LicenseSHA256)
	})
	if err != nil {
		return err
	}
	missing = missing || licenseMissing
	noticePath, err := desired.SupportFilePath(layout, "NOTICE")
	if err != nil {
		return err
	}
	noticeMissing, err := verifyPreviewInstalledPath(noticePath, func() error {
		return VerifyStagedReleaseFile(noticePath, desired.NoticeBytes, desired.NoticeSHA256)
	})
	if err != nil {
		return err
	}
	missing = missing || noticeMissing
	if missing {
		return errInstalledReleaseFilesMissing
	}
	return nil
}

func verifyPreviewInstalledPath(path string, verify func() error) (bool, error) {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return true, nil
	} else if err != nil {
		return false, err
	}
	return false, verify()
}

func validateManagerAvailability(lifecycle *Lifecycle, desired InstalledRelease, availability ManagerAvailability) error {
	if availability.Available {
		if availability.Manager != lifecycle.manager.Kind() || availability.ServiceDefinition != lifecycle.manager.DefinitionPath() || availability.Foreground != nil {
			return errors.New("service-manager probe returned an inconsistent native-user outcome")
		}
		if (availability.Manager == ManagerSystemd) != (desired.OS == "linux") || (availability.Manager == ManagerLaunchd) != (desired.OS == "darwin") {
			return errors.New("service-manager outcome does not match the deployment target")
		}
		return nil
	}
	if availability.Manager != ManagerForeground || availability.ServiceDefinition != "" || availability.Foreground == nil ||
		!availability.Foreground.Required || !availability.Foreground.Supervised || availability.Foreground.Reason == "" ||
		!slices.Equal(availability.Foreground.Command, []string{desired.BinaryPath, "serve", "--state-dir", lifecycle.layout.StateDir}) {
		return errors.New("service-manager probe returned an invalid foreground outcome")
	}
	return nil
}

func cloneManagerAvailability(value ManagerAvailability) ManagerAvailability {
	if value.Foreground != nil {
		copy := *value.Foreground
		copy.Command = slices.Clone(copy.Command)
		value.Foreground = &copy
	}
	return value
}

func sameManagerAvailability(first, second ManagerAvailability) bool {
	if first.Manager != second.Manager || first.Available != second.Available || first.ServiceDefinition != second.ServiceDefinition {
		return false
	}
	if first.Foreground == nil || second.Foreground == nil {
		return first.Foreground == nil && second.Foreground == nil
	}
	return first.Foreground.Required == second.Foreground.Required && first.Foreground.Reason == second.Foreground.Reason &&
		first.Foreground.Supervised == second.Foreground.Supervised && slices.Equal(first.Foreground.Command, second.Foreground.Command)
}

func managerMatchesJournal(availability ManagerAvailability, journal DeploymentJournal) bool {
	return availability.Manager == journal.Manager && availability.ServiceDefinition == journal.ServiceDefinition
}

func validateProspectiveServiceDefinition(layout Layout, path string) error {
	if !canonicalAbsolutePath(path) {
		return errors.New("service definition path is not canonical and absolute")
	}
	if err := requireStrictDescendant(layout.HomeDir, path, "service definition"); err != nil {
		return err
	}
	homeFD, err := openSecureDirectory(layout.HomeDir)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(homeFD) }()
	relative, err := filepath.Rel(layout.HomeDir, filepath.Dir(path))
	if err != nil {
		return err
	}
	if err := validateExistingDirectoryBelow(homeFD, relative); err != nil {
		return err
	}
	if err := config.ValidateProtectedFile(path, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("validate existing service definition: %w", err)
	}
	return nil
}

func (preview DeploymentPreview) Validate() error {
	if preview.Version != DeploymentPreviewVersion {
		return errors.New("deployment preview version is invalid")
	}
	switch preview.Classification {
	case PreviewFresh, PreviewIdempotent, PreviewUpgrade:
		if !preview.ApplyAllowed || preview.BlockReason != "" {
			return errors.New("applicable deployment preview classification is inconsistent")
		}
	case PreviewResumeOrRecoveryRequired:
		if preview.ApplyAllowed == (preview.BlockReason != "") {
			return errors.New("deployment recovery preview applicability is inconsistent")
		}
	case PreviewBlocked:
		if preview.ApplyAllowed || preview.BlockReason == "" || len(preview.Actions) != 0 {
			return errors.New("blocked deployment preview is inconsistent")
		}
	default:
		return errors.New("deployment preview classification is invalid")
	}
	if preview.BlockReason != "" && (!previewReasonPattern.MatchString(preview.BlockReason) || !previewBlockReasons[preview.BlockReason]) {
		return errors.New("deployment preview block reason is invalid")
	}
	if (preview.Classification == PreviewResumeOrRecoveryRequired) != (preview.Existing.Journal != nil) {
		return errors.New("deployment preview recovery classification does not match its journal")
	}
	if preview.Classification == PreviewFresh && preview.Existing.State != nil && preview.Existing.State.Status != StatusUninstalled {
		return errors.New("fresh deployment preview has an installed state")
	}
	if (preview.Classification == PreviewIdempotent || preview.Classification == PreviewUpgrade) &&
		(preview.Existing.State == nil || preview.Existing.State.Status == StatusUninstalled) {
		return errors.New("existing deployment preview classification has no installed state")
	}
	layout, err := NewLayout(preview.Paths.HomeDir, preview.Paths.InstallRoot, preview.Paths.StateDir)
	if err != nil || layout.VersionsDir != preview.Paths.VersionsDir || layout.StatePath != preview.Paths.DeploymentState ||
		layout.JournalPath != preview.Paths.DeploymentJournal || layout.LockPath != preview.Paths.LifecycleLock {
		return errors.New("deployment preview paths do not form one canonical layout")
	}
	target := Target{OS: preview.Target.OS, Architecture: preview.Target.Architecture}
	if !isSupportedTarget(target) {
		return errors.New("deployment preview target is unsupported")
	}
	if !releaseIDPattern.MatchString(preview.Release.Release) || !sourceRevisionPattern.MatchString(preview.Release.SourceRevision) ||
		!toolchainPattern.MatchString(preview.Release.BuildToolchain) || !hexDigestPattern.MatchString(preview.Release.BuildIdentity) ||
		preview.Release.ProtocolVersion != "1" || preview.Release.StorageSchema != "1" {
		return errors.New("deployment preview release identity is invalid")
	}
	wantBuildIdentity, err := DeriveBuildIdentity(
		preview.Release.Release,
		preview.Release.SourceRevision,
		preview.Release.BuildToolchain,
		target,
	)
	if err != nil || preview.Release.BuildIdentity != wantBuildIdentity {
		return errors.New("deployment preview build identity does not match its release and target")
	}
	binaryPath, err := layout.BinaryPath(preview.Release.Release, target)
	if err != nil || binaryPath != preview.Paths.BinaryPath {
		return errors.New("deployment preview binary path is invalid")
	}
	releaseDir, _ := layout.VersionDir(preview.Release.Release)
	if preview.Paths.ReleaseDir != releaseDir || preview.Paths.LicensePath != filepath.Join(releaseDir, "LICENSE") ||
		preview.Paths.NoticePath != filepath.Join(releaseDir, "NOTICE") ||
		preview.Paths.InitializationLock != filepath.Join(layout.StateDir, ".instance.lock") ||
		preview.Paths.AdminSocket != config.ForStateDir(layout.StateDir).AdminSocket {
		return errors.New("deployment preview derived paths are invalid")
	}
	for _, path := range []string{preview.Inputs.Manifest.Path, preview.Inputs.Artifact.SourcePath, preview.Inputs.License.SourcePath, preview.Inputs.Notice.SourcePath} {
		if !canonicalAbsolutePath(path) {
			return errors.New("deployment preview input path is invalid")
		}
	}
	seenInputs := make(map[string]bool, 4)
	for _, path := range []string{preview.Inputs.Manifest.Path, preview.Inputs.Artifact.SourcePath, preview.Inputs.License.SourcePath, preview.Inputs.Notice.SourcePath} {
		if seenInputs[path] {
			return errors.New("deployment preview input paths are not distinct")
		}
		seenInputs[path] = true
	}
	if preview.Inputs.Manifest.Bytes <= 0 || preview.Inputs.Manifest.Bytes > maxManifestBytes || !hexDigestPattern.MatchString(preview.Inputs.Manifest.SHA256) ||
		preview.Inputs.Artifact.Bytes <= 0 || preview.Inputs.Artifact.Bytes > maxArtifactBytes || !hexDigestPattern.MatchString(preview.Inputs.Artifact.SHA256) ||
		preview.Inputs.License.Bytes <= 0 || preview.Inputs.License.Bytes > maxReleaseFileBytes || !hexDigestPattern.MatchString(preview.Inputs.License.SHA256) ||
		preview.Inputs.Notice.Bytes <= 0 || preview.Inputs.Notice.Bytes > maxReleaseFileBytes || !hexDigestPattern.MatchString(preview.Inputs.Notice.SHA256) {
		return errors.New("deployment preview input identity is invalid")
	}
	desired := installedReleaseFromPreview(preview)
	if err := desired.validate(layout); err != nil {
		return fmt.Errorf("deployment preview desired release is invalid: %w", err)
	}
	if err := validatePreviewURLs(preview); err != nil {
		return err
	}
	if preview.Manager.Manager == ManagerForeground {
		if err := validateForegroundPreview(preview); err != nil {
			return err
		}
	} else {
		wantManager := ManagerSystemd
		if target.OS == "darwin" {
			wantManager = ManagerLaunchd
		}
		if preview.Manager.Manager != wantManager || !preview.Manager.Available || preview.Manager.Foreground != nil ||
			preview.Manager.ServiceDefinition == "" || preview.Manager.ServiceDefinition != preview.Paths.ServiceDefinition ||
			!canonicalAbsolutePath(preview.Manager.ServiceDefinition) {
			return errors.New("deployment preview native manager outcome is invalid")
		}
		if err := requireStrictDescendant(layout.HomeDir, preview.Manager.ServiceDefinition, "service definition"); err != nil {
			return err
		}
	}
	if preview.Existing.State != nil {
		if err := preview.Existing.State.Validate(layout); err != nil {
			return err
		}
	}
	if preview.Existing.Journal != nil {
		if err := preview.Existing.Journal.Validate(layout); err != nil {
			return err
		}
	}
	switch preview.Classification {
	case PreviewIdempotent:
		if preview.Existing.State.Active == nil || *preview.Existing.State.Active != desired || preview.Existing.State.Manager != preview.Manager.Manager {
			return errors.New("idempotent deployment preview does not match its desired release and manager")
		}
	case PreviewUpgrade:
		state := preview.Existing.State
		if state.Active != nil && *state.Active == desired && state.Manager == preview.Manager.Manager {
			return errors.New("upgrade deployment preview is already idempotent")
		}
	case PreviewResumeOrRecoveryRequired:
		journal := preview.Existing.Journal
		matchingApply := journal.Operation == OperationApply && journal.Desired != nil && *journal.Desired == desired &&
			managerMatchesJournal(preview.Manager, *journal)
		if preview.ApplyAllowed && !matchingApply {
			return errors.New("deployment recovery preview does not match its desired release and manager")
		}
	}
	validInstanceState := map[string]bool{"missing": true, "uninitialized": true, "resume": true, "initializing": true, "ready": true, "invalid": true}
	if !validInstanceState[preview.Existing.InstanceState] || preview.Existing.InstanceState == "invalid" && preview.ApplyAllowed {
		return errors.New("deployment preview instance state is invalid")
	}
	if preview.Actions == nil {
		return errors.New("deployment preview actions must be an explicit array")
	}
	for index, action := range preview.Actions {
		if action.Sequence != index+1 || action.Arguments == nil {
			return errors.New("deployment preview action ordering is invalid")
		}
		switch action.Category {
		case "filesystem", "service", "init", "health", "state":
		default:
			return errors.New("deployment preview action category is invalid")
		}
		if !previewActionOperations[action.Operation] || (action.Path != "" && !canonicalAbsolutePath(action.Path)) {
			return errors.New("deployment preview action is invalid")
		}
	}
	expectedActions, err := expectedPreviewActions(preview)
	if err != nil {
		return err
	}
	if !equalPreviewActions(preview.Actions, expectedActions) {
		return errors.New("deployment preview actions do not match the exact classified lifecycle plan")
	}
	if !preview.Assertions.Data.PreserveStateDirectory || !preview.Assertions.Data.PreserveInstanceIDs ||
		!preview.Assertions.Data.PreserveDatabase || !preview.Assertions.Data.PreserveDeviceRegistry ||
		!preview.Assertions.Data.PreserveInstanceSecret || preview.Assertions.Data.DestructivePurgePlanned ||
		!preview.Assertions.Network.LoopbackOnly || preview.Assertions.Network.PublicListenerPlanned ||
		!preview.Assertions.Scope.CurrentUserOnly || preview.Assertions.Scope.SudoRequired || len(preview.Assertions.Network.Listeners) == 0 {
		return errors.New("deployment preview safety assertions are invalid")
	}
	for _, listener := range preview.Assertions.Network.Listeners {
		if err := config.ValidateListener(listener); err != nil {
			return errors.New("deployment preview contains a non-loopback listener")
		}
	}
	if !slices.IsSorted(preview.Assertions.Network.Listeners) {
		return errors.New("deployment preview listeners are not canonically ordered")
	}
	for index := 1; index < len(preview.Assertions.Network.Listeners); index++ {
		if preview.Assertions.Network.Listeners[index-1] == preview.Assertions.Network.Listeners[index] {
			return errors.New("deployment preview listeners are not unique")
		}
	}
	return nil
}

func validatePreviewURLs(preview DeploymentPreview) error {
	artifactURL, err := url.Parse(preview.Inputs.Artifact.URL)
	if err != nil || artifactURL.Scheme == "" || artifactURL.Host == "" {
		return errors.New("deployment preview artifact URL is invalid")
	}
	origin, err := parseDownloadOrigin(artifactURL.Scheme + "://" + artifactURL.Host)
	if err != nil {
		return errors.New("deployment preview download origin is invalid")
	}
	files := []struct {
		value string
		name  string
	}{
		{value: preview.Inputs.Artifact.URL, name: "sshserver-" + preview.Target.OS + "-" + preview.Target.Architecture},
		{value: preview.Inputs.License.URL, name: "LICENSE"},
		{value: preview.Inputs.Notice.URL, name: "NOTICE"},
	}
	for _, file := range files {
		parsed, err := parseReleaseURL(file.value, origin, preview.Release.Release)
		if err != nil || pathpkg.Base(parsed.Path) != file.name {
			return fmt.Errorf("deployment preview %s URL is invalid", file.name)
		}
	}
	return nil
}

func validateForegroundPreview(preview DeploymentPreview) error {
	foreground := preview.Manager.Foreground
	if preview.Manager.Available || preview.Manager.ServiceDefinition != "" || preview.Paths.ServiceDefinition != "" || foreground == nil ||
		!foreground.Required || !foreground.Supervised || !previewReasonPattern.MatchString(foreground.Reason) || !previewForegroundReasons[foreground.Reason] ||
		!slices.Equal(foreground.Command, []string{preview.Paths.BinaryPath, "serve", "--state-dir", preview.Paths.StateDir}) {
		return errors.New("deployment preview foreground outcome is invalid")
	}
	return nil
}

func (preview DeploymentPreview) CanonicalBytes() ([]byte, error) {
	if err := preview.Validate(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(preview)
	if err != nil {
		return nil, err
	}
	return append(payload, '\n'), nil
}

func ParseDeploymentPreview(payload []byte) (DeploymentPreview, error) {
	var preview DeploymentPreview
	if len(payload) == 0 || len(payload) > maxDeploymentPreviewBytes {
		return preview, errors.New("deployment preview exceeds its size boundary")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&preview); err != nil {
		return DeploymentPreview{}, fmt.Errorf("decode deployment preview: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return DeploymentPreview{}, errors.New("deployment preview contains trailing data")
	}
	canonical, err := preview.CanonicalBytes()
	if err != nil {
		return DeploymentPreview{}, err
	}
	if !bytes.Equal(payload, canonical) {
		return DeploymentPreview{}, errors.New("deployment preview is not in canonical byte form")
	}
	return preview, nil
}
