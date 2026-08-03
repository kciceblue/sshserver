//go:build darwin || linux

package deployment

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/buildinfo"
	"github.com/kciceblue/sshserver/runtime/internal/config"
	"github.com/kciceblue/sshserver/runtime/internal/instance"
	"github.com/kciceblue/sshserver/runtime/internal/service"
)

var ErrInjectedDeploymentCrash = errors.New("injected deployment crash")

type serviceController interface {
	Kind() ManagerKind
	DefinitionPath() string
	Detect(context.Context, string, string) (ManagerAvailability, error)
	InstallDefinition([]byte) (string, error)
	Activate(context.Context) error
	Stop(context.Context) error
	Remove(context.Context) error
	IsActive(context.Context) (bool, error)
}

type Lifecycle struct {
	layout            Layout
	target            Target
	manager           serviceController
	inspector         IdentityInspector
	stageArtifact     func(string, string, string, int64, string) (string, error)
	verifyArtifact    func(string, int64, string) error
	stageReleaseFile  func(string, string, string, int64, string) (string, error)
	verifyReleaseFile func(string, int64, string) error
	initialize        func(context.Context, string, []string) (config.Settings, error)
	renderService     func(string, string, string) ([]byte, error)
	probeRunning      func(context.Context, string) (buildinfo.Identity, error)
	removeArtifacts   func(Layout) error
	failAfterPhase    Phase
}

type ApplyRequest struct {
	ManifestPayload []byte
	ManifestSHA256  string
	ArtifactPath    string
	LicensePath     string
	NoticePath      string
}

type ApplyResult struct {
	Status        string              `json:"status"`
	State         DeploymentState     `json:"state"`
	Foreground    *ForegroundFallback `json:"foreground,omitempty"`
	TransactionID string              `json:"transaction_id,omitempty"`
}

type StatusResult struct {
	Status           string             `json:"status"`
	State            *DeploymentState   `json:"state,omitempty"`
	Journal          *DeploymentJournal `json:"journal,omitempty"`
	Running          bool               `json:"running"`
	RecoveryRequired bool               `json:"recovery_required"`
}

type UninstallResult struct {
	Status        string          `json:"status"`
	State         DeploymentState `json:"state"`
	TransactionID string          `json:"transaction_id,omitempty"`
}

func NewNativeLifecycle(layout Layout) (*Lifecycle, error) {
	target := Target{OS: runtime.GOOS, Architecture: runtime.GOARCH}
	if !isSupportedTarget(target) {
		return nil, fmt.Errorf("unsupported deployment host %s/%s", target.OS, target.Architecture)
	}
	manager, err := NewNativeServiceManagerAdapter(layout.HomeDir)
	if err != nil {
		return nil, err
	}
	return newLifecycle(layout, target, manager), nil
}

func (lifecycle *Lifecycle) Status(ctx context.Context) (StatusResult, error) {
	if lifecycle == nil || lifecycle.manager == nil || lifecycle.inspector == nil || lifecycle.verifyArtifact == nil || lifecycle.verifyReleaseFile == nil || lifecycle.probeRunning == nil {
		return StatusResult{}, errors.New("deployment lifecycle dependencies are incomplete")
	}
	journal, journalErr := LoadJournal(lifecycle.layout)
	if journalErr == nil {
		result := StatusResult{Status: "recovery_required", Journal: &journal, RecoveryRequired: true}
		if state, err := LoadState(lifecycle.layout); err == nil {
			result.State = &state
		} else if !errors.Is(err, ErrNoDeploymentState) {
			return StatusResult{}, err
		}
		return result, nil
	}
	if !errors.Is(journalErr, ErrNoDeploymentJournal) {
		return StatusResult{}, journalErr
	}
	state, err := LoadState(lifecycle.layout)
	if errors.Is(err, ErrNoDeploymentState) {
		return StatusResult{Status: "uninstalled"}, nil
	}
	if err != nil {
		return StatusResult{}, err
	}
	result := StatusResult{State: &state}
	if state.Status == StatusUninstalled {
		result.Status = "uninstalled"
		return result, nil
	}
	if state.Active == nil {
		return StatusResult{}, errors.New("deployment state has no active release")
	}
	if err := lifecycle.verifyDesired(ctx, *state.Active); err != nil {
		result.Status = "damaged"
		return result, err
	}
	if state.Status == StatusActive {
		active, err := lifecycle.manager.IsActive(ctx)
		if err != nil {
			return StatusResult{}, err
		}
		if !active {
			result.Status = "inactive"
			return result, nil
		}
	}
	identity, err := lifecycle.probeRunning(ctx, lifecycle.layout.StateDir)
	if errors.Is(err, ErrRuntimeUnavailable) {
		if state.Status == StatusForeground {
			result.Status = "foreground_stopped"
		} else {
			result.Status = "starting"
		}
		return result, nil
	}
	if err != nil {
		return StatusResult{}, err
	}
	if err := ValidateReleaseIdentity(identity, *state.Active); err != nil {
		result.Status = "identity_mismatch"
		return result, err
	}
	result.Running = true
	if state.Status == StatusForeground {
		result.Status = "foreground_running"
	} else {
		result.Status = "active"
	}
	return result, nil
}

func (lifecycle *Lifecycle) Rollback(ctx context.Context) (result ApplyResult, returnErr error) {
	if lifecycle == nil || lifecycle.manager == nil || lifecycle.inspector == nil || lifecycle.verifyArtifact == nil ||
		lifecycle.verifyReleaseFile == nil || lifecycle.renderService == nil || lifecycle.probeRunning == nil {
		return ApplyResult{}, errors.New("deployment lifecycle dependencies are incomplete")
	}
	if err := PrepareLayout(lifecycle.layout); err != nil {
		return ApplyResult{}, err
	}
	lock, err := acquireDeploymentLock(lifecycle.layout)
	if err != nil {
		return ApplyResult{}, err
	}
	defer func() {
		if closeErr := lock.Close(); closeErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("release deployment lock: %w", closeErr))
		}
	}()
	journal, journalErr := LoadJournal(lifecycle.layout)
	if journalErr == nil {
		if journal.Operation != OperationRollback {
			return ApplyResult{}, errors.New("a different deployment transaction requires recovery before rollback")
		}
		result, err := lifecycle.runRollback(ctx, &journal)
		if err == nil || errors.Is(err, ErrInjectedDeploymentCrash) || journal.Phase == PhaseStateSaved {
			return result, err
		}
		return ApplyResult{}, errors.Join(err, lifecycle.restorePriorAfterFailedSwitch(ctx, journal))
	}
	if !errors.Is(journalErr, ErrNoDeploymentJournal) {
		return ApplyResult{}, journalErr
	}
	state, err := LoadState(lifecycle.layout)
	if err != nil {
		return ApplyResult{}, err
	}
	if state.Active == nil || state.Previous == nil || state.Status == StatusUninstalled {
		return ApplyResult{}, errors.New("no verified previous release is available for rollback")
	}
	if state.Active.StorageSchema != state.Previous.StorageSchema {
		return ApplyResult{}, errors.New("rollback across storage schemas requires a complete verified database image")
	}
	if err := lifecycle.verifyDesired(ctx, *state.Previous); err != nil {
		return ApplyResult{}, fmt.Errorf("verify previous release before rollback: %w", err)
	}
	availability, err := lifecycle.manager.Detect(ctx, state.Previous.BinaryPath, lifecycle.layout.StateDir)
	if err != nil {
		return ApplyResult{}, err
	}
	if state.Status == StatusActive && !availability.Available {
		return ApplyResult{}, errors.New("the active native user service manager is unavailable; refusing rollback")
	}
	transactionID, err := newTransactionID()
	if err != nil {
		return ApplyResult{}, err
	}
	desired := *state.Previous
	journal = DeploymentJournal{
		StateVersion:      DeploymentStateVersion,
		TransactionID:     transactionID,
		Operation:         OperationRollback,
		Phase:             PhasePlanned,
		Manager:           availability.Manager,
		ServiceDefinition: availability.ServiceDefinition,
		Desired:           &desired,
		PriorState:        &state,
	}
	if err := SaveJournal(lifecycle.layout, journal); err != nil {
		return ApplyResult{}, err
	}
	if err := lifecycle.injectCrash(PhasePlanned); err != nil {
		return ApplyResult{}, err
	}
	result, err = lifecycle.runRollback(ctx, &journal)
	if err == nil || errors.Is(err, ErrInjectedDeploymentCrash) || journal.Phase == PhaseStateSaved {
		return result, err
	}
	return ApplyResult{}, errors.Join(err, lifecycle.restorePriorAfterFailedSwitch(ctx, journal))
}

func (lifecycle *Lifecycle) Uninstall(ctx context.Context) (result UninstallResult, returnErr error) {
	if lifecycle == nil || lifecycle.manager == nil || lifecycle.inspector == nil || lifecycle.verifyArtifact == nil ||
		lifecycle.verifyReleaseFile == nil || lifecycle.renderService == nil || lifecycle.probeRunning == nil || lifecycle.removeArtifacts == nil {
		return UninstallResult{}, errors.New("deployment lifecycle dependencies are incomplete")
	}
	if err := PrepareLayout(lifecycle.layout); err != nil {
		return UninstallResult{}, err
	}
	lock, err := acquireDeploymentLock(lifecycle.layout)
	if err != nil {
		return UninstallResult{}, err
	}
	defer func() {
		if closeErr := lock.Close(); closeErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("release deployment lock: %w", closeErr))
		}
	}()
	journal, journalErr := LoadJournal(lifecycle.layout)
	if journalErr == nil {
		if journal.Operation != OperationUninstall {
			return UninstallResult{}, errors.New("a different deployment transaction requires recovery before uninstall")
		}
		result, err := lifecycle.runUninstall(ctx, &journal)
		if err == nil || errors.Is(err, ErrInjectedDeploymentCrash) || uninstallPhaseReached(journal.Phase, PhaseRemovingArtifacts) {
			return result, err
		}
		return UninstallResult{}, errors.Join(err, lifecycle.restorePriorAfterFailedUninstall(ctx, journal))
	}
	if !errors.Is(journalErr, ErrNoDeploymentJournal) {
		return UninstallResult{}, journalErr
	}
	state, stateErr := LoadState(lifecycle.layout)
	if errors.Is(stateErr, ErrNoDeploymentState) {
		state = DeploymentState{
			StateVersion: DeploymentStateVersion,
			Generation:   1,
			Status:       StatusUninstalled,
			Manager:      ManagerNone,
			StateDir:     lifecycle.layout.StateDir,
		}
		if err := SaveState(lifecycle.layout, state); err != nil {
			return UninstallResult{}, err
		}
		return UninstallResult{Status: "uninstalled", State: state}, nil
	}
	if stateErr != nil {
		return UninstallResult{}, stateErr
	}
	if state.Status == StatusUninstalled {
		return UninstallResult{Status: "uninstalled", State: state}, nil
	}
	transactionID, err := newTransactionID()
	if err != nil {
		return UninstallResult{}, err
	}
	journal = DeploymentJournal{
		StateVersion:      DeploymentStateVersion,
		TransactionID:     transactionID,
		Operation:         OperationUninstall,
		Phase:             PhasePlanned,
		Manager:           state.Manager,
		ServiceDefinition: state.ServiceDefinition,
		PriorState:        &state,
	}
	if err := SaveJournal(lifecycle.layout, journal); err != nil {
		return UninstallResult{}, err
	}
	if err := lifecycle.injectCrash(PhasePlanned); err != nil {
		return UninstallResult{}, err
	}
	result, err = lifecycle.runUninstall(ctx, &journal)
	if err == nil || errors.Is(err, ErrInjectedDeploymentCrash) || uninstallPhaseReached(journal.Phase, PhaseRemovingArtifacts) {
		return result, err
	}
	return UninstallResult{}, errors.Join(err, lifecycle.restorePriorAfterFailedUninstall(ctx, journal))
}

func (lifecycle *Lifecycle) runUninstall(ctx context.Context, journal *DeploymentJournal) (UninstallResult, error) {
	if journal.Phase == PhaseStateSaved {
		state, err := lifecycle.validateCommittedUninstallState(*journal)
		if err != nil {
			return UninstallResult{}, err
		}
		if err := RemoveJournal(lifecycle.layout); err != nil {
			return UninstallResult{}, err
		}
		return UninstallResult{Status: "uninstalled", State: state, TransactionID: journal.TransactionID}, nil
	}
	if !uninstallPhaseReached(journal.Phase, PhasePriorServiceStopped) {
		if err := lifecycle.stopPrior(ctx, journal.PriorState); err != nil {
			return UninstallResult{}, err
		}
		if err := lifecycle.checkpoint(journal, PhasePriorServiceStopped); err != nil {
			return UninstallResult{}, err
		}
	}
	if !uninstallPhaseReached(journal.Phase, PhaseDefinitionRemoved) {
		if journal.Manager != ManagerForeground && journal.Manager != ManagerNone {
			if err := lifecycle.manager.Remove(ctx); err != nil {
				return UninstallResult{}, err
			}
		}
		if err := lifecycle.checkpoint(journal, PhaseDefinitionRemoved); err != nil {
			return UninstallResult{}, err
		}
	}
	if !uninstallPhaseReached(journal.Phase, PhaseRemovingArtifacts) {
		if err := lifecycle.checkpoint(journal, PhaseRemovingArtifacts); err != nil {
			return UninstallResult{}, err
		}
	}
	if !uninstallPhaseReached(journal.Phase, PhaseArtifactsRemoved) {
		if err := lifecycle.removeArtifacts(lifecycle.layout); err != nil {
			return UninstallResult{}, err
		}
		if err := lifecycle.checkpoint(journal, PhaseArtifactsRemoved); err != nil {
			return UninstallResult{}, err
		}
	}
	if !uninstallPhaseReached(journal.Phase, PhaseCommitting) {
		if err := lifecycle.checkpoint(journal, PhaseCommitting); err != nil {
			return UninstallResult{}, err
		}
	}
	state := lifecycle.committedUninstallState(*journal)
	if err := SaveState(lifecycle.layout, state); err != nil {
		return UninstallResult{}, err
	}
	if err := lifecycle.checkpoint(journal, PhaseStateSaved); err != nil {
		return UninstallResult{}, err
	}
	if err := RemoveJournal(lifecycle.layout); err != nil {
		return UninstallResult{}, err
	}
	return UninstallResult{Status: "uninstalled", State: state, TransactionID: journal.TransactionID}, nil
}

func (lifecycle *Lifecycle) committedUninstallState(journal DeploymentJournal) DeploymentState {
	var lastActive *InstalledRelease
	if journal.PriorState.Active != nil {
		copy := *journal.PriorState.Active
		lastActive = &copy
	}
	return DeploymentState{
		StateVersion: DeploymentStateVersion,
		Generation:   journal.PriorState.Generation + 1,
		Status:       StatusUninstalled,
		Manager:      ManagerNone,
		StateDir:     lifecycle.layout.StateDir,
		Previous:     lastActive,
	}
}

func (lifecycle *Lifecycle) validateCommittedUninstallState(journal DeploymentJournal) (DeploymentState, error) {
	state, err := LoadState(lifecycle.layout)
	if err != nil {
		return DeploymentState{}, err
	}
	if !sameDeploymentState(state, lifecycle.committedUninstallState(journal)) {
		return DeploymentState{}, errors.New("saved uninstall state does not match the recovering transaction")
	}
	return state, nil
}

func (lifecycle *Lifecycle) restorePriorAfterFailedUninstall(ctx context.Context, journal DeploymentJournal) error {
	if journal.PriorState == nil {
		return errors.New("uninstall recovery has no prior state")
	}
	prior := *journal.PriorState
	if prior.Status == StatusActive && prior.Active != nil {
		if err := lifecycle.verifyDesired(ctx, *prior.Active); err != nil {
			return fmt.Errorf("verify prior release during uninstall recovery: %w", err)
		}
		payload, err := lifecycle.renderService(prior.Active.OS, prior.Active.BinaryPath, lifecycle.layout.StateDir)
		if err != nil {
			return err
		}
		if _, err := lifecycle.manager.InstallDefinition(payload); err != nil {
			return fmt.Errorf("restore service after failed uninstall: %w", err)
		}
		if err := lifecycle.manager.Activate(ctx); err != nil {
			return fmt.Errorf("reactivate service after failed uninstall: %w", err)
		}
		if err := lifecycle.waitForRunning(ctx, *prior.Active); err != nil {
			return fmt.Errorf("attest service after failed uninstall: %w", err)
		}
	}
	if err := SaveState(lifecycle.layout, prior); err != nil {
		return err
	}
	return RemoveJournal(lifecycle.layout)
}

func (lifecycle *Lifecycle) runRollback(ctx context.Context, journal *DeploymentJournal) (ApplyResult, error) {
	if journal.Phase == PhaseStateSaved {
		state, err := lifecycle.validateCommittedRollbackState(*journal)
		if err != nil {
			return ApplyResult{}, err
		}
		if err := RemoveJournal(lifecycle.layout); err != nil {
			return ApplyResult{}, err
		}
		return lifecycle.resultForState(state, lifecycle.foregroundFor(journal), journal.TransactionID), nil
	}
	desired := *journal.Desired
	if err := lifecycle.verifyDesired(ctx, desired); err != nil {
		return ApplyResult{}, err
	}
	if !rollbackPhaseReached(journal.Phase, PhasePriorServiceStopped) {
		if err := lifecycle.stopPrior(ctx, journal.PriorState); err != nil {
			return ApplyResult{}, err
		}
		if err := lifecycle.checkpoint(journal, PhasePriorServiceStopped); err != nil {
			return ApplyResult{}, err
		}
	}
	if !rollbackPhaseReached(journal.Phase, PhaseDefinitionInstalled) {
		if journal.Manager != ManagerForeground {
			payload, err := lifecycle.renderService(desired.OS, desired.BinaryPath, lifecycle.layout.StateDir)
			if err != nil {
				return ApplyResult{}, err
			}
			installed, err := lifecycle.manager.InstallDefinition(payload)
			if err != nil {
				return ApplyResult{}, err
			}
			if installed != journal.ServiceDefinition {
				return ApplyResult{}, errors.New("service manager installed an unexpected rollback definition path")
			}
		}
		if err := lifecycle.checkpoint(journal, PhaseDefinitionInstalled); err != nil {
			return ApplyResult{}, err
		}
	}
	if journal.Manager != ManagerForeground {
		if !rollbackPhaseReached(journal.Phase, PhaseActivated) {
			if err := lifecycle.activateDesired(ctx, desired); err != nil {
				return ApplyResult{}, err
			}
			if err := lifecycle.checkpoint(journal, PhaseActivated); err != nil {
				return ApplyResult{}, err
			}
		}
		if !rollbackPhaseReached(journal.Phase, PhaseHealthVerified) {
			if err := lifecycle.waitForRunning(ctx, desired); err != nil {
				return ApplyResult{}, err
			}
			if err := lifecycle.checkpoint(journal, PhaseHealthVerified); err != nil {
				return ApplyResult{}, err
			}
		}
	}
	if !rollbackPhaseReached(journal.Phase, PhaseCommitting) {
		if err := lifecycle.checkpoint(journal, PhaseCommitting); err != nil {
			return ApplyResult{}, err
		}
	}
	state := lifecycle.committedRollbackState(*journal)
	if err := SaveState(lifecycle.layout, state); err != nil {
		return ApplyResult{}, err
	}
	if err := lifecycle.checkpoint(journal, PhaseStateSaved); err != nil {
		return ApplyResult{}, err
	}
	if err := RemoveJournal(lifecycle.layout); err != nil {
		return ApplyResult{}, err
	}
	return lifecycle.resultForState(state, lifecycle.foregroundFor(journal), journal.TransactionID), nil
}

func (lifecycle *Lifecycle) committedRollbackState(journal DeploymentJournal) DeploymentState {
	desired := *journal.Desired
	priorActive := *journal.PriorState.Active
	state := DeploymentState{
		StateVersion:      DeploymentStateVersion,
		Generation:        journal.PriorState.Generation + 1,
		Status:            StatusActive,
		Manager:           journal.Manager,
		StateDir:          lifecycle.layout.StateDir,
		ServiceDefinition: journal.ServiceDefinition,
		Active:            &desired,
		Previous:          &priorActive,
	}
	if journal.Manager == ManagerForeground {
		state.Status = StatusForeground
	}
	return state
}

func (lifecycle *Lifecycle) validateCommittedRollbackState(journal DeploymentJournal) (DeploymentState, error) {
	state, err := LoadState(lifecycle.layout)
	if err != nil {
		return DeploymentState{}, err
	}
	if !sameDeploymentState(state, lifecycle.committedRollbackState(journal)) {
		return DeploymentState{}, errors.New("saved rollback state does not match the recovering transaction")
	}
	return state, nil
}

func (lifecycle *Lifecycle) restorePriorAfterFailedSwitch(ctx context.Context, journal DeploymentJournal) error {
	if journal.Manager != ManagerForeground {
		if err := lifecycle.manager.Remove(ctx); err != nil {
			return fmt.Errorf("remove failed switched service: %w", err)
		}
	}
	if journal.PriorState == nil {
		return errors.New("switch recovery has no prior state")
	}
	prior := *journal.PriorState
	if prior.Status == StatusActive && prior.Active != nil {
		if err := lifecycle.verifyDesired(ctx, *prior.Active); err != nil {
			return fmt.Errorf("verify prior release during switch recovery: %w", err)
		}
		payload, err := lifecycle.renderService(prior.Active.OS, prior.Active.BinaryPath, lifecycle.layout.StateDir)
		if err != nil {
			return err
		}
		if _, err := lifecycle.manager.InstallDefinition(payload); err != nil {
			return fmt.Errorf("restore prior service during switch recovery: %w", err)
		}
		if err := lifecycle.manager.Activate(ctx); err != nil {
			return fmt.Errorf("activate prior service during switch recovery: %w", err)
		}
		if err := lifecycle.waitForRunning(ctx, *prior.Active); err != nil {
			return fmt.Errorf("attest prior service during switch recovery: %w", err)
		}
	}
	if err := SaveState(lifecycle.layout, prior); err != nil {
		return err
	}
	return RemoveJournal(lifecycle.layout)
}

func newLifecycle(layout Layout, target Target, manager serviceController) *Lifecycle {
	return &Lifecycle{
		layout:            layout,
		target:            target,
		manager:           manager,
		inspector:         ExecutableIdentityInspector{},
		stageArtifact:     StageVerifiedArtifact,
		verifyArtifact:    VerifyStagedArtifact,
		stageReleaseFile:  StageVerifiedReleaseFile,
		verifyReleaseFile: VerifyStagedReleaseFile,
		initialize:        instance.Initialize,
		renderService:     service.Render,
		probeRunning:      ProbeRunningIdentity,
		removeArtifacts:   RemoveInstalledArtifacts,
	}
}

func (lifecycle *Lifecycle) Apply(ctx context.Context, request ApplyRequest) (result ApplyResult, returnErr error) {
	if lifecycle == nil || lifecycle.manager == nil || lifecycle.inspector == nil || lifecycle.stageArtifact == nil ||
		lifecycle.verifyArtifact == nil || lifecycle.stageReleaseFile == nil || lifecycle.verifyReleaseFile == nil ||
		lifecycle.initialize == nil || lifecycle.renderService == nil || lifecycle.probeRunning == nil {
		return ApplyResult{}, errors.New("deployment lifecycle dependencies are incomplete")
	}
	manifest, err := ParsePinnedManifest(request.ManifestPayload, request.ManifestSHA256)
	if err != nil {
		return ApplyResult{}, err
	}
	desired, err := InstalledFromManifest(lifecycle.layout, manifest, request.ManifestSHA256, lifecycle.target)
	if err != nil {
		return ApplyResult{}, err
	}
	if !canonicalAbsolutePath(request.ArtifactPath) || !canonicalAbsolutePath(request.LicensePath) || !canonicalAbsolutePath(request.NoticePath) {
		return ApplyResult{}, errors.New("deployment artifact and release-file paths must be canonical and absolute")
	}
	if request.ArtifactPath == request.LicensePath || request.ArtifactPath == request.NoticePath || request.LicensePath == request.NoticePath {
		return ApplyResult{}, errors.New("deployment input paths must be distinct")
	}
	if err := PrepareLayout(lifecycle.layout); err != nil {
		return ApplyResult{}, err
	}
	lock, err := acquireDeploymentLock(lifecycle.layout)
	if err != nil {
		return ApplyResult{}, err
	}
	defer func() {
		if closeErr := lock.Close(); closeErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("release deployment lock: %w", closeErr))
		}
	}()

	journal, journalErr := LoadJournal(lifecycle.layout)
	if journalErr == nil {
		if journal.Operation != OperationApply || journal.Desired == nil || *journal.Desired != desired {
			return ApplyResult{}, errors.New("a different deployment transaction requires recovery before apply")
		}
		if journal.Phase == PhasePlanned && (journal.SourcePath != request.ArtifactPath || journal.LicenseSourcePath != request.LicensePath || journal.NoticeSourcePath != request.NoticePath) {
			journal.SourcePath = request.ArtifactPath
			journal.LicenseSourcePath = request.LicensePath
			journal.NoticeSourcePath = request.NoticePath
			if err := SaveJournal(lifecycle.layout, journal); err != nil {
				return ApplyResult{}, err
			}
		}
		result, err := lifecycle.runApply(ctx, &journal)
		if err == nil || errors.Is(err, ErrInjectedDeploymentCrash) || journal.Phase == PhaseStateSaved {
			return result, err
		}
		rollbackErr := lifecycle.restorePriorAfterFailedApply(ctx, journal)
		return ApplyResult{}, errors.Join(err, rollbackErr)
	}
	if !errors.Is(journalErr, ErrNoDeploymentJournal) {
		return ApplyResult{}, journalErr
	}

	var prior *DeploymentState
	state, stateErr := LoadState(lifecycle.layout)
	if stateErr == nil {
		prior = &state
	} else if !errors.Is(stateErr, ErrNoDeploymentState) {
		return ApplyResult{}, stateErr
	}
	availability, err := lifecycle.manager.Detect(ctx, desired.BinaryPath, lifecycle.layout.StateDir)
	if err != nil {
		return ApplyResult{}, err
	}
	if prior != nil && prior.Status == StatusActive && !availability.Available {
		return ApplyResult{}, errors.New("the active native user service manager is unavailable; refusing an implicit foreground transition")
	}
	if prior != nil && prior.Active != nil && *prior.Active == desired && prior.Manager == availability.Manager {
		return lifecycle.validateIdempotentApply(ctx, *prior, availability, request)
	}
	transactionID, err := newTransactionID()
	if err != nil {
		return ApplyResult{}, err
	}
	journal = DeploymentJournal{
		StateVersion:      DeploymentStateVersion,
		TransactionID:     transactionID,
		Operation:         OperationApply,
		Phase:             PhasePlanned,
		Manager:           availability.Manager,
		ServiceDefinition: availability.ServiceDefinition,
		SourcePath:        request.ArtifactPath,
		LicenseSourcePath: request.LicensePath,
		NoticeSourcePath:  request.NoticePath,
		Desired:           &desired,
		PriorState:        prior,
	}
	if err := SaveJournal(lifecycle.layout, journal); err != nil {
		return ApplyResult{}, err
	}
	if err := lifecycle.injectCrash(PhasePlanned); err != nil {
		return ApplyResult{}, err
	}
	result, err = lifecycle.runApply(ctx, &journal)
	if err == nil || errors.Is(err, ErrInjectedDeploymentCrash) || journal.Phase == PhaseStateSaved {
		return result, err
	}
	rollbackErr := lifecycle.restorePriorAfterFailedApply(ctx, journal)
	return ApplyResult{}, errors.Join(err, rollbackErr)
}

func (lifecycle *Lifecycle) validateIdempotentApply(ctx context.Context, state DeploymentState, availability ManagerAvailability, request ApplyRequest) (ApplyResult, error) {
	if state.Active == nil {
		return ApplyResult{}, errors.New("idempotent deployment state has no active release")
	}
	versionDir, err := PrepareVersionDirectory(lifecycle.layout, state.Active.Release)
	if err != nil {
		return ApplyResult{}, err
	}
	staged, err := lifecycle.stageArtifact(request.ArtifactPath, versionDir, filepath.Base(state.Active.BinaryPath), state.Active.BinaryBytes, state.Active.BinarySHA256)
	if err != nil {
		return ApplyResult{}, err
	}
	if staged != state.Active.BinaryPath {
		return ApplyResult{}, errors.New("idempotent artifact staging returned an unexpected path")
	}
	if err := lifecycle.stageSupportFiles(versionDir, *state.Active, request.LicensePath, request.NoticePath); err != nil {
		return ApplyResult{}, err
	}
	if err := lifecycle.verifyDesired(ctx, *state.Active); err != nil {
		return ApplyResult{}, err
	}
	if state.Status == StatusActive {
		active, err := lifecycle.manager.IsActive(ctx)
		if err != nil {
			return ApplyResult{}, err
		}
		if !active {
			return ApplyResult{}, errors.New("recorded user service is not active; run deployment recovery")
		}
		identity, err := lifecycle.probeRunning(ctx, lifecycle.layout.StateDir)
		if err != nil {
			return ApplyResult{}, err
		}
		if err := ValidateReleaseIdentity(identity, *state.Active); err != nil {
			return ApplyResult{}, err
		}
	}
	return lifecycle.resultForState(state, availability.Foreground, ""), nil
}

func (lifecycle *Lifecycle) runApply(ctx context.Context, journal *DeploymentJournal) (ApplyResult, error) {
	if journal.Phase == PhaseStateSaved {
		state, err := lifecycle.validateCommittedState(*journal)
		if err != nil {
			return ApplyResult{}, err
		}
		if err := RemoveJournal(lifecycle.layout); err != nil {
			return ApplyResult{}, err
		}
		return lifecycle.resultForState(state, lifecycle.foregroundFor(journal), journal.TransactionID), nil
	}
	desired := *journal.Desired
	if !applyPhaseReached(journal.Phase, PhaseArtifactStaged) {
		versionDir, err := PrepareVersionDirectory(lifecycle.layout, desired.Release)
		if err != nil {
			return ApplyResult{}, err
		}
		staged, err := lifecycle.stageArtifact(journal.SourcePath, versionDir, filepath.Base(desired.BinaryPath), desired.BinaryBytes, desired.BinarySHA256)
		if err != nil {
			return ApplyResult{}, err
		}
		if staged != desired.BinaryPath {
			return ApplyResult{}, errors.New("artifact staging returned an unexpected immutable path")
		}
		if err := lifecycle.stageSupportFiles(versionDir, desired, journal.LicenseSourcePath, journal.NoticeSourcePath); err != nil {
			return ApplyResult{}, err
		}
		if err := lifecycle.verifyDesired(ctx, desired); err != nil {
			return ApplyResult{}, err
		}
		if err := lifecycle.checkpoint(journal, PhaseArtifactStaged); err != nil {
			return ApplyResult{}, err
		}
	} else if err := lifecycle.verifyDesired(ctx, desired); err != nil {
		return ApplyResult{}, err
	}

	if !applyPhaseReached(journal.Phase, PhaseInstanceReady) {
		if _, err := lifecycle.initialize(ctx, lifecycle.layout.StateDir, nil); err != nil {
			return ApplyResult{}, err
		}
		if err := lifecycle.checkpoint(journal, PhaseInstanceReady); err != nil {
			return ApplyResult{}, err
		}
	}
	if !applyPhaseReached(journal.Phase, PhasePriorServiceStopped) {
		if err := lifecycle.stopPrior(ctx, journal.PriorState); err != nil {
			return ApplyResult{}, err
		}
		if err := lifecycle.checkpoint(journal, PhasePriorServiceStopped); err != nil {
			return ApplyResult{}, err
		}
	}
	if !applyPhaseReached(journal.Phase, PhaseDefinitionInstalled) {
		if journal.Manager != ManagerForeground {
			payload, err := lifecycle.renderService(desired.OS, desired.BinaryPath, lifecycle.layout.StateDir)
			if err != nil {
				return ApplyResult{}, err
			}
			installed, err := lifecycle.manager.InstallDefinition(payload)
			if err != nil {
				return ApplyResult{}, err
			}
			if installed != journal.ServiceDefinition {
				return ApplyResult{}, errors.New("service manager installed an unexpected definition path")
			}
		}
		if err := lifecycle.checkpoint(journal, PhaseDefinitionInstalled); err != nil {
			return ApplyResult{}, err
		}
	}
	if journal.Manager != ManagerForeground {
		if !applyPhaseReached(journal.Phase, PhaseActivated) {
			if err := lifecycle.activateDesired(ctx, desired); err != nil {
				return ApplyResult{}, err
			}
			if err := lifecycle.checkpoint(journal, PhaseActivated); err != nil {
				return ApplyResult{}, err
			}
		}
		if !applyPhaseReached(journal.Phase, PhaseHealthVerified) {
			if err := lifecycle.waitForRunning(ctx, desired); err != nil {
				return ApplyResult{}, err
			}
			if err := lifecycle.checkpoint(journal, PhaseHealthVerified); err != nil {
				return ApplyResult{}, err
			}
		}
	}
	if !applyPhaseReached(journal.Phase, PhaseCommitting) {
		if err := lifecycle.checkpoint(journal, PhaseCommitting); err != nil {
			return ApplyResult{}, err
		}
	}
	state := lifecycle.committedApplyState(*journal)
	if err := SaveState(lifecycle.layout, state); err != nil {
		return ApplyResult{}, err
	}
	if err := lifecycle.checkpoint(journal, PhaseStateSaved); err != nil {
		return ApplyResult{}, err
	}
	if err := RemoveJournal(lifecycle.layout); err != nil {
		return ApplyResult{}, err
	}
	return lifecycle.resultForState(state, lifecycle.foregroundFor(journal), journal.TransactionID), nil
}

func (lifecycle *Lifecycle) verifyDesired(ctx context.Context, desired InstalledRelease) error {
	if err := lifecycle.verifyArtifact(desired.BinaryPath, desired.BinaryBytes, desired.BinarySHA256); err != nil {
		return err
	}
	licensePath, err := desired.SupportFilePath(lifecycle.layout, "LICENSE")
	if err != nil {
		return err
	}
	if err := lifecycle.verifyReleaseFile(licensePath, desired.LicenseBytes, desired.LicenseSHA256); err != nil {
		return err
	}
	noticePath, err := desired.SupportFilePath(lifecycle.layout, "NOTICE")
	if err != nil {
		return err
	}
	if err := lifecycle.verifyReleaseFile(noticePath, desired.NoticeBytes, desired.NoticeSHA256); err != nil {
		return err
	}
	identity, err := lifecycle.inspector.Inspect(ctx, desired.BinaryPath)
	if err != nil {
		return err
	}
	return ValidateReleaseIdentity(identity, desired)
}

func (lifecycle *Lifecycle) stageSupportFiles(versionDir string, desired InstalledRelease, licenseSource, noticeSource string) error {
	licensePath, err := lifecycle.stageReleaseFile(licenseSource, versionDir, "LICENSE", desired.LicenseBytes, desired.LicenseSHA256)
	if err != nil {
		return err
	}
	wantLicense, err := desired.SupportFilePath(lifecycle.layout, "LICENSE")
	if err != nil {
		return err
	}
	if licensePath != wantLicense {
		return errors.New("release LICENSE staging returned an unexpected immutable path")
	}
	noticePath, err := lifecycle.stageReleaseFile(noticeSource, versionDir, "NOTICE", desired.NoticeBytes, desired.NoticeSHA256)
	if err != nil {
		return err
	}
	wantNotice, err := desired.SupportFilePath(lifecycle.layout, "NOTICE")
	if err != nil {
		return err
	}
	if noticePath != wantNotice {
		return errors.New("release NOTICE staging returned an unexpected immutable path")
	}
	return nil
}

func (lifecycle *Lifecycle) stopPrior(ctx context.Context, prior *DeploymentState) error {
	if prior == nil || prior.Status == StatusUninstalled || prior.Active == nil {
		return nil
	}
	if prior.Status == StatusActive {
		if prior.Manager != lifecycle.manager.Kind() {
			return errors.New("prior service manager does not match this host")
		}
		return lifecycle.manager.Stop(ctx)
	}
	identity, err := lifecycle.probeRunning(ctx, lifecycle.layout.StateDir)
	if err == nil {
		if identityErr := ValidateReleaseIdentity(identity, *prior.Active); identityErr != nil {
			return errors.New("an unknown foreground runtime is using the protected instance")
		}
		return errors.New("the supervised foreground runtime must be stopped before deployment")
	}
	if !errors.Is(err, ErrRuntimeUnavailable) {
		return err
	}
	return nil
}

func (lifecycle *Lifecycle) activateDesired(ctx context.Context, desired InstalledRelease) error {
	active, err := lifecycle.manager.IsActive(ctx)
	if err != nil {
		return err
	}
	if active {
		identity, probeErr := lifecycle.probeRunning(ctx, lifecycle.layout.StateDir)
		if probeErr == nil && ValidateReleaseIdentity(identity, desired) == nil {
			return nil
		}
		if err := lifecycle.manager.Stop(ctx); err != nil {
			return err
		}
	}
	return lifecycle.manager.Activate(ctx)
}

func (lifecycle *Lifecycle) waitForRunning(ctx context.Context, desired InstalledRelease) error {
	waitCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	for {
		active, err := lifecycle.manager.IsActive(waitCtx)
		if err != nil {
			return err
		}
		if active {
			identity, probeErr := lifecycle.probeRunning(waitCtx, lifecycle.layout.StateDir)
			if probeErr == nil {
				return ValidateReleaseIdentity(identity, desired)
			}
			if !errors.Is(probeErr, ErrRuntimeUnavailable) {
				return probeErr
			}
		}
		select {
		case <-waitCtx.Done():
			return errors.New("user service did not attest the desired release before the health deadline")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (lifecycle *Lifecycle) committedApplyState(journal DeploymentJournal) DeploymentState {
	generation := uint64(1)
	var previous *InstalledRelease
	if journal.PriorState != nil {
		generation = journal.PriorState.Generation + 1
		if journal.PriorState.Active != nil && journal.PriorState.Active.ManifestSHA256 != journal.Desired.ManifestSHA256 {
			copy := *journal.PriorState.Active
			previous = &copy
		} else if journal.PriorState.Active != nil && journal.PriorState.Previous != nil {
			copy := *journal.PriorState.Previous
			previous = &copy
		}
	}
	desired := *journal.Desired
	state := DeploymentState{
		StateVersion:      DeploymentStateVersion,
		Generation:        generation,
		Status:            StatusActive,
		Manager:           journal.Manager,
		StateDir:          lifecycle.layout.StateDir,
		ServiceDefinition: journal.ServiceDefinition,
		Active:            &desired,
		Previous:          previous,
	}
	if journal.Manager == ManagerForeground {
		state.Status = StatusForeground
	}
	return state
}

func (lifecycle *Lifecycle) validateCommittedState(journal DeploymentJournal) (DeploymentState, error) {
	state, err := LoadState(lifecycle.layout)
	if err != nil {
		return DeploymentState{}, err
	}
	want := lifecycle.committedApplyState(journal)
	if !sameDeploymentState(state, want) {
		return DeploymentState{}, errors.New("saved deployment state does not match the recovering transaction")
	}
	return state, nil
}

func (lifecycle *Lifecycle) restorePriorAfterFailedApply(ctx context.Context, journal DeploymentJournal) error {
	if !applyPhaseReached(journal.Phase, PhasePriorServiceStopped) {
		if applyPhaseReached(journal.Phase, PhaseInstanceReady) && journal.PriorState != nil &&
			journal.PriorState.Status == StatusActive && journal.PriorState.Active != nil {
			prior := *journal.PriorState.Active
			active, statusErr := lifecycle.manager.IsActive(ctx)
			if statusErr != nil {
				return fmt.Errorf("inspect prior service after interrupted stop: %w", statusErr)
			}
			if active {
				identity, probeErr := lifecycle.probeRunning(ctx, lifecycle.layout.StateDir)
				if probeErr == nil && ValidateReleaseIdentity(identity, prior) == nil {
					return RemoveJournal(lifecycle.layout)
				}
			}
			if err := lifecycle.verifyDesired(ctx, prior); err != nil {
				return fmt.Errorf("verify prior release after interrupted stop: %w", err)
			}
			payload, err := lifecycle.renderService(prior.OS, prior.BinaryPath, lifecycle.layout.StateDir)
			if err != nil {
				return err
			}
			if _, err := lifecycle.manager.InstallDefinition(payload); err != nil {
				return fmt.Errorf("restore prior definition after interrupted stop: %w", err)
			}
			if err := lifecycle.manager.Activate(ctx); err != nil {
				return fmt.Errorf("reactivate prior release after interrupted stop: %w", err)
			}
			if err := lifecycle.waitForRunning(ctx, prior); err != nil {
				return fmt.Errorf("attest prior release after interrupted stop: %w", err)
			}
		}
		return RemoveJournal(lifecycle.layout)
	}
	if journal.Manager != ManagerForeground {
		if err := lifecycle.manager.Remove(ctx); err != nil {
			return fmt.Errorf("rollback failed deployment service: %w", err)
		}
	}
	if journal.PriorState == nil {
		if err := RemoveState(lifecycle.layout); err != nil {
			return err
		}
		return RemoveJournal(lifecycle.layout)
	}
	prior := *journal.PriorState
	if prior.Status == StatusActive && prior.Active != nil {
		if err := lifecycle.verifyDesired(ctx, *prior.Active); err != nil {
			return fmt.Errorf("verify rollback release: %w", err)
		}
		payload, err := lifecycle.renderService(prior.Active.OS, prior.Active.BinaryPath, lifecycle.layout.StateDir)
		if err != nil {
			return err
		}
		if _, err := lifecycle.manager.InstallDefinition(payload); err != nil {
			return fmt.Errorf("restore prior service definition: %w", err)
		}
		if err := lifecycle.manager.Activate(ctx); err != nil {
			return fmt.Errorf("reactivate prior release: %w", err)
		}
		if err := lifecycle.waitForRunning(ctx, *prior.Active); err != nil {
			return fmt.Errorf("attest prior release after rollback: %w", err)
		}
	}
	if err := SaveState(lifecycle.layout, prior); err != nil {
		return err
	}
	return RemoveJournal(lifecycle.layout)
}

func (lifecycle *Lifecycle) checkpoint(journal *DeploymentJournal, phase Phase) error {
	journal.Phase = phase
	if err := SaveJournal(lifecycle.layout, *journal); err != nil {
		return err
	}
	return lifecycle.injectCrash(phase)
}

func (lifecycle *Lifecycle) injectCrash(phase Phase) error {
	if lifecycle.failAfterPhase == phase {
		return fmt.Errorf("%w after %s", ErrInjectedDeploymentCrash, phase)
	}
	return nil
}

func (lifecycle *Lifecycle) foregroundFor(journal *DeploymentJournal) *ForegroundFallback {
	if journal.Manager != ManagerForeground || journal.Desired == nil {
		return nil
	}
	return &ForegroundFallback{
		Required:   true,
		Reason:     "user_service_manager_unavailable",
		Command:    []string{journal.Desired.BinaryPath, "serve", "--state-dir", lifecycle.layout.StateDir},
		Supervised: true,
	}
}

func (lifecycle *Lifecycle) resultForState(state DeploymentState, foreground *ForegroundFallback, transactionID string) ApplyResult {
	status := "active"
	if state.Status == StatusForeground {
		status = "foreground_required"
	}
	return ApplyResult{Status: status, State: state, Foreground: foreground, TransactionID: transactionID}
}

func applyPhaseReached(current, target Phase) bool {
	order := []Phase{
		PhasePlanned,
		PhaseArtifactStaged,
		PhaseInstanceReady,
		PhasePriorServiceStopped,
		PhaseDefinitionInstalled,
		PhaseActivated,
		PhaseHealthVerified,
		PhaseCommitting,
		PhaseStateSaved,
	}
	currentRank, targetRank := -1, -1
	for index, phase := range order {
		if current == phase {
			currentRank = index
		}
		if target == phase {
			targetRank = index
		}
	}
	return currentRank >= targetRank && targetRank >= 0
}

func rollbackPhaseReached(current, target Phase) bool {
	order := []Phase{
		PhasePlanned,
		PhasePriorServiceStopped,
		PhaseDefinitionInstalled,
		PhaseActivated,
		PhaseHealthVerified,
		PhaseCommitting,
		PhaseStateSaved,
	}
	currentRank, targetRank := -1, -1
	for index, phase := range order {
		if current == phase {
			currentRank = index
		}
		if target == phase {
			targetRank = index
		}
	}
	return currentRank >= targetRank && targetRank >= 0
}

func uninstallPhaseReached(current, target Phase) bool {
	order := []Phase{
		PhasePlanned,
		PhasePriorServiceStopped,
		PhaseDefinitionRemoved,
		PhaseRemovingArtifacts,
		PhaseArtifactsRemoved,
		PhaseCommitting,
		PhaseStateSaved,
	}
	currentRank, targetRank := -1, -1
	for index, phase := range order {
		if current == phase {
			currentRank = index
		}
		if target == phase {
			targetRank = index
		}
	}
	return currentRank >= targetRank && targetRank >= 0
}

func sameDeploymentState(first, second DeploymentState) bool {
	if first.StateVersion != second.StateVersion || first.Generation != second.Generation || first.Status != second.Status ||
		first.Manager != second.Manager || first.StateDir != second.StateDir || first.ServiceDefinition != second.ServiceDefinition {
		return false
	}
	return sameInstalledRelease(first.Active, second.Active) && sameInstalledRelease(first.Previous, second.Previous)
}

func sameInstalledRelease(first, second *InstalledRelease) bool {
	if first == nil || second == nil {
		return first == nil && second == nil
	}
	return *first == *second
}
