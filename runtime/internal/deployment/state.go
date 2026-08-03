package deployment

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/kciceblue/sshserver/runtime/internal/config"
)

const (
	DeploymentStateVersion = 1
	maxDeploymentFileBytes = 64 * 1024
)

var transactionIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

var (
	ErrNoDeploymentState   = errors.New("deployment state does not exist")
	ErrNoDeploymentJournal = errors.New("deployment journal does not exist")
)

type DeploymentStatus string

const (
	StatusActive      DeploymentStatus = "active"
	StatusForeground  DeploymentStatus = "foreground"
	StatusUninstalled DeploymentStatus = "uninstalled"
)

type ManagerKind string

const (
	ManagerNone       ManagerKind = "none"
	ManagerForeground ManagerKind = "foreground"
	ManagerSystemd    ManagerKind = "systemd-user"
	ManagerLaunchd    ManagerKind = "launchd-user"
)

type InstalledRelease struct {
	Release         string `json:"release"`
	SourceRevision  string `json:"source_revision"`
	BuildToolchain  string `json:"build_toolchain"`
	BuildIdentity   string `json:"build_identity"`
	ManifestSHA256  string `json:"manifest_sha256"`
	ProtocolVersion string `json:"protocol_version"`
	StorageSchema   string `json:"storage_schema"`
	OS              string `json:"os"`
	Architecture    string `json:"architecture"`
	BinaryPath      string `json:"binary_path"`
	BinaryBytes     int64  `json:"binary_bytes"`
	BinarySHA256    string `json:"binary_sha256"`
	LicenseBytes    int64  `json:"license_bytes"`
	LicenseSHA256   string `json:"license_sha256"`
	NoticeBytes     int64  `json:"notice_bytes"`
	NoticeSHA256    string `json:"notice_sha256"`
}

func InstalledFromManifest(layout Layout, manifest ReleaseManifest, manifestSHA256 string, target Target) (InstalledRelease, error) {
	if err := manifest.Validate(); err != nil {
		return InstalledRelease{}, err
	}
	if !hexDigestPattern.MatchString(manifestSHA256) {
		return InstalledRelease{}, errors.New("installed manifest digest must be lowercase SHA-256")
	}
	artifact, err := manifest.Artifact(target)
	if err != nil {
		return InstalledRelease{}, err
	}
	binaryPath, err := layout.BinaryPath(manifest.Release, target)
	if err != nil {
		return InstalledRelease{}, err
	}
	release := InstalledRelease{
		Release:         manifest.Release,
		SourceRevision:  manifest.SourceRevision,
		BuildToolchain:  manifest.BuildToolchain,
		BuildIdentity:   artifact.BuildIdentity,
		ManifestSHA256:  manifestSHA256,
		ProtocolVersion: manifest.ProtocolVersion,
		StorageSchema:   manifest.StorageSchema,
		OS:              target.OS,
		Architecture:    target.Architecture,
		BinaryPath:      binaryPath,
		BinaryBytes:     artifact.Bytes,
		BinarySHA256:    artifact.SHA256,
		LicenseBytes:    manifest.ReleaseFiles[0].Bytes,
		LicenseSHA256:   manifest.ReleaseFiles[0].SHA256,
		NoticeBytes:     manifest.ReleaseFiles[1].Bytes,
		NoticeSHA256:    manifest.ReleaseFiles[1].SHA256,
	}
	if err := release.validate(layout); err != nil {
		return InstalledRelease{}, err
	}
	return release, nil
}

func (release InstalledRelease) validate(layout Layout) error {
	if !releaseIDPattern.MatchString(release.Release) || release.Release == "latest" {
		return errors.New("installed release identifier is invalid")
	}
	if !sourceRevisionPattern.MatchString(release.SourceRevision) || !toolchainPattern.MatchString(release.BuildToolchain) ||
		!hexDigestPattern.MatchString(release.BuildIdentity) || !hexDigestPattern.MatchString(release.ManifestSHA256) ||
		!hexDigestPattern.MatchString(release.BinarySHA256) {
		return errors.New("installed release identity is invalid")
	}
	if release.ProtocolVersion != "1" || release.StorageSchema != "1" {
		return errors.New("installed release is incompatible with V1")
	}
	target := Target{OS: release.OS, Architecture: release.Architecture}
	wantPath, err := layout.BinaryPath(release.Release, target)
	if err != nil {
		return err
	}
	if release.BinaryPath != wantPath || !filepath.IsAbs(release.BinaryPath) || filepath.Clean(release.BinaryPath) != release.BinaryPath {
		return errors.New("installed binary path does not match the immutable release layout")
	}
	if release.BinaryBytes <= 0 || release.BinaryBytes > maxArtifactBytes {
		return errors.New("installed binary size is invalid")
	}
	if release.LicenseBytes <= 0 || release.LicenseBytes > maxReleaseFileBytes || release.NoticeBytes <= 0 || release.NoticeBytes > maxReleaseFileBytes ||
		!hexDigestPattern.MatchString(release.LicenseSHA256) || !hexDigestPattern.MatchString(release.NoticeSHA256) {
		return errors.New("installed release support-file metadata is invalid")
	}
	return nil
}

func (release InstalledRelease) SupportFilePath(layout Layout, name string) (string, error) {
	if name != "LICENSE" && name != "NOTICE" {
		return "", errors.New("release support file must be LICENSE or NOTICE")
	}
	versionDir, err := layout.VersionDir(release.Release)
	if err != nil {
		return "", err
	}
	return filepath.Join(versionDir, name), nil
}

type DeploymentState struct {
	StateVersion      int               `json:"state_version"`
	Generation        uint64            `json:"generation"`
	Status            DeploymentStatus  `json:"status"`
	Manager           ManagerKind       `json:"manager"`
	StateDir          string            `json:"state_dir"`
	ServiceDefinition string            `json:"service_definition"`
	Active            *InstalledRelease `json:"active"`
	Previous          *InstalledRelease `json:"previous"`
}

func (state DeploymentState) Validate(layout Layout) error {
	if state.StateVersion != DeploymentStateVersion || state.Generation == 0 {
		return errors.New("deployment state version or generation is invalid")
	}
	if state.StateDir != layout.StateDir {
		return errors.New("deployment state directory does not match the protected layout")
	}
	if state.Active != nil {
		if err := state.Active.validate(layout); err != nil {
			return err
		}
	}
	if state.Previous != nil {
		if err := state.Previous.validate(layout); err != nil {
			return err
		}
	}
	if state.Active != nil && state.Previous != nil && state.Active.ManifestSHA256 == state.Previous.ManifestSHA256 {
		return errors.New("active and previous releases must be distinct")
	}
	switch state.Status {
	case StatusActive:
		if state.Active == nil || (state.Manager != ManagerSystemd && state.Manager != ManagerLaunchd) ||
			state.ServiceDefinition == "" || !canonicalAbsolutePath(state.ServiceDefinition) {
			return errors.New("active deployment state lacks a user service manager and definition")
		}
		if err := requireStrictDescendant(layout.HomeDir, state.ServiceDefinition, "service definition"); err != nil {
			return err
		}
		if (state.Manager == ManagerSystemd) != (state.Active.OS == "linux") ||
			(state.Manager == ManagerLaunchd) != (state.Active.OS == "darwin") {
			return errors.New("deployment service manager does not match the active platform")
		}
	case StatusForeground:
		if state.Active == nil || state.Manager != ManagerForeground || state.ServiceDefinition != "" {
			return errors.New("foreground deployment state is inconsistent")
		}
	case StatusUninstalled:
		if state.Active != nil || state.Manager != ManagerNone || state.ServiceDefinition != "" {
			return errors.New("uninstalled deployment state is inconsistent")
		}
	default:
		return errors.New("deployment status is invalid")
	}
	return nil
}

type Operation string

const (
	OperationApply     Operation = "apply"
	OperationRollback  Operation = "rollback"
	OperationUninstall Operation = "uninstall"
)

type Phase string

const (
	PhasePlanned             Phase = "planned"
	PhaseArtifactStaged      Phase = "artifact_staged"
	PhaseInstanceReady       Phase = "instance_ready"
	PhasePriorServiceStopped Phase = "prior_service_stopped"
	PhaseDefinitionInstalled Phase = "definition_installed"
	PhaseActivated           Phase = "activated"
	PhaseHealthVerified      Phase = "health_verified"
	PhaseDefinitionRemoved   Phase = "definition_removed"
	PhaseRemovingArtifacts   Phase = "removing_artifacts"
	PhaseArtifactsRemoved    Phase = "artifacts_removed"
	PhaseCommitting          Phase = "committing"
	PhaseStateSaved          Phase = "state_saved"
)

type DeploymentJournal struct {
	StateVersion      int               `json:"state_version"`
	TransactionID     string            `json:"transaction_id"`
	Operation         Operation         `json:"operation"`
	Phase             Phase             `json:"phase"`
	Manager           ManagerKind       `json:"manager"`
	ServiceDefinition string            `json:"service_definition"`
	SourcePath        string            `json:"source_path"`
	LicenseSourcePath string            `json:"license_source_path"`
	NoticeSourcePath  string            `json:"notice_source_path"`
	Desired           *InstalledRelease `json:"desired"`
	PriorState        *DeploymentState  `json:"prior_state"`
}

func (journal DeploymentJournal) Validate(layout Layout) error {
	if journal.StateVersion != DeploymentStateVersion || !transactionIDPattern.MatchString(journal.TransactionID) {
		return errors.New("deployment journal identity is invalid")
	}
	if journal.Desired != nil {
		if err := journal.Desired.validate(layout); err != nil {
			return err
		}
	}
	if journal.PriorState != nil {
		if err := journal.PriorState.Validate(layout); err != nil {
			return fmt.Errorf("validate prior deployment state: %w", err)
		}
	}
	allowed := map[Operation]map[Phase]bool{
		OperationApply: {
			PhasePlanned: true, PhaseArtifactStaged: true, PhaseInstanceReady: true,
			PhasePriorServiceStopped: true, PhaseDefinitionInstalled: true, PhaseActivated: true,
			PhaseHealthVerified: true, PhaseCommitting: true, PhaseStateSaved: true,
		},
		OperationRollback: {
			PhasePlanned: true, PhasePriorServiceStopped: true, PhaseDefinitionInstalled: true,
			PhaseActivated: true, PhaseHealthVerified: true, PhaseCommitting: true, PhaseStateSaved: true,
		},
		OperationUninstall: {
			PhasePlanned: true, PhasePriorServiceStopped: true, PhaseDefinitionRemoved: true,
			PhaseRemovingArtifacts: true, PhaseArtifactsRemoved: true, PhaseCommitting: true, PhaseStateSaved: true,
		},
	}
	if !allowed[journal.Operation][journal.Phase] {
		return errors.New("deployment journal operation or phase is invalid")
	}
	if (journal.Operation == OperationApply || journal.Operation == OperationRollback) != (journal.Desired != nil) {
		return errors.New("deployment journal desired release is inconsistent with its operation")
	}
	if journal.Operation == OperationApply {
		if !canonicalAbsolutePath(journal.SourcePath) || !canonicalAbsolutePath(journal.LicenseSourcePath) || !canonicalAbsolutePath(journal.NoticeSourcePath) {
			return errors.New("apply journal requires canonical artifact and release-file source paths")
		}
		if journal.SourcePath == journal.LicenseSourcePath || journal.SourcePath == journal.NoticeSourcePath || journal.LicenseSourcePath == journal.NoticeSourcePath {
			return errors.New("apply journal input paths must be distinct")
		}
	} else if journal.SourcePath != "" || journal.LicenseSourcePath != "" || journal.NoticeSourcePath != "" {
		return errors.New("only apply journals may retain release input paths")
	}
	if journal.Desired != nil {
		switch journal.Manager {
		case ManagerForeground:
			if journal.ServiceDefinition != "" {
				return errors.New("foreground journal must not contain a service definition")
			}
		case ManagerSystemd:
			if journal.Desired.OS != "linux" || !canonicalAbsolutePath(journal.ServiceDefinition) {
				return errors.New("systemd journal is inconsistent with the desired release")
			}
		case ManagerLaunchd:
			if journal.Desired.OS != "darwin" || !canonicalAbsolutePath(journal.ServiceDefinition) {
				return errors.New("launchd journal is inconsistent with the desired release")
			}
		default:
			return errors.New("deployment journal manager is invalid")
		}
		if journal.ServiceDefinition != "" {
			if err := requireStrictDescendant(layout.HomeDir, journal.ServiceDefinition, "service definition"); err != nil {
				return err
			}
		}
	} else if journal.Manager != ManagerNone && (journal.PriorState == nil || journal.Manager != journal.PriorState.Manager) {
		return errors.New("uninstall journal manager does not match its prior state")
	}
	if journal.Operation == OperationRollback && (journal.PriorState == nil || journal.PriorState.Active == nil) {
		return errors.New("rollback journal requires an active prior state")
	}
	if journal.Operation == OperationUninstall && journal.PriorState == nil {
		return errors.New("uninstall journal requires prior deployment state")
	}
	return nil
}

func LoadState(layout Layout) (DeploymentState, error) {
	var state DeploymentState
	if err := loadCanonicalDeploymentJSON(layout.StatePath, &state); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return DeploymentState{}, ErrNoDeploymentState
		}
		return DeploymentState{}, fmt.Errorf("load deployment state: %w", err)
	}
	if err := state.Validate(layout); err != nil {
		return DeploymentState{}, err
	}
	return state, nil
}

func SaveState(layout Layout, state DeploymentState) error {
	if err := state.Validate(layout); err != nil {
		return err
	}
	return saveCanonicalDeploymentJSON(layout.StatePath, state)
}

func LoadJournal(layout Layout) (DeploymentJournal, error) {
	var journal DeploymentJournal
	if err := loadCanonicalDeploymentJSON(layout.JournalPath, &journal); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return DeploymentJournal{}, ErrNoDeploymentJournal
		}
		return DeploymentJournal{}, fmt.Errorf("load deployment journal: %w", err)
	}
	if err := journal.Validate(layout); err != nil {
		return DeploymentJournal{}, err
	}
	return journal, nil
}

func SaveJournal(layout Layout, journal DeploymentJournal) error {
	if err := journal.Validate(layout); err != nil {
		return err
	}
	return saveCanonicalDeploymentJSON(layout.JournalPath, journal)
}

func RemoveJournal(layout Layout) error {
	return removeDeploymentFile(layout.JournalPath)
}

func RemoveState(layout Layout) error {
	return removeDeploymentFile(layout.StatePath)
}

func loadCanonicalDeploymentJSON(path string, destination any) error {
	payload, err := readDeploymentFile(path, maxDeploymentFileBytes)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("deployment metadata contains trailing data")
	}
	canonical, err := canonicalDeploymentJSON(destination)
	if err != nil {
		return err
	}
	if !bytes.Equal(payload, canonical) {
		return errors.New("deployment metadata is not in canonical byte form")
	}
	return nil
}

func saveCanonicalDeploymentJSON(path string, value any) error {
	payload, err := canonicalDeploymentJSON(value)
	if err != nil {
		return err
	}
	return config.WriteFileAtomic(path, payload, 0o600)
}

func canonicalDeploymentJSON(value any) ([]byte, error) {
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(payload, '\n'), nil
}

func canonicalAbsolutePath(value string) bool {
	return value != "" && filepath.IsAbs(value) && filepath.Clean(value) == value
}
