package deployment

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeploymentStateAndJournalRoundTripCanonicalBytes(t *testing.T) {
	layout := testLayout(t)
	active := testInstalledRelease(t, layout, "v1.2.3", "a")
	state := DeploymentState{
		StateVersion:      DeploymentStateVersion,
		Generation:        1,
		Status:            StatusActive,
		Manager:           ManagerSystemd,
		StateDir:          layout.StateDir,
		ServiceDefinition: filepath.Join(layout.HomeDir, ".config", "systemd", "user", "com.kciceblue.sshserver.service"),
		Active:            &active,
	}
	if err := SaveState(layout, state); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadState(layout)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Active.ManifestSHA256 != active.ManifestSHA256 || loaded.Generation != 1 {
		t.Fatalf("loaded state = %+v", loaded)
	}
	journal := DeploymentJournal{
		StateVersion:      DeploymentStateVersion,
		TransactionID:     strings.Repeat("1", 32),
		Operation:         OperationApply,
		Phase:             PhaseArtifactStaged,
		Manager:           ManagerSystemd,
		ServiceDefinition: state.ServiceDefinition,
		SourcePath:        filepath.Join(layout.HomeDir, "download", "sshserver"),
		LicenseSourcePath: filepath.Join(layout.HomeDir, "download", "LICENSE"),
		NoticeSourcePath:  filepath.Join(layout.HomeDir, "download", "NOTICE"),
		Desired:           &active,
		PriorState:        &state,
	}
	if err := SaveJournal(layout, journal); err != nil {
		t.Fatal(err)
	}
	loadedJournal, err := LoadJournal(layout)
	if err != nil {
		t.Fatal(err)
	}
	if loadedJournal.TransactionID != journal.TransactionID || loadedJournal.Phase != PhaseArtifactStaged {
		t.Fatalf("loaded journal = %+v", loadedJournal)
	}
	if err := RemoveJournal(layout); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadJournal(layout); !errors.Is(err, ErrNoDeploymentJournal) {
		t.Fatalf("removed journal error = %v", err)
	}
}

func TestDeploymentMetadataRejectsTampering(t *testing.T) {
	layout := testLayout(t)
	release := testInstalledRelease(t, layout, "v1.2.3", "a")
	state := DeploymentState{
		StateVersion: DeploymentStateVersion,
		Generation:   1,
		Status:       StatusForeground,
		Manager:      ManagerForeground,
		StateDir:     layout.StateDir,
		Active:       &release,
	}
	if err := SaveState(layout, state); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(layout.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		payload []byte
		mode    os.FileMode
		want    string
	}{
		{name: "noncanonical", payload: append([]byte(" "), original...), mode: 0o600, want: "canonical"},
		{name: "trailing", payload: append(append([]byte(nil), original...), []byte("{}")...), mode: 0o600, want: "trailing"},
		{name: "unknown", payload: []byte(strings.Replace(string(original), "\n}", ",\n  \"future\": true\n}", 1)), mode: 0o600, want: "unknown field"},
		{name: "broad mode", payload: original, mode: 0o644, want: "owner-only"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(layout.StatePath, test.payload, test.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(layout.StatePath, test.mode); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadState(layout); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestDeploymentStateRejectsIncompatibleAndMismatchedRecords(t *testing.T) {
	layout := testLayout(t)
	release := testInstalledRelease(t, layout, "v1.2.3", "a")
	valid := DeploymentState{
		StateVersion: DeploymentStateVersion,
		Generation:   1,
		Status:       StatusForeground,
		Manager:      ManagerForeground,
		StateDir:     layout.StateDir,
		Active:       &release,
	}
	for _, test := range []struct {
		name   string
		mutate func(*DeploymentState)
		want   string
	}{
		{name: "generation", mutate: func(value *DeploymentState) { value.Generation = 0 }, want: "generation"},
		{name: "wrong state", mutate: func(value *DeploymentState) { value.StateDir += "-other" }, want: "state directory"},
		{name: "wrong binary", mutate: func(value *DeploymentState) { value.Active.BinaryPath += "-other" }, want: "binary path"},
		{name: "schema", mutate: func(value *DeploymentState) { value.Active.StorageSchema = "2" }, want: "incompatible"},
		{name: "foreground service", mutate: func(value *DeploymentState) { value.ServiceDefinition = "/tmp/unit" }, want: "foreground"},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := valid
			active := release
			value.Active = &active
			test.mutate(&value)
			if err := value.Validate(layout); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func testLayout(t *testing.T) Layout {
	t.Helper()
	home := secureTestHome(t)
	layout, err := NewLayout(home, filepath.Join(home, "deployment"), filepath.Join(home, "state"))
	if err != nil {
		t.Fatal(err)
	}
	if err := PrepareLayout(layout); err != nil {
		t.Fatal(err)
	}
	return layout
}

func testInstalledRelease(t *testing.T, layout Layout, version, digit string) InstalledRelease {
	t.Helper()
	manifest := testReleaseManifest()
	manifest.Release = version
	manifest.Artifacts = append([]ReleaseArtifact(nil), manifest.Artifacts...)
	manifest.ReleaseFiles = append([]ReleaseFile(nil), manifest.ReleaseFiles...)
	refreshTestBuildIdentities(&manifest)
	for index := range manifest.Artifacts {
		manifest.Artifacts[index].URL = strings.Replace(manifest.Artifacts[index].URL, "/v1.0.0-test.1/", "/"+version+"/", 1)
	}
	for index := range manifest.ReleaseFiles {
		manifest.ReleaseFiles[index].URL = strings.Replace(manifest.ReleaseFiles[index].URL, "/v1.0.0-test.1/", "/"+version+"/", 1)
	}
	release, err := InstalledFromManifest(layout, manifest, strings.Repeat(digit, 64), Target{OS: "linux", Architecture: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	return release
}
