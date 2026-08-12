//go:build darwin || linux

package deployment

import (
	"strings"
	"testing"
)

func FuzzDeploymentPathGrammar(f *testing.F) {
	f.Add("/home/alice", "/home/alice/deployment", "/home/alice/state")
	f.Add("/", "/opt/jat/deployment", "/var/lib/jat")
	f.Add("/home/alice", "/home/alice-sibling/deployment", "/home/alice/../state")
	f.Add(string([]byte{'/', 'h', 0, 'm', 'e'}), "/tmp//deployment", "relative/state")
	f.Add("sshserver", "LICENSE", "name with spaces")
	f.Add(".", "..", "nested/artifact")
	f.Add(string([]byte{'n', 'a', 'm', 'e', 0}), strings.Repeat("a", 129), `backslash\name`)

	f.Fuzz(func(t *testing.T, homeDir, installRoot, stateDir string) {
		if len(homeDir) > 4096 || len(installRoot) > 4096 || len(stateDir) > 4096 {
			return
		}
		for _, candidate := range []string{homeDir, installRoot, stateDir} {
			firstNameErr := validateArtifactName(candidate)
			secondNameErr := validateArtifactName(candidate)
			wantName := exactArtifactName(candidate)
			if (firstNameErr == nil) != wantName || (secondNameErr == nil) != wantName {
				t.Fatalf("artifact-name acceptance first=%v second=%v want=%v for %q", firstNameErr == nil, secondNameErr == nil, wantName, candidate)
			}

			firstErr := validateAbsoluteCanonicalPath(candidate)
			secondErr := validateAbsoluteCanonicalPath(candidate)
			want := exactDeploymentCanonicalPath(candidate)
			if (firstErr == nil) != want || (secondErr == nil) != want {
				t.Fatalf("canonical-path acceptance first=%v second=%v want=%v for %q", firstErr == nil, secondErr == nil, want, candidate)
			}
			if canonicalAbsolutePath(candidate) != want {
				t.Fatalf("persisted canonical-path acceptance differs for %q", candidate)
			}
		}

		firstDescendantErr := requireStrictDescendant(homeDir, installRoot, "install root")
		secondDescendantErr := requireStrictDescendant(homeDir, installRoot, "install root")
		if (firstDescendantErr == nil) != (secondDescendantErr == nil) {
			t.Fatal("strict-descendant acceptance changed across identical input")
		}
		if exactDeploymentCanonicalPath(homeDir) && exactDeploymentCanonicalPath(installRoot) {
			want := exactStrictDescendant(homeDir, installRoot)
			if (firstDescendantErr == nil) != want {
				t.Fatalf("strict-descendant acceptance=%v want=%v for parent=%q child=%q", firstDescendantErr == nil, want, homeDir, installRoot)
			}
		}

		first, firstErr := NewLayout(homeDir, installRoot, stateDir)
		second, secondErr := NewLayout(homeDir, installRoot, stateDir)
		wantOK := exactDeploymentCanonicalPath(homeDir) &&
			exactStrictDescendant(homeDir, installRoot) && exactStrictDescendant(homeDir, stateDir)
		if (firstErr == nil) != wantOK || (secondErr == nil) != wantOK {
			t.Fatalf("layout acceptance first=%v second=%v want=%v", firstErr == nil, secondErr == nil, wantOK)
		}
		if !wantOK {
			return
		}
		want := Layout{
			HomeDir: homeDir, InstallRoot: installRoot, StateDir: stateDir,
			VersionsDir: installRoot + "/versions", StatePath: installRoot + "/deployment.json",
			JournalPath: installRoot + "/deployment-journal.json", LockPath: installRoot + "/.deployment.lock",
		}
		if first != want || second != want {
			t.Fatalf("derived layout differs from exact grammar: first=%+v second=%+v want=%+v", first, second, want)
		}
	})
}

func exactArtifactName(value string) bool {
	return value != "" && value != "." && value != ".." && len(value) <= 128 &&
		strings.IndexByte(value, 0) < 0 && !strings.Contains(value, "/")
}

func exactDeploymentCanonicalPath(value string) bool {
	if value == "" || value[0] != '/' || strings.IndexByte(value, 0) >= 0 {
		return false
	}
	if value == "/" {
		return true
	}
	if strings.HasSuffix(value, "/") || strings.Contains(value, "//") {
		return false
	}
	for _, component := range strings.Split(value[1:], "/") {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	return true
}

func exactStrictDescendant(parent, child string) bool {
	if !exactDeploymentCanonicalPath(parent) || !exactDeploymentCanonicalPath(child) || parent == child {
		return false
	}
	if parent == "/" {
		return child != "/"
	}
	return strings.HasPrefix(child, parent+"/")
}
