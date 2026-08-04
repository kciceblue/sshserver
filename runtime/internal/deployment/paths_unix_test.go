//go:build darwin || linux

package deployment

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPrepareLayoutCreatesOwnerOnlySeparatedRoots(t *testing.T) {
	home := secureTestHome(t)
	layout, err := NewLayout(home, filepath.Join(home, "data", "deployment"), filepath.Join(home, "state", "server"))
	if err != nil {
		t.Fatal(err)
	}
	if err := PrepareLayout(layout); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{layout.InstallRoot, layout.VersionsDir, layout.StateDir} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("%s mode = %v", path, info.Mode())
		}
	}
	versionDir, err := PrepareVersionDirectory(layout, "v1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	binary, err := layout.BinaryPath("v1.2.3", Target{OS: runtime.GOOS, Architecture: runtime.GOARCH})
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(binary) != versionDir {
		t.Fatalf("binary path %q not in version directory %q", binary, versionDir)
	}
}

func TestLayoutRejectsEscapesAndUnsupportedTargets(t *testing.T) {
	home := secureTestHome(t)
	for _, test := range []struct {
		name    string
		install string
		state   string
	}{
		{name: "install equals home", install: home, state: filepath.Join(home, "state")},
		{name: "install escapes", install: filepath.Dir(home), state: filepath.Join(home, "state")},
		{name: "state escapes", install: filepath.Join(home, "install"), state: filepath.Dir(home)},
		{name: "noncanonical", install: home + "/data/../install", state: filepath.Join(home, "state")},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewLayout(home, test.install, test.state); err == nil {
				t.Fatal("unsafe layout unexpectedly accepted")
			}
		})
	}
	layout, err := NewLayout(home, filepath.Join(home, "install"), filepath.Join(home, "state"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := layout.BinaryPath("v1.2.3", Target{OS: "freebsd", Architecture: "amd64"}); err == nil {
		t.Fatal("unsupported target unexpectedly accepted")
	}
	for _, release := range []string{"latest", "stable", "current", "main", "nightly", "v1", "v1.2.3+build"} {
		if _, err := layout.VersionDir(release); err == nil {
			t.Fatalf("non-immutable release %q unexpectedly accepted", release)
		}
	}
}

func TestPrepareLayoutRejectsUnsafeComponents(t *testing.T) {
	home := secureTestHome(t)
	for _, test := range []struct {
		name  string
		setup func(string) error
		want  string
	}{
		{name: "symlink", setup: func(path string) error { return os.Symlink(filepath.Join(home, "elsewhere"), path) }, want: "not a directory"},
		{name: "broad permissions", setup: func(path string) error {
			if err := os.Mkdir(path, 0o700); err != nil {
				return err
			}
			return os.Chmod(path, 0o777)
		}, want: "writable"},
		{name: "regular file", setup: func(path string) error { return os.WriteFile(path, []byte("x"), 0o600) }, want: "not a directory"},
	} {
		t.Run(test.name, func(t *testing.T) {
			component := filepath.Join(home, "unsafe-"+test.name)
			if err := test.setup(component); err != nil {
				t.Fatal(err)
			}
			layout, err := NewLayout(home, filepath.Join(component, "install"), filepath.Join(home, "state-"+test.name))
			if err != nil {
				t.Fatal(err)
			}
			if err := PrepareLayout(layout); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func secureTestHome(t *testing.T) string {
	t.Helper()
	userHome, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	physicalHome, err := filepath.EvalSymlinks(userHome)
	if err != nil {
		t.Fatal(err)
	}
	home, err := os.MkdirTemp(physicalHome, ".sshserver-deployment-test-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	return home
}
