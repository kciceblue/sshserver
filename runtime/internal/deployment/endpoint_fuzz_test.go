//go:build darwin || linux

package deployment

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

type deploymentLocationFuzzErrorClass uint8

const (
	deploymentLocationFuzzAccepted deploymentLocationFuzzErrorClass = iota
	deploymentLocationFuzzNotDeployed
	deploymentLocationFuzzFilesystem
)

func FuzzLocateDeploymentExecutable(f *testing.F) {
	for mode := uint8(0); mode < 13; mode++ {
		f.Add(mode, "v1.2.3", "sshserver-linux-amd64")
	}
	f.Fuzz(func(t *testing.T, mode uint8, version, binaryName string) {
		if !deploymentLocationFuzzComponent(version) || !deploymentLocationFuzzComponent(binaryName) {
			return
		}
		mode %= 13
		candidate, resolvedExecutable, physicalHome, installRoot := deploymentLocationFuzzFixture(t, mode, version, binaryName)
		wantLocation, wantClass := exactDeploymentExecutableLocation(mode, resolvedExecutable, physicalHome, installRoot)

		first, firstErr := locateDeploymentExecutable(candidate)
		second, secondErr := locateDeploymentExecutable(candidate)
		firstClass := deploymentLocationFuzzClass(firstErr)
		secondClass := deploymentLocationFuzzClass(secondErr)
		if firstClass != wantClass || secondClass != wantClass {
			t.Fatalf("location class first=%d second=%d want=%d", firstClass, secondClass, wantClass)
		}
		if wantClass == deploymentLocationFuzzAccepted && (first != wantLocation || second != wantLocation) {
			t.Fatalf("location first=%+v second=%+v want=%+v", first, second, wantLocation)
		}
	})
}

func deploymentLocationFuzzComponent(value string) bool {
	return value != "" && value != "." && value != ".." && len(value) <= 128 &&
		utf8.ValidString(value) && !strings.Contains(value, "/") && !strings.ContainsRune(value, 0)
}

func deploymentLocationFuzzFixture(t *testing.T, mode uint8, version, binaryName string) (candidate, resolvedExecutable, physicalHome, installRoot string) {
	t.Helper()
	physicalHome = secureTestHome(t)
	outsideHome := secureTestHome(t)
	t.Setenv("HOME", physicalHome)

	targetHome := physicalHome
	if mode == 4 || mode == 11 {
		targetHome = outsideHome
	}
	versionsLabel := "versions"
	if mode == 3 {
		versionsLabel = "releases"
	}
	installRoot = filepath.Join(targetHome, "deployment")
	versionDir := filepath.Join(installRoot, versionsLabel, version)
	resolvedExecutable = filepath.Join(versionDir, binaryName)

	if mode == 10 {
		detachedVersion := filepath.Join(physicalHome, "detached", version)
		resolvedExecutable = filepath.Join(detachedVersion, binaryName)
		deploymentLocationFuzzWriteExecutable(t, resolvedExecutable)
		versionsDir := filepath.Join(physicalHome, "deployment", "versions")
		if err := os.MkdirAll(versionsDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(versionsDir, 0o700); err != nil {
			t.Fatal(err)
		}
		linkedVersion := filepath.Join(versionsDir, version)
		if err := os.Symlink(detachedVersion, linkedVersion); err != nil {
			t.Fatal(err)
		}
		candidate = filepath.Join(linkedVersion, binaryName)
		return candidate, resolvedExecutable, physicalHome, filepath.Join(physicalHome, "deployment")
	}

	deploymentLocationFuzzWriteExecutable(t, resolvedExecutable)
	candidate = resolvedExecutable
	switch mode {
	case 1:
		aliasDirectory := filepath.Join(physicalHome, "bin")
		if err := os.MkdirAll(aliasDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		candidate = filepath.Join(aliasDirectory, "sshserver")
		if err := os.Symlink(resolvedExecutable, candidate); err != nil {
			t.Fatal(err)
		}
	case 2:
		alias := filepath.Join(physicalHome, "current-version")
		if err := os.Symlink(versionDir, alias); err != nil {
			t.Fatal(err)
		}
		candidate = filepath.Join(alias, binaryName)
	case 5:
		if err := os.Remove(resolvedExecutable); err != nil {
			t.Fatal(err)
		}
		candidate = resolvedExecutable
	case 6:
		candidate = filepath.Join("deployment", "versions", version, binaryName)
	case 7:
		candidate = versionDir + string(filepath.Separator) + ".." + string(filepath.Separator) + version + string(filepath.Separator) + binaryName
	case 8:
		if err := os.Chmod(installRoot, 0o770); err != nil {
			t.Fatal(err)
		}
	case 9:
		if err := os.Chmod(versionDir, 0o770); err != nil {
			t.Fatal(err)
		}
	case 11:
		aliasDirectory := filepath.Join(physicalHome, "bin")
		if err := os.MkdirAll(aliasDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		candidate = filepath.Join(aliasDirectory, "outside-sshserver")
		if err := os.Symlink(resolvedExecutable, candidate); err != nil {
			t.Fatal(err)
		}
	case 12:
		candidate = resolvedExecutable + string([]byte{0})
	}
	return candidate, resolvedExecutable, physicalHome, installRoot
}

func deploymentLocationFuzzWriteExecutable(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Dir(path)
	for range 3 {
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		directory = filepath.Dir(directory)
	}
	if err := os.WriteFile(path, []byte("fuzz executable"), 0o500); err != nil {
		t.Fatal(err)
	}
}

func deploymentLocationFuzzClass(err error) deploymentLocationFuzzErrorClass {
	if err == nil {
		return deploymentLocationFuzzAccepted
	}
	if errors.Is(err, ErrNotDeployedExecutable) {
		return deploymentLocationFuzzNotDeployed
	}
	return deploymentLocationFuzzFilesystem
}

func exactDeploymentExecutableLocation(mode uint8, resolvedExecutable, physicalHome, installRoot string) (deploymentExecutableLocation, deploymentLocationFuzzErrorClass) {
	if mode <= 2 {
		return deploymentExecutableLocation{
			resolvedExecutable: resolvedExecutable,
			physicalHome:       physicalHome,
			installRoot:        installRoot,
		}, deploymentLocationFuzzAccepted
	}
	if mode == 3 || mode == 6 || mode == 7 || mode == 10 || mode == 12 {
		return deploymentExecutableLocation{}, deploymentLocationFuzzNotDeployed
	}
	return deploymentExecutableLocation{}, deploymentLocationFuzzFilesystem
}
