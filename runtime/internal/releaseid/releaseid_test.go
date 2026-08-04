package releaseid

import (
	"strings"
	"testing"
)

func TestValidAcceptsExactImmutableReleaseVersions(t *testing.T) {
	for _, value := range []string{
		"1.2.3",
		"v1.2.3",
		"2026.08.03",
		"v1.2.3-rc.1",
		"v0.0.0-metadata-test",
		"1.2.3-" + strings.Repeat("a", 58),
	} {
		if !Valid(value) {
			t.Errorf("Valid(%q) = false", value)
		}
	}
}

func TestValidRejectsMovingIncompleteAndUnsafeReleaseNames(t *testing.T) {
	for _, value := range []string{
		"",
		"latest",
		"stable",
		"current",
		"main",
		"nightly",
		"v1",
		"v1.2",
		"v1..2",
		"V1.2.3",
		"v1.2.3-RC1",
		"v1.2.3-rc..1",
		"v1.2.3-rc_1",
		"v1.2.3+build",
		"../v1.2.3",
		"v1.2.3/sshserver",
		"1.2.3-" + strings.Repeat("a", 59),
	} {
		if Valid(value) {
			t.Errorf("Valid(%q) = true", value)
		}
	}
}
