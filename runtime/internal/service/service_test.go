package service

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderServiceDefinitionsAreUserScopedAndSecretFree(t *testing.T) {
	binary := "/Users/example/$HOME/bin/sshserver%stable"
	stateDir := "/Users/example/Library/Application Support/JAT & Sync"
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			payload, err := Render(platform, binary, stateDir)
			if err != nil {
				t.Fatal(err)
			}
			text := string(payload)
			for _, forbidden := range []string{"instance-secret", "Authorization", "Environment=", "--token", "--secret"} {
				if strings.Contains(text, forbidden) {
					t.Fatalf("service definition contains %q", forbidden)
				}
			}
			if !strings.Contains(text, "serve") || !strings.Contains(text, "--state-dir") {
				t.Fatalf("service definition lacks foreground command: %s", text)
			}
			if platform == "darwin" {
				var parsed xmlElement
				if err := xml.Unmarshal(payload, &parsed); err != nil {
					t.Fatalf("invalid plist XML: %v", err)
				}
				if parsed.XMLName.Local != "plist" {
					t.Fatalf("plist root = %q", parsed.XMLName.Local)
				}
				if !strings.Contains(text, "JAT &amp; Sync") {
					t.Fatal("plist path was not XML escaped")
				}
			} else if !strings.Contains(text, "$$HOME") || !strings.Contains(text, "sshserver%%stable") {
				t.Fatal("systemd expansion characters were not escaped")
			}
		})
	}
}

type xmlElement struct {
	XMLName xml.Name
	Text    string       `xml:",chardata"`
	Child   []xmlElement `xml:",any"`
}

func TestRenderRejectsNonCanonicalAndControlPaths(t *testing.T) {
	for _, stateDir := range []string{"/", "/tmp/../state", "/tmp/state\tbad"} {
		if _, err := Render("linux", "/opt/jat/sshserver", stateDir); err == nil {
			t.Fatalf("state directory %q unexpectedly accepted", stateDir)
		}
	}
}

func TestInstallWritesProtectedDefinition(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "units", Label+".service")
	installed, err := Install("linux", "/opt/jat/sshserver", "/var/lib/jat-user", output)
	if err != nil {
		t.Fatal(err)
	}
	if installed != output {
		t.Fatalf("installed path = %q", installed)
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("service mode = %o", info.Mode().Perm())
	}
}

func TestInstallRejectsNonCanonicalOutputPath(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "units") + "/../" + Label + ".service"
	if _, err := Install("linux", "/opt/jat/sshserver", "/var/lib/jat-user", output); err == nil {
		t.Fatal("non-canonical output path unexpectedly accepted")
	}
}
