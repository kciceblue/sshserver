//go:build darwin || linux

package releasebundle

import (
	"bytes"
	"strings"
	"testing"
)

func FuzzInstallCommandInput(f *testing.F) {
	f.Add("https://downloads.example.test/releases/v1.2.3/install.sh", []byte("#!/bin/sh\n"))
	f.Add("/dev/tty", []byte("/usr/bin:/bin"))
	f.Fuzz(func(t *testing.T, installerURL string, installerPayload []byte) {
		if len(installerURL) > 4096 || len(installerPayload) > maxInstallerBytes+1 {
			return
		}
		first, firstErr := InstallCommand(installerURL, installerPayload)
		second, secondErr := InstallCommand(installerURL, installerPayload)
		if (firstErr == nil) != (secondErr == nil) || !bytes.Equal(first, second) {
			t.Fatalf("install-command parser is nondeterministic: first_error=%v second_error=%v", firstErr, secondErr)
		}
		if firstErr == nil {
			if len(first) == 0 || !bytes.HasSuffix(first, []byte("\n")) || bytes.Count(first, []byte("\n")) != 1 || bytes.IndexByte(first, 0) >= 0 {
				t.Fatal("accepted install-command inputs produced a noncanonical command")
			}
		}

		for _, options := range []installerRenderOptions{
			{
				ToolPath: string(installerPayload), TTYReadPath: "/dev/tty", TTYWritePath: "/dev/tty",
				EnvPath: "/usr/bin/env", ShellPath: "/bin/sh",
			},
			{
				ToolPath: "/usr/bin:/bin", TTYReadPath: installerURL, TTYWritePath: string(installerPayload),
				EnvPath: installerURL, ShellPath: string(installerPayload),
			},
		} {
			firstOptionsErr := validateInstallerRenderOptions(options)
			secondOptionsErr := validateInstallerRenderOptions(options)
			wantOptions := exactInstallerRenderOptions(options)
			if (firstOptionsErr == nil) != wantOptions || (secondOptionsErr == nil) != wantOptions {
				t.Fatalf("installer path grammar first=%v second=%v want=%v", firstOptionsErr == nil, secondOptionsErr == nil, wantOptions)
			}
		}
	})
}

func exactInstallerRenderOptions(options installerRenderOptions) bool {
	if options.ToolPath == "" || options.TTYReadPath == "" || options.TTYWritePath == "" || options.EnvPath == "" || options.ShellPath == "" {
		return false
	}
	for _, candidate := range strings.Split(options.ToolPath, ":") {
		if !exactInstallerCanonicalPath(candidate) {
			return false
		}
	}
	for _, candidate := range []string{options.TTYReadPath, options.TTYWritePath, options.EnvPath, options.ShellPath} {
		if !exactInstallerCanonicalPath(candidate) {
			return false
		}
	}
	return true
}

func exactInstallerCanonicalPath(value string) bool {
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
