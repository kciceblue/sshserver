//go:build darwin || linux

package releasebundle

import (
	"bytes"
	"testing"
)

func FuzzInstallCommandInput(f *testing.F) {
	f.Add("https://downloads.example.test/releases/v1.2.3/install.sh", []byte("#!/bin/sh\n"))
	f.Fuzz(func(t *testing.T, installerURL string, installerPayload []byte) {
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
	})
}
