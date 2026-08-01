package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitOutputContainsNoSecretAndIsIdempotent(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	var first, second bytes.Buffer
	runner := Runner{Stdout: &first, Stderr: &bytes.Buffer{}}
	args := []string{"init", "--state-dir", stateDir, "--listen", "127.0.0.1:37421"}
	if code := runner.Run(context.Background(), args); code != 0 {
		t.Fatalf("first init exit = %d", code)
	}
	runner.Stdout = &second
	if code := runner.Run(context.Background(), args); code != 0 {
		t.Fatalf("second init exit = %d", code)
	}
	for _, output := range []string{first.String(), second.String()} {
		if strings.Contains(output, "secret") || strings.Contains(output, "token") || strings.Contains(output, "grant") {
			t.Fatalf("init output exposes a credential field: %s", output)
		}
	}
	var firstBody, secondBody map[string]any
	if err := json.Unmarshal(first.Bytes(), &firstBody); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(second.Bytes(), &secondBody); err != nil {
		t.Fatal(err)
	}
	if firstBody["instance_id"] != secondBody["instance_id"] || firstBody["vault_id"] != secondBody["vault_id"] {
		t.Fatal("repeated init changed identity")
	}
}

func TestRenderServiceRejectsRelativePaths(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := (Runner{Stdout: &stdout, Stderr: &stderr}).Run(context.Background(), []string{
		"service", "render", "--platform", "linux", "--binary", "relative", "--state-dir", "/tmp/state",
	})
	if code == 0 || !strings.Contains(stderr.String(), "absolute") {
		t.Fatalf("relative binary result: code=%d stderr=%q", code, stderr.String())
	}
}

func TestHealthRejectsResponseLargerThanLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = writer.Write([]byte(`{"status":"ok","protocol_version":"1"}` + strings.Repeat(" ", 1025)))
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	code := (Runner{Stdout: &stdout, Stderr: &stderr}).Run(context.Background(), []string{
		"health", "--address", strings.TrimPrefix(server.URL, "http://"),
	})
	if code == 0 || !strings.Contains(stderr.String(), "exceeds 1024 bytes") {
		t.Fatalf("oversized health result: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}
