package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/auth"
	"github.com/kciceblue/sshserver/runtime/internal/buildinfo"
	"github.com/kciceblue/sshserver/runtime/internal/config"
	"github.com/kciceblue/sshserver/runtime/internal/instance"
	serverpkg "github.com/kciceblue/sshserver/runtime/internal/server"
)

func TestVersionJSONReportsExactBuildIdentity(t *testing.T) {
	original := buildinfo.EncodedIdentity
	expected := buildinfo.Identity{
		Release:         "v1.2.3",
		SourceRevision:  strings.Repeat("a", 40),
		BuildToolchain:  "go1.25.0",
		BuildIdentity:   strings.Repeat("b", 64),
		ProtocolVersion: "1",
		StorageSchema:   "1",
	}
	encoded, err := buildinfo.Encode(expected)
	if err != nil {
		t.Fatal(err)
	}
	buildinfo.EncodedIdentity = encoded
	t.Cleanup(func() { buildinfo.EncodedIdentity = original })
	var stdout, stderr bytes.Buffer
	code := (Runner{Stdout: &stdout, Stderr: &stderr}).Run(context.Background(), []string{"version", "--format=json"})
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("version code=%d stderr=%q", code, stderr.String())
	}
	var identity buildinfo.Identity
	decoder := json.NewDecoder(&stdout)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&identity); err != nil {
		t.Fatal(err)
	}
	if identity != expected {
		t.Fatalf("identity=%+v want=%+v", identity, expected)
	}
}

func TestDeployStatusReportsUninstalledWithoutMutatingRuntime(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	home, err = filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}
	testHome, err := os.MkdirTemp(home, ".sshserver-cli-deploy-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(testHome) })
	if err := os.Chmod(testHome, 0o700); err != nil {
		t.Fatal(err)
	}
	installRoot := filepath.Join(testHome, "deployment")
	stateDir := filepath.Join(testHome, "state")
	var stdout, stderr bytes.Buffer
	code := (Runner{Stdout: &stdout, Stderr: &stderr}).Run(context.Background(), []string{
		"deploy", "status",
		"--home-dir", testHome,
		"--install-root", installRoot,
		"--state-dir", stateDir,
	})
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("deploy status code=%d stderr=%q", code, stderr.String())
	}
	var result struct {
		Status           string `json:"status"`
		Running          bool   `json:"running"`
		RecoveryRequired bool   `json:"recovery_required"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "uninstalled" || result.Running || result.RecoveryRequired {
		t.Fatalf("deploy status=%+v", result)
	}
	if _, err := os.Lstat(installRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only status created deployment root: %v", err)
	}
}

func TestDeployApplyRequiresExactPinnedInputs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := (Runner{Stdout: &stdout, Stderr: &stderr}).Run(context.Background(), []string{"deploy", "apply"})
	if code == 0 || !strings.Contains(stderr.String(), "requires --manifest") || stdout.Len() != 0 {
		t.Fatalf("deploy apply code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

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

func TestEnrollmentCreateUsesOwnerSocketAndBootstrapsRealHTTPDataPlane(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	testRoot, err := os.MkdirTemp("/tmp", "jat-runtime-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(testRoot) })
	stateDir := filepath.Join(testRoot, "state")
	settings, err := instance.Initialize(context.Background(), stateDir, []string{address})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := instance.OpenForServe(context.Background(), stateDir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- serverpkg.RunWithAdmin(ctx, opened.Settings, opened.Store, opened.Paths) }()
	runtimeStopped := false
	instanceClosed := false
	defer func() {
		cancel()
		if !runtimeStopped {
			select {
			case <-errCh:
			case <-time.After(5 * time.Second):
			}
		}
		if !instanceClosed {
			_ = opened.Close()
		}
	}()
	waitForAdminSocket(t, opened.Paths.AdminSocket, errCh)
	waitForRuntimeHealth(t, address)

	var stdout, stderr bytes.Buffer
	runner := Runner{Stdout: &stdout, Stderr: &stderr}
	if code := runner.Run(context.Background(), []string{"enrollment", "create", "--format=json", "--state-dir", stateDir}); code != 0 {
		t.Fatalf("enrollment create exit=%d stderr=%q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("enrollment stderr=%q", stderr.String())
	}
	var bootstrap struct {
		ProtocolVersion string `json:"protocol_version"`
		InstanceID      string `json:"instance_id"`
		VaultID         string `json:"vault_id"`
		InstanceSecret  string `json:"instance_secret"`
		EnrollmentGrant string `json:"enrollment_grant"`
		ExpiresAt       string `json:"expires_at"`
		LoopbackPort    int    `json:"loopback_port"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &bootstrap); err != nil {
		t.Fatal(err)
	}
	_, portText, _ := net.SplitHostPort(address)
	if bootstrap.ProtocolVersion != "1" || bootstrap.InstanceID != settings.InstanceID || bootstrap.VaultID != settings.VaultID ||
		portText != fmt.Sprint(bootstrap.LoopbackPort) || strings.Count(strings.TrimSpace(stdout.String()), "\n") != 0 {
		t.Fatalf("bootstrap=%+v output=%q", bootstrap, stdout.String())
	}
	secret, err := config.ReadSecret(opened.Paths.InstanceSecret)
	if err != nil {
		t.Fatal(err)
	}
	if bootstrap.InstanceSecret != base64.RawURLEncoding.EncodeToString(secret) {
		clear(secret)
		t.Fatal("bootstrap instance secret does not match protected host state")
	}
	clear(secret)
	grant, err := base64.RawURLEncoding.Strict().DecodeString(bootstrap.EnrollmentGrant)
	if err != nil || len(grant) != 32 {
		t.Fatalf("grant length=%d error=%v", len(grant), err)
	}
	socketInfo, err := os.Lstat(opened.Paths.AdminSocket)
	if err != nil || socketInfo.Mode()&os.ModeSocket == 0 || socketInfo.Mode().Perm() != 0o600 {
		t.Fatalf("admin socket mode=%v error=%v", socketInfo, err)
	}

	deviceToken := bytes.Repeat([]byte{0x5a}, 32)
	deviceID := "00000000-0000-4000-8000-000000000003"
	enrollmentID := "00000000-0000-4000-8000-000000000004"
	enrollmentBody, _ := json.Marshal(struct {
		ProtocolVersion string   `json:"protocol_version"`
		EnrollmentID    string   `json:"enrollment_id"`
		DeviceID        string   `json:"device_id"`
		DeviceToken     string   `json:"device_token"`
		Scopes          []string `json:"scopes"`
	}{"1", enrollmentID, deviceID, base64.RawURLEncoding.EncodeToString(deviceToken), auth.FixedScopes()})
	enrollmentRequest := newRuntimeRequest(t, http.MethodPost, address, "/v1/enrollments", "00000000-0000-4000-8000-000000000005", enrollmentBody)
	enrollmentRequest.Header.Set("Authorization", "JAT-Enrollment "+bootstrap.EnrollmentGrant)
	client := &http.Client{Timeout: 3 * time.Second}
	enrollmentResponse, err := client.Do(enrollmentRequest)
	if err != nil {
		t.Fatal(err)
	}
	enrollmentResponseBody, _ := io.ReadAll(enrollmentResponse.Body)
	enrollmentResponse.Body.Close()
	if enrollmentResponse.StatusCode != http.StatusCreated {
		t.Fatalf("enrollment response=%d %s", enrollmentResponse.StatusCode, enrollmentResponseBody)
	}

	syncID := "00000000-0000-4000-8000-000000000006"
	syncBody, _ := json.Marshal(struct {
		ProtocolVersion string `json:"protocol_version"`
		DeviceID        string `json:"device_id"`
		RequestID       string `json:"request_id"`
		AfterCursor     string `json:"after_cursor"`
		AckCursor       string `json:"ack_cursor"`
		Mutations       []any  `json:"mutations"`
	}{"1", deviceID, syncID, "0", "0", []any{}})
	syncRequest := newRuntimeRequest(t, http.MethodPost, address, "/v1/sync", syncID, syncBody)
	syncRequest.Header.Set("Authorization", "Bearer "+base64.RawURLEncoding.EncodeToString(deviceToken))
	syncResponse, err := client.Do(syncRequest)
	if err != nil {
		t.Fatal(err)
	}
	syncResponseBody, _ := io.ReadAll(syncResponse.Body)
	syncResponse.Body.Close()
	if syncResponse.StatusCode != http.StatusOK || !bytes.Contains(syncResponseBody, []byte(`"server_cursor":"1"`)) {
		t.Fatalf("sync response=%d %s", syncResponse.StatusCode, syncResponseBody)
	}

	cancel()
	select {
	case err := <-errCh:
		runtimeStopped = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runtime did not stop")
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	instanceClosed = true
	if _, err := os.Lstat(opened.Paths.AdminSocket); !os.IsNotExist(err) {
		t.Fatalf("admin socket survived shutdown: %v", err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		payload, err := os.ReadFile(opened.Paths.Database + suffix)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatal(err)
		}
		if bytes.Contains(payload, grant) || bytes.Contains(payload, deviceToken) {
			t.Fatalf("plaintext bootstrap credential persisted in %s", filepath.Base(opened.Paths.Database+suffix))
		}
	}
	clear(grant)
	clear(deviceToken)
}

func waitForAdminSocket(t *testing.T, path string, errCh chan error) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
			return
		}
		select {
		case err := <-errCh:
			errCh <- err
			t.Fatalf("runtime exited before admin socket: %v", err)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("admin socket did not appear")
}

func waitForRuntimeHealth(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		request, _ := http.NewRequest(http.MethodGet, "http://"+address+"/v1/healthz", nil)
		request.Header.Set("JAT-Protocol-Version", "1")
		request.Header.Set("JAT-Request-ID", "00000000-0000-4000-8000-000000000010")
		response, err := (&http.Client{Timeout: 250 * time.Millisecond}).Do(request)
		if err == nil {
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("runtime health did not become ready")
}

func newRuntimeRequest(t *testing.T, method, address, path, requestID string, body []byte) *http.Request {
	t.Helper()
	request, err := http.NewRequest(method, "http://"+address+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("JAT-Protocol-Version", "1")
	request.Header.Set("JAT-Request-ID", requestID)
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	return request
}
