package server

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/buildinfo"
	"github.com/kciceblue/sshserver/runtime/internal/config"
	"github.com/kciceblue/sshserver/runtime/internal/deployment"
	"github.com/kciceblue/sshserver/runtime/internal/httpapi"
	"github.com/kciceblue/sshserver/runtime/internal/instance"
)

type ready struct{}

func (ready) Ready(context.Context) error { return nil }

func TestRunServesHealthAndRestartsOnSameLoopbackAddress(t *testing.T) {
	address := reserveAddress(t, "tcp4", "127.0.0.1:0")
	settings := config.Settings{
		ConfigVersion: 1,
		InstanceID:    "00000000-0000-4000-8000-000000000001",
		VaultID:       "00000000-0000-4000-8000-000000000002",
		Listeners:     []string{address},
	}
	for iteration := range 2 {
		ctx, cancel := context.WithCancel(context.Background())
		errCh := make(chan error, 1)
		go func() { errCh <- Run(ctx, settings, ready{}) }()
		waitForHealth(t, address)
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("run %d: %v", iteration, err)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("run %d did not stop", iteration)
		}
	}
}

func TestRunWithAdminAcquiresListenersBeforeStartingBoot(t *testing.T) {
	ctx := context.Background()
	stateDir := shortStateDir(t)
	address := reserveAddress(t, "tcp4", "127.0.0.1:0")
	if _, err := instance.Initialize(ctx, stateDir, []string{address}); err != nil {
		t.Fatal(err)
	}
	first, err := instance.Open(ctx, stateDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := first.Close(); err != nil {
			t.Errorf("close first instance: %v", err)
		}
	})

	serveCtx, cancelServe := context.WithCancel(ctx)
	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- RunWithAdmin(serveCtx, first.Settings, first.Store, first.Paths)
	}()
	serverStopped := false
	t.Cleanup(func() {
		if serverStopped {
			return
		}
		cancelServe()
		select {
		case <-serveErrCh:
		case <-time.After(10 * time.Second):
			t.Error("first server did not stop during cleanup")
		}
	})
	waitForHealth(t, address)

	second, err := instance.Open(ctx, stateDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := second.Close(); err != nil {
			t.Errorf("close second instance: %v", err)
		}
	})

	grant, err := first.Store.CreateEnrollmentGrant(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	clear(grant.Grant)
	raw, err := sql.Open("sqlite3", "file:"+first.Paths.Database+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := raw.Close(); err != nil {
			t.Errorf("close raw database: %v", err)
		}
	})
	zero := make([]byte, 8)
	if _, err := raw.ExecContext(ctx, `
		INSERT INTO snapshots (
			snapshot_id, owner_device_id, request_id, request_fingerprint,
			cut_cursor, envelope_generation, collection_generation,
			expires_at_ms, metadata_bytes, create_response_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"10000000-0000-4000-8000-000000000010",
		"10000000-0000-4000-8000-000000000011",
		"10000000-0000-4000-8000-000000000012",
		bytes.Repeat([]byte{0x41}, 32), zero, zero, zero,
		time.Now().Add(time.Hour).UnixMilli(), 0, []byte("{}"),
	); err != nil {
		t.Fatal(err)
	}
	beforeBootID, beforeGrants, beforeSnapshots := readBootArtifacts(t, raw)
	beforeSocket, err := os.Lstat(first.Paths.AdminSocket)
	if err != nil {
		t.Fatal(err)
	}

	attemptCtx, cancelAttempt := context.WithTimeout(ctx, 2*time.Second)
	defer cancelAttempt()
	attemptErrCh := make(chan error, 1)
	go func() {
		attemptErrCh <- RunWithAdmin(attemptCtx, second.Settings, second.Store, second.Paths)
	}()
	select {
	case err = <-attemptErrCh:
		if err == nil || !strings.Contains(err.Error(), "listen on "+address) {
			t.Fatalf("second server error = %v, want occupied HTTP listener", err)
		}
	case <-attemptCtx.Done():
		t.Fatal("second server did not reject the occupied listener promptly")
	}

	afterBootID, afterGrants, afterSnapshots := readBootArtifacts(t, raw)
	if !bytes.Equal(afterBootID, beforeBootID) {
		t.Fatal("failed second startup rotated the active boot ID")
	}
	if afterGrants != beforeGrants || afterSnapshots != beforeSnapshots {
		t.Fatalf("failed second startup changed grants/snapshots from %d/%d to %d/%d",
			beforeGrants, beforeSnapshots, afterGrants, afterSnapshots)
	}
	afterSocket, err := os.Lstat(first.Paths.AdminSocket)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(beforeSocket, afterSocket) {
		t.Fatal("failed second startup replaced the first server's admin socket")
	}
	if afterSocket.Mode().Perm() != 0o600 {
		t.Fatalf("admin socket mode = %o, want 600", afterSocket.Mode().Perm())
	}
	if grant, err := second.Store.CreateEnrollmentGrant(ctx, time.Now()); err == nil {
		clear(grant.Grant)
		t.Fatal("failed second startup marked its store as booted")
	} else if !strings.Contains(err.Error(), "server daemon is not running") {
		t.Fatalf("second store enrollment error = %v", err)
	}

	waitForHealth(t, address)
	select {
	case err := <-serveErrCh:
		serverStopped = true
		t.Fatalf("first server exited after competing startup: %v", err)
	default:
	}
	statusBody := sendAdminCommand(t, first.Paths.AdminSocket, `{"operation":"deployment_status"}`)
	var runningIdentity buildinfo.Identity
	if err := json.Unmarshal(statusBody, &runningIdentity); err != nil {
		t.Fatalf("decode deployment status: %v", err)
	}
	wantIdentity, err := buildinfo.ValidatedCurrent()
	if err != nil {
		t.Fatal(err)
	}
	if runningIdentity != wantIdentity {
		t.Fatalf("running identity = %+v, want %+v", runningIdentity, wantIdentity)
	}
	_, statusGrants, statusSnapshots := readBootArtifacts(t, raw)
	if statusGrants != beforeGrants || statusSnapshots != beforeSnapshots {
		t.Fatalf("deployment status mutated grants/snapshots to %d/%d", statusGrants, statusSnapshots)
	}
	connection, err := net.DialTimeout("unix", first.Paths.AdminSocket, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		connection.Close()
		t.Fatal(err)
	}
	enrollmentCommand, err := EncodeEnrollmentCreateRequest(nil)
	if err != nil {
		connection.Close()
		t.Fatal(err)
	}
	if _, err := connection.Write(enrollmentCommand); err != nil {
		connection.Close()
		t.Fatal(err)
	}
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		connection.Close()
		t.Fatal("admin connection is not a Unix connection")
	}
	if err := unixConnection.CloseWrite(); err != nil {
		connection.Close()
		t.Fatal(err)
	}
	responseBody, err := io.ReadAll(connection)
	connection.Close()
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		ProtocolVersion string `json:"protocol_version"`
	}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		t.Fatalf("decode admin response: %v", err)
	}
	if response.ProtocolVersion != "1" {
		t.Fatalf("admin protocol version = %q, want 1", response.ProtocolVersion)
	}
	_, finalGrants, finalSnapshots := readBootArtifacts(t, raw)
	if finalGrants != beforeGrants+1 || finalSnapshots != beforeSnapshots {
		t.Fatalf("first admin socket left grants/snapshots at %d/%d, want %d/%d",
			finalGrants, finalSnapshots, beforeGrants+1, beforeSnapshots)
	}

	cancelServe()
	select {
	case err := <-serveErrCh:
		serverStopped = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("first server did not stop")
	}
	if _, err := os.Lstat(first.Paths.AdminSocket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("admin socket remains after shutdown: %v", err)
	}
}

func TestManagedEnrollmentRejectsUpgradeBetweenCLIBindingAndGrantHandling(t *testing.T) {
	ctx := context.Background()
	layout := managedEnrollmentLayout(t)
	first := managedEnrollmentRelease(t, layout, "v1.2.3", "a")
	second := managedEnrollmentRelease(t, layout, "v1.2.4", "b")
	for _, release := range []deployment.InstalledRelease{first, second} {
		if err := os.MkdirAll(filepath.Dir(release.BinaryPath), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(release.BinaryPath, []byte(release.Release), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	firstState := deployment.DeploymentState{
		StateVersion: deployment.DeploymentStateVersion,
		Generation:   1,
		Status:       deployment.StatusForeground,
		Manager:      deployment.ManagerForeground,
		StateDir:     layout.StateDir,
		Active:       &first,
	}
	if err := deployment.SaveState(layout, firstState); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.LockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	binding, err := deployment.ActiveExecutableForExecutable(first.BinaryPath)
	if err != nil {
		t.Fatal(err)
	}
	request, err := EncodeEnrollmentCreateRequest(&binding)
	if err != nil {
		t.Fatal(err)
	}

	settings, err := instance.Initialize(ctx, layout.StateDir, []string{"127.0.0.1:37421"})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := instance.Open(ctx, layout.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := opened.Close(); err != nil {
			t.Errorf("close managed enrollment instance: %v", err)
		}
	})
	if err := opened.Store.StartBoot(ctx); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite3", "file:"+opened.Paths.Database+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	_, grantsBefore, _ := readBootArtifacts(t, raw)
	directRequest, err := EncodeEnrollmentCreateRequest(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := handleAdminRequest(ctx, directRequest, io.Discard, settings, opened.Store, opened.Paths, first.BinaryPath); err == nil {
		t.Fatal("managed serving executable accepted an unbound direct-init request")
	}
	_, grantsAfterDirect, _ := readBootArtifacts(t, raw)
	if grantsAfterDirect != grantsBefore {
		t.Fatalf("unbound managed request changed grants from %d to %d", grantsBefore, grantsAfterDirect)
	}
	var activeResponse bytes.Buffer
	if err := handleAdminRequest(ctx, request, &activeResponse, settings, opened.Store, opened.Paths, first.BinaryPath); err != nil {
		t.Fatalf("active managed enrollment failed: %v", err)
	}
	if activeResponse.Len() == 0 {
		t.Fatal("active managed enrollment returned no response")
	}
	_, grantsBeforeRace, _ := readBootArtifacts(t, raw)
	if grantsBeforeRace != grantsBefore+1 {
		t.Fatalf("active managed enrollment changed grants from %d to %d", grantsBefore, grantsBeforeRace)
	}

	// This state switch is the deterministic external upgrade between the
	// CLI's captured binding above and the admin handler below.
	secondState := deployment.DeploymentState{
		StateVersion: deployment.DeploymentStateVersion,
		Generation:   2,
		Status:       deployment.StatusForeground,
		Manager:      deployment.ManagerForeground,
		StateDir:     layout.StateDir,
		Active:       &second,
		Previous:     &first,
	}
	if err := deployment.SaveState(layout, secondState); err != nil {
		t.Fatal(err)
	}
	var response bytes.Buffer
	if err := handleAdminRequest(ctx, request, &response, settings, opened.Store, opened.Paths, first.BinaryPath); err == nil {
		t.Fatal("stale managed executable unexpectedly created an enrollment response")
	}
	if response.Len() != 0 {
		t.Fatalf("stale managed enrollment exposed response bytes: %q", response.String())
	}
	_, grantsAfter, _ := readBootArtifacts(t, raw)
	if grantsAfter != grantsBeforeRace {
		t.Fatalf("stale managed enrollment changed grants from %d to %d", grantsBeforeRace, grantsAfter)
	}
}

func TestAdminRequestBoundaryIsCanonicalBoundedAndCredentialFree(t *testing.T) {
	binding := deployment.ActiveExecutableBinding{
		Generation:   9,
		BinaryPath:   "/managed/versions/v1.2.3/sshserver-linux-amd64",
		BinarySHA256: strings.Repeat("a", 64),
		StateDir:     "/must/not/be/serialized",
	}
	payload, err := EncodeEnrollmentCreateRequest(&binding)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"instance_secret", "enrollment_grant", "device_token", binding.StateDir} {
		if strings.Contains(string(payload), forbidden) {
			t.Fatalf("admin request exposed %q: %s", forbidden, payload)
		}
	}
	decoded, err := decodeAdminRequest(payload)
	if err != nil || decoded.Deployment == nil || decoded.Deployment.BinaryPath != binding.BinaryPath {
		t.Fatalf("decode managed request = %+v, error=%v", decoded, err)
	}
	directPayload, err := EncodeEnrollmentCreateRequest(nil)
	if err != nil {
		t.Fatal(err)
	}
	direct, err := decodeAdminRequest(directPayload)
	if err != nil || !direct.DirectInit || direct.Deployment != nil {
		t.Fatalf("decode direct request = %+v, error=%v", direct, err)
	}
	oversizedBinding := binding
	oversizedBinding.BinaryPath = "/" + strings.Repeat("x", maxAdminRequestBytes)
	if _, err := EncodeEnrollmentCreateRequest(&oversizedBinding); err == nil {
		t.Fatal("oversized canonical admin request unexpectedly encoded")
	}
	for name, malformed := range map[string][]byte{
		"trailing":   append(append([]byte(nil), payload...), ' '),
		"unknown":    []byte(`{"operation":"deployment_status","future":true}`),
		"over limit": bytes.Repeat([]byte("x"), maxAdminRequestBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeAdminRequest(malformed); err == nil {
				t.Fatalf("malformed admin request accepted (%d bytes)", len(malformed))
			}
		})
	}
}

func TestListenAdminSocketRejectsLiveSocket(t *testing.T) {
	path := config.ForStateDir(shortStateDir(t)).AdminSocket
	listener, err := listenAdminSocket(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(listener.cleanup)
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := listenAdminSocket(path)
	if second != nil {
		second.cleanup()
		t.Fatal("second admin listener unexpectedly succeeded")
	}
	if err == nil || !strings.Contains(err.Error(), "already active") {
		t.Fatalf("second admin listener error = %v", err)
	}
	after, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("live admin socket was replaced")
	}
	connection, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatalf("live admin socket is no longer dialable: %v", err)
	}
	connection.Close()
}

func TestOwnedAdminListenerCleanupPreservesReplacement(t *testing.T) {
	path := config.ForStateDir(shortStateDir(t)).AdminSocket
	first, err := listenAdminSocket(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(first.cleanup)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	replacement, err := listenAdminSocket(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(replacement.cleanup)
	replacementInfo, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	first.cleanup()
	current, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(replacementInfo, current) {
		t.Fatal("first listener cleanup removed or replaced the successor socket")
	}
	connection, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatalf("replacement admin socket is not dialable: %v", err)
	}
	connection.Close()
	replacement.cleanup()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned replacement socket remains after cleanup: %v", err)
	}
}

func sendAdminCommand(t *testing.T, socketPath, command string) []byte {
	t.Helper()
	connection, err := net.DialTimeout("unix", socketPath, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(connection, command); err != nil {
		t.Fatal(err)
	}
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		t.Fatal("admin connection is not a Unix connection")
	}
	if err := unixConnection.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(connection)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestRequestHeadLimitAcceptsExactBoundaryAndRejectsOneByteMore(t *testing.T) {
	address := reserveAddress(t, "tcp4", "127.0.0.1:0")
	settings := config.Settings{
		ConfigVersion: 1,
		InstanceID:    "00000000-0000-4000-8000-000000000001",
		VaultID:       "00000000-0000-4000-8000-000000000002",
		Listeners:     []string{address},
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, settings, ready{}) }()
	waitForHealth(t, address)
	defer func() {
		cancel()
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}()

	response, body := rawHeaderRequest(t, address, httpapi.MaxHeaderBytes)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("exact-limit request status = %d", response.StatusCode)
	}
	if len(body) == 0 {
		t.Fatal("exact-limit response body is empty")
	}

	response, body = rawHeaderRequest(t, address, httpapi.MaxHeaderBytes+1)
	if response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-limit request status = %d, body = %s", response.StatusCode, body)
	}
	for name, want := range map[string]string{
		"Content-Type":           "application/json; charset=utf-8",
		"Cache-Control":          "no-store",
		"X-Content-Type-Options": "nosniff",
	} {
		if got := response.Header.Get(name); got != want {
			t.Fatalf("over-limit %s = %q, want %q", name, got, want)
		}
	}
	var envelope struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			Retryable bool   `json:"retryable"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode over-limit body: %v", err)
	}
	if envelope.Error.Code != "limit_exceeded" ||
		envelope.Error.Message != "The request exceeded a protocol limit." ||
		envelope.Error.Retryable ||
		envelope.Error.RequestID != "00000000-0000-4000-8000-000000000003" {
		t.Fatalf("unexpected over-limit envelope: %+v", envelope.Error)
	}
}

func rawHeaderRequest(t *testing.T, address string, size int) (*http.Response, []byte) {
	t.Helper()
	prefix := "GET /v1/healthz HTTP/1.1\r\n" +
		"Host: " + address + "\r\n" +
		"JAT-Protocol-Version: 1\r\n" +
		"JAT-Request-ID: 00000000-0000-4000-8000-000000000003\r\n" +
		"X-Pad: "
	suffix := "\r\n\r\n"
	padding := size - len(prefix) - len(suffix)
	if padding < 0 {
		t.Fatalf("request framing exceeds target size %d", size)
	}
	request := prefix + strings.Repeat("a", padding) + suffix
	if len(request) != size {
		t.Fatalf("request size = %d, want %d", len(request), size)
	}
	connection, err := net.DialTimeout("tcp4", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(connection, request); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return response, body
}

func TestPartialListenerFailureRollsBackEarlierListener(t *testing.T) {
	first := reserveAddress(t, "tcp4", "127.0.0.1:0")
	occupied, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = runHTTP(ctx, []string{first, occupied.Addr().String()}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if err == nil {
		t.Fatal("partial listener failure unexpectedly succeeded")
	}
	probe, err := net.Listen("tcp4", first)
	if err != nil {
		t.Fatalf("first listener was not rolled back: %v", err)
	}
	probe.Close()
}

func reserveAddress(t *testing.T, network, address string) string {
	t.Helper()
	listener, err := net.Listen(network, address)
	if err != nil {
		t.Fatal(err)
	}
	result := listener.Addr().String()
	listener.Close()
	return result
}

func shortStateDir(t *testing.T) string {
	t.Helper()
	stateDir, err := os.MkdirTemp("/tmp", "jat-server-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(stateDir); err != nil {
			t.Errorf("remove state directory: %v", err)
		}
	})
	return stateDir
}

func managedEnrollmentLayout(t *testing.T) deployment.Layout {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	home, err = filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}
	testHome, err := os.MkdirTemp(home, ".sshserver-admin-race-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(testHome) })
	if err := os.Chmod(testHome, 0o700); err != nil {
		t.Fatal(err)
	}
	layout, err := deployment.NewLayout(testHome, filepath.Join(testHome, "deployment"), filepath.Join(testHome, "state"))
	if err != nil {
		t.Fatal(err)
	}
	if err := deployment.PrepareLayout(layout); err != nil {
		t.Fatal(err)
	}
	return layout
}

func managedEnrollmentRelease(t *testing.T, layout deployment.Layout, release, digestDigit string) deployment.InstalledRelease {
	t.Helper()
	target := deployment.Target{OS: runtime.GOOS, Architecture: runtime.GOARCH}
	binaryPath, err := layout.BinaryPath(release, target)
	if err != nil {
		t.Fatal(err)
	}
	return deployment.InstalledRelease{
		Release:         release,
		SourceRevision:  strings.Repeat(digestDigit, 40),
		BuildToolchain:  "go1.25.0",
		BuildIdentity:   strings.Repeat(digestDigit, 64),
		ManifestSHA256:  strings.Repeat(digestDigit, 64),
		ProtocolVersion: "1",
		StorageSchema:   "1",
		OS:              target.OS,
		Architecture:    target.Architecture,
		BinaryPath:      binaryPath,
		BinaryBytes:     int64(len(release)),
		BinarySHA256:    strings.Repeat(digestDigit, 64),
		LicenseBytes:    1,
		LicenseSHA256:   strings.Repeat(digestDigit, 64),
		NoticeBytes:     1,
		NoticeSHA256:    strings.Repeat(digestDigit, 64),
	}
}

func readBootArtifacts(t *testing.T, database *sql.DB) ([]byte, int, int) {
	t.Helper()
	var bootID []byte
	var grants, snapshots int
	if err := database.QueryRow(`
		SELECT active_boot_id,
		       (SELECT count(*) FROM enrollment_grants),
		       (SELECT count(*) FROM snapshots)
		FROM runtime_state WHERE singleton = 1`).Scan(&bootID, &grants, &snapshots); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), bootID...), grants, snapshots
}

func waitForHealth(t *testing.T, address string) {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	url := fmt.Sprintf("http://%s/v1/healthz", address)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		request, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("JAT-Protocol-Version", "1")
		request.Header.Set("JAT-Request-ID", "00000000-0000-4000-8000-000000000003")
		response, err := client.Do(request)
		if err == nil {
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
			t.Logf("health status %d: %s", response.StatusCode, body)
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("health endpoint did not become ready")
}
