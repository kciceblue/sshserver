package integration_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const serviceLabel = "com.kciceblue.sshserver"

type runtimeStartMode string

const (
	runtimeUserService runtimeStartMode = "user-service"
	runtimeForeground  runtimeStartMode = "foreground"
)

// TestRuntimeUserServiceSSHTunnel is an opt-in, native integration test. It
// proves that the release binary runs under the native user service manager
// and that /v1/healthz remains reachable through an authenticated SSH
// local-forwarding channel.
func TestRuntimeUserServiceSSHTunnel(t *testing.T) {
	testRuntimeSSHTunnel(t, runtimeUserService)
}

// TestRuntimeForegroundSSHTunnel proves the documented no-service-manager
// fallback through the same authenticated SSH forwarding path. Routine
// `go test ./...` runs compile both tests but skip process/service mutation
// unless JAT_RUNTIME_SERVICE_BINARY names an exact native binary.
func TestRuntimeForegroundSSHTunnel(t *testing.T) {
	testRuntimeSSHTunnel(t, runtimeForeground)
}

func testRuntimeSSHTunnel(t *testing.T, startMode runtimeStartMode) {
	t.Helper()
	binary := os.Getenv("JAT_RUNTIME_SERVICE_BINARY")
	if binary == "" {
		t.Skip("set JAT_RUNTIME_SERVICE_BINARY to run the native service/tunnel test")
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Fatalf("unsupported native service platform %q", runtime.GOOS)
	}
	binary, err := filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(binary)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
		t.Fatalf("runtime binary is not an executable regular file: %s", binary)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	scratch, err := os.MkdirTemp(home, ".sshserver-service-smoke-")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(scratch) != filepath.Clean(home) ||
		!strings.HasPrefix(filepath.Base(scratch), ".sshserver-service-smoke-") {
		t.Fatalf("refusing unsafe integration scratch path %q", scratch)
	}
	if err := os.Chmod(scratch, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(scratch); err != nil {
			t.Errorf("remove integration scratch directory: %v", err)
		}
	})

	stateDir := filepath.Join(scratch, "state")
	serverAddress := reserveLoopbackAddress(t)
	run(t, binary, "init", "--state-dir", stateDir, "--listen", serverAddress)

	var managed managedService
	switch startMode {
	case runtimeUserService:
		serviceFile := filepath.Join(scratch, serviceLabel+serviceSuffix())
		run(
			t,
			binary,
			"service",
			"install",
			"--platform",
			runtime.GOOS,
			"--binary",
			binary,
			"--state-dir",
			stateDir,
			"--output",
			serviceFile,
		)
		managed = startUserService(t, binary, stateDir, serviceFile)
	case runtimeForeground:
		managed = startForegroundFallback(t, binary, stateDir)
	default:
		t.Fatalf("unsupported runtime start mode %q", startMode)
	}
	waitForHealth(t, binary, serverAddress, 15*time.Second)
	if err := managed.assertRunning(); err != nil {
		t.Fatal(err)
	}

	tunnel := startSSHTunnel(t, serverAddress)
	t.Cleanup(tunnel.close)
	waitForHealth(t, binary, tunnel.address, 10*time.Second)
	if err := tunnel.failure(); err != nil {
		t.Fatalf("SSH forwarding failed: %v", err)
	}
	t.Logf("healthz passed through SSH forwarding to %s under %s", serverAddress, managed.mode)
}

type managedService struct {
	mode          string
	assertRunning func() error
	stop          func()
}

func startUserService(t *testing.T, binary, stateDir, serviceFile string) managedService {
	t.Helper()
	if runtime.GOOS == "darwin" {
		return startLaunchAgent(t, serviceFile)
	}
	return startSystemdUserService(t, binary, stateDir, serviceFile)
}

func startLaunchAgent(t *testing.T, serviceFile string) managedService {
	t.Helper()
	domain := "gui/" + strconv.Itoa(os.Getuid())
	target := domain + "/" + serviceLabel
	if output, err := commandOutput("launchctl", "print", target); err == nil {
		t.Fatalf("refusing to replace existing LaunchAgent %s:\n%s", target, output)
	}
	run(t, "launchctl", "bootstrap", domain, serviceFile)
	stop := onceCleanup(func() {
		if output, err := commandOutput("launchctl", "bootout", target); err != nil {
			t.Errorf("stop LaunchAgent: %v\n%s", err, output)
		}
	})
	managed := managedService{
		mode: "macOS LaunchAgent",
		assertRunning: func() error {
			output, err := commandOutput("launchctl", "print", target)
			if err != nil {
				return fmt.Errorf("inspect LaunchAgent: %w", err)
			}
			if !strings.Contains(output, "state = running") {
				return fmt.Errorf("LaunchAgent is not running:\n%s", output)
			}
			return nil
		},
		stop: stop,
	}
	t.Cleanup(managed.stop)
	return managed
}

func startSystemdUserService(t *testing.T, binary, stateDir, serviceFile string) managedService {
	t.Helper()
	if output, err := commandOutput("systemctl", "--user", "show-environment"); err != nil {
		t.Logf("systemd user manager unavailable; exercising documented foreground fallback: %v\n%s", err, output)
		return startForegroundFallback(t, binary, stateDir)
	}
	unit := serviceLabel + ".service"
	if output, err := commandOutput("systemctl", "--user", "cat", unit); err == nil {
		t.Fatalf("refusing to replace existing systemd user unit %s:\n%s", unit, output)
	}
	run(t, "systemctl", "--user", "link", "--runtime", serviceFile)
	stop := onceCleanup(func() {
		if output, err := commandOutput("systemctl", "--user", "disable", "--runtime", "--now", unit); err != nil {
			t.Errorf("disable systemd user unit: %v\n%s", err, output)
		}
		if output, err := commandOutput("systemctl", "--user", "daemon-reload"); err != nil {
			t.Errorf("reload systemd user manager: %v\n%s", err, output)
		}
	})
	managed := managedService{
		mode: "Linux systemd user service",
		assertRunning: func() error {
			output, err := commandOutput("systemctl", "--user", "is-active", unit)
			if err != nil || strings.TrimSpace(output) != "active" {
				return fmt.Errorf("systemd user unit is not active: %w\n%s", err, output)
			}
			return nil
		},
		stop: stop,
	}
	// Register cleanup as soon as the runtime link exists. Fatal failures in
	// the following reload/start steps must not leave a linked or active unit.
	t.Cleanup(managed.stop)
	run(t, "systemctl", "--user", "daemon-reload")
	run(t, "systemctl", "--user", "start", unit)
	return managed
}

func startForegroundFallback(t *testing.T, binary, stateDir string) managedService {
	t.Helper()
	var output bytes.Buffer
	process := exec.Command(binary, "serve", "--state-dir", stateDir)
	process.Stdout = &output
	process.Stderr = &output
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	stop := onceCleanup(func() {
		if process.ProcessState != nil {
			return
		}
		_ = process.Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func() { done <- process.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("foreground fallback exit: %v\n%s", err, output.String())
			}
		case <-time.After(10 * time.Second):
			_ = process.Process.Kill()
			<-done
			t.Errorf("foreground fallback did not stop after interrupt")
		}
	})
	managed := managedService{
		mode: "foreground fallback",
		assertRunning: func() error {
			if process.ProcessState != nil {
				return fmt.Errorf("foreground fallback exited early:\n%s", output.String())
			}
			return nil
		},
		stop: stop,
	}
	t.Cleanup(managed.stop)
	return managed
}

func onceCleanup(cleanup func()) func() {
	var once sync.Once
	return func() { once.Do(cleanup) }
}

func serviceSuffix() string {
	if runtime.GOOS == "darwin" {
		return ".plist"
	}
	return ".service"
}

type directTCPIPRequest struct {
	DestinationAddress string
	DestinationPort    uint32
	OriginAddress      string
	OriginPort         uint32
}

type sshTunnel struct {
	address string
	client  *ssh.Client
	local   net.Listener
	server  net.Listener
	errors  chan error
	once    sync.Once
}

func startSSHTunnel(t *testing.T, target string) *sshTunnel {
	t.Helper()
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	_, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientSigner, err := ssh.NewSignerFromKey(clientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &ssh.ServerConfig{
		MaxAuthTries: 1,
		PublicKeyCallback: func(metadata ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if metadata.User() != "runtime-service-smoke" || !bytes.Equal(key.Marshal(), clientSigner.PublicKey().Marshal()) {
				return nil, errors.New("unauthorized integration key")
			}
			return nil, nil
		},
	}
	serverConfig.AddHostKey(hostSigner)
	serverListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	failures := make(chan error, 16)
	go serveSSHForward(serverListener, serverConfig, target, failures)

	clientConfig := &ssh.ClientConfig{
		User:            "runtime-service-smoke",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(clientSigner)},
		HostKeyCallback: ssh.FixedHostKey(hostSigner.PublicKey()),
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", serverListener.Addr().String(), clientConfig)
	if err != nil {
		serverListener.Close()
		t.Fatal(err)
	}
	local, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		client.Close()
		serverListener.Close()
		t.Fatal(err)
	}
	result := &sshTunnel{
		address: local.Addr().String(),
		client:  client,
		local:   local,
		server:  serverListener,
		errors:  failures,
	}
	go result.forward(target)
	return result
}

func serveSSHForward(listener net.Listener, config *ssh.ServerConfig, target string, failures chan<- error) {
	connection, err := listener.Accept()
	if err != nil {
		if !errors.Is(err, net.ErrClosed) {
			nonBlockingError(failures, err)
		}
		return
	}
	serverConnection, channels, requests, err := ssh.NewServerConn(connection, config)
	if err != nil {
		_ = connection.Close()
		nonBlockingError(failures, err)
		return
	}
	defer serverConnection.Close()
	go ssh.DiscardRequests(requests)
	for proposed := range channels {
		if proposed.ChannelType() != "direct-tcpip" {
			_ = proposed.Reject(ssh.UnknownChannelType, "only direct-tcpip is supported")
			continue
		}
		var request directTCPIPRequest
		if err := ssh.Unmarshal(proposed.ExtraData(), &request); err != nil {
			_ = proposed.Reject(ssh.ConnectionFailed, "invalid direct-tcpip request")
			continue
		}
		requested := net.JoinHostPort(request.DestinationAddress, strconv.FormatUint(uint64(request.DestinationPort), 10))
		if requested != target {
			_ = proposed.Reject(ssh.Prohibited, "target is outside the integration endpoint")
			continue
		}
		upstream, err := net.DialTimeout("tcp", target, 3*time.Second)
		if err != nil {
			_ = proposed.Reject(ssh.ConnectionFailed, "target unavailable")
			continue
		}
		channel, channelRequests, err := proposed.Accept()
		if err != nil {
			upstream.Close()
			nonBlockingError(failures, err)
			continue
		}
		go ssh.DiscardRequests(channelRequests)
		go proxy(channel, upstream)
	}
}

func (tunnel *sshTunnel) forward(target string) {
	for {
		localConnection, err := tunnel.local.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				nonBlockingError(tunnel.errors, err)
			}
			return
		}
		remoteConnection, err := tunnel.client.Dial("tcp", target)
		if err != nil {
			localConnection.Close()
			nonBlockingError(tunnel.errors, err)
			continue
		}
		go proxy(localConnection, remoteConnection)
	}
}

func proxy(left, right io.ReadWriteCloser) {
	defer left.Close()
	defer right.Close()
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(left, right)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(right, left)
		done <- struct{}{}
	}()
	<-done
}

func (tunnel *sshTunnel) failure() error {
	select {
	case err := <-tunnel.errors:
		return err
	default:
		return nil
	}
}

func (tunnel *sshTunnel) close() {
	tunnel.once.Do(func() {
		_ = tunnel.local.Close()
		_ = tunnel.client.Close()
		_ = tunnel.server.Close()
	})
}

func nonBlockingError(destination chan<- error, err error) {
	select {
	case destination <- err:
	default:
	}
}

func reserveLoopbackAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func waitForHealth(t *testing.T, binary, address string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastOutput string
	var lastError error
	for time.Now().Before(deadline) {
		lastOutput, lastError = commandOutput(binary, "health", "--address", address)
		if lastError == nil && lastOutput == "ok\n" {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("health did not become ready at %s: %v\n%s", address, lastError, lastOutput)
}

func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	output, err := commandOutput(name, args...)
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, output)
	}
	return output
}

func commandOutput(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		return string(output), fmt.Errorf("command timed out: %w", ctx.Err())
	}
	return string(output), err
}
