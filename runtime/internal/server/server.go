// Package server owns loopback listener creation and bounded HTTP lifecycle.
package server

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
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/config"
	"github.com/kciceblue/sshserver/runtime/internal/httpapi"
	"github.com/kciceblue/sshserver/runtime/internal/store"
)

func Run(ctx context.Context, settings config.Settings, readiness httpapi.Readiness) error {
	if err := settings.Validate(); err != nil {
		return err
	}
	handler, err := httpapi.New(settings, readiness)
	if err != nil {
		return err
	}
	return runHTTP(ctx, settings.Listeners, handler)
}

// RunWithAdmin serves the public loopback V1 API and an owner-only Unix socket
// used exclusively by `sshserver enrollment create` over the already verified
// SSH channel. The Unix socket keeps the instance secret and plaintext grant
// out of the normal HTTP surface.
func RunWithAdmin(ctx context.Context, settings config.Settings, database *store.Store, paths config.Paths) error {
	if err := settings.Validate(); err != nil {
		return err
	}
	if database == nil {
		return errors.New("data plane store is required")
	}
	handler, err := httpapi.New(settings, database)
	if err != nil {
		return err
	}
	httpListeners, err := listenHTTP(ctx, settings.Listeners)
	if err != nil {
		return err
	}
	defer closeListeners(httpListeners)
	adminListener, err := listenAdminSocket(paths.AdminSocket)
	if err != nil {
		return err
	}
	defer adminListener.cleanup()
	if err := database.StartBoot(ctx); err != nil {
		return err
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errCh := make(chan error, 2)
	go func() { errCh <- serveHTTP(runCtx, httpListeners, handler) }()
	go func() { errCh <- runAdmin(runCtx, adminListener, settings, database, paths) }()
	firstErr := <-errCh
	cancel()
	_ = adminListener.Close()
	secondErr := <-errCh
	checkpointCtx, checkpointCancel := context.WithTimeout(context.Background(), 5*time.Second)
	checkpointErr := database.CheckpointUptime(checkpointCtx, time.Now())
	checkpointCancel()
	if firstErr != nil {
		return errors.Join(firstErr, checkpointErr)
	}
	return errors.Join(secondErr, checkpointErr)
}

type ownedAdminListener struct {
	*net.UnixListener
	path      string
	info      os.FileInfo
	closeOnce sync.Once
	closeErr  error
}

func listenAdminSocket(path string) (*ownedAdminListener, error) {
	if existing, err := os.Lstat(path); err == nil {
		if existing.Mode()&os.ModeSymlink != 0 || existing.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("enrollment socket path is occupied by a non-socket")
		}
		connection, dialErr := net.DialTimeout("unix", path, 250*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			return nil, errors.New("enrollment socket is already active")
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) && !errors.Is(dialErr, os.ErrNotExist) {
			return nil, fmt.Errorf("probe enrollment socket: %w", dialErr)
		}
		if errors.Is(dialErr, syscall.ECONNREFUSED) {
			current, statErr := os.Lstat(path)
			if statErr != nil {
				if errors.Is(statErr, os.ErrNotExist) {
					return listenNewAdminSocket(path)
				}
				return nil, fmt.Errorf("reinspect stale enrollment socket: %w", statErr)
			}
			if current.Mode()&os.ModeSymlink != 0 || current.Mode()&os.ModeSocket == 0 || !os.SameFile(existing, current) {
				return nil, errors.New("enrollment socket changed during stale-socket inspection")
			}
			if err := os.Remove(path); err != nil {
				return nil, fmt.Errorf("remove stale enrollment socket: %w", err)
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect enrollment socket: %w", err)
	}
	return listenNewAdminSocket(path)
}

func listenNewAdminSocket(path string) (*ownedAdminListener, error) {
	address, err := net.ResolveUnixAddr("unix", path)
	if err != nil {
		return nil, fmt.Errorf("resolve enrollment socket: %w", err)
	}
	listener, err := net.ListenUnix("unix", address)
	if err != nil {
		return nil, fmt.Errorf("listen on enrollment socket: %w", err)
	}
	listener.SetUnlinkOnClose(false)
	info, err := os.Lstat(path)
	if err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("inspect new enrollment socket: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		_ = listener.Close()
		return nil, errors.New("new enrollment socket path is not a socket")
	}
	owned := &ownedAdminListener{UnixListener: listener, path: path, info: info}
	if err := os.Chmod(path, 0o600); err != nil {
		owned.cleanup()
		return nil, fmt.Errorf("protect enrollment socket: %w", err)
	}
	return owned, nil
}

func (listener *ownedAdminListener) cleanup() {
	_ = listener.Close()
}

// Close removes this listener's pathname before closing the descriptor. That
// ordering lets a successor bind immediately without a later cleanup removing
// the successor's socket. The inode check protects a path already replaced by
// another owner.
func (listener *ownedAdminListener) Close() error {
	listener.closeOnce.Do(func() {
		if current, err := os.Lstat(listener.path); err == nil &&
			current.Mode()&os.ModeSymlink == 0 && current.Mode()&os.ModeSocket != 0 &&
			os.SameFile(listener.info, current) {
			_ = os.Remove(listener.path)
		}
		listener.closeErr = listener.UnixListener.Close()
	})
	return listener.closeErr
}

func runAdmin(ctx context.Context, listener net.Listener, settings config.Settings, database *store.Store, paths config.Paths) error {
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept enrollment command: %w", err)
		}
		if err := handleAdminConnection(ctx, connection, settings, database, paths); err != nil {
			_, _ = io.WriteString(connection, `{"error":"bootstrap_failed"}`)
		}
		_ = connection.Close()
	}
}

func handleAdminConnection(ctx context.Context, connection net.Conn, settings config.Settings, database *store.Store, paths config.Paths) error {
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	request, err := io.ReadAll(io.LimitReader(connection, 257))
	if err != nil {
		return err
	}
	if string(request) != `{"operation":"enrollment_create"}` {
		return errors.New("invalid enrollment command")
	}
	grant, err := database.CreateEnrollmentGrant(ctx, time.Now())
	if err != nil {
		return err
	}
	defer clear(grant.Grant)
	secret, err := config.ReadSecret(paths.InstanceSecret)
	if err != nil {
		return err
	}
	defer clear(secret)
	_, portText, err := net.SplitHostPort(settings.Listeners[0])
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return err
	}
	body, err := json.Marshal(struct {
		ProtocolVersion string `json:"protocol_version"`
		InstanceID      string `json:"instance_id"`
		VaultID         string `json:"vault_id"`
		InstanceSecret  string `json:"instance_secret"`
		EnrollmentGrant string `json:"enrollment_grant"`
		ExpiresAt       string `json:"expires_at"`
		LoopbackPort    int    `json:"loopback_port"`
	}{
		ProtocolVersion: "1",
		InstanceID:      settings.InstanceID,
		VaultID:         settings.VaultID,
		InstanceSecret:  base64.RawURLEncoding.EncodeToString(secret),
		EnrollmentGrant: base64.RawURLEncoding.EncodeToString(grant.Grant),
		ExpiresAt:       grant.ExpiresAt.UTC().Format("2006-01-02T15:04:05.000Z"),
		LoopbackPort:    port,
	})
	if err != nil {
		return err
	}
	_, err = connection.Write(body)
	return err
}

func runHTTP(ctx context.Context, addresses []string, handler http.Handler) error {
	listeners, err := listenHTTP(ctx, addresses)
	if err != nil {
		return err
	}
	return serveHTTP(ctx, listeners, handler)
}

func listenHTTP(ctx context.Context, addresses []string) ([]net.Listener, error) {
	listeners := make([]net.Listener, 0, len(addresses))
	for _, address := range addresses {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			closeListeners(listeners)
			return nil, err
		}
		network := "tcp4"
		if net.ParseIP(host).To4() == nil {
			network = "tcp6"
		}
		listener, err := (&net.ListenConfig{}).Listen(ctx, network, address)
		if err != nil {
			closeListeners(listeners)
			return nil, fmt.Errorf("listen on %s: %w", address, err)
		}
		listeners = append(listeners, listener)
	}
	return listeners, nil
}

func serveHTTP(ctx context.Context, listeners []net.Listener, handler http.Handler) error {
	servers := make([]*http.Server, 0, len(listeners))
	errCh := make(chan error, len(listeners))
	var wait sync.WaitGroup
	for _, listener := range listeners {
		limitedHandler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if state, ok := request.Context().Value(headerLimitContextKey{}).(*headerLimitState); ok && state.exceeded {
				httpapi.WriteLimitExceeded(response, state.requestID)
				return
			}
			handler.ServeHTTP(response, request)
		})
		server := &http.Server{
			Handler:           limitedHandler,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       30 * time.Second,
			MaxHeaderBytes:    httpapi.MaxHeaderBytes,
			ConnContext: func(ctx context.Context, connection net.Conn) context.Context {
				limited, ok := connection.(*headerLimitConn)
				if !ok {
					return ctx
				}
				return context.WithValue(ctx, headerLimitContextKey{}, &limited.limit)
			},
		}
		server.SetKeepAlivesEnabled(false)
		servers = append(servers, server)
		wait.Add(1)
		go func(server *http.Server, listener net.Listener) {
			defer wait.Done()
			limited := &headerLimitListener{Listener: listener, maxBytes: httpapi.MaxHeaderBytes}
			if err := server.Serve(limited); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}(server, listener)
	}

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errCh:
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, server := range servers {
		if err := server.Shutdown(shutdownCtx); err != nil && runErr == nil {
			runErr = fmt.Errorf("shutdown HTTP service: %w", err)
		}
	}
	closeListeners(listeners)
	wait.Wait()
	return runErr
}

type headerLimitListener struct {
	net.Listener
	maxBytes int
}

type headerLimitContextKey struct{}

type headerLimitState struct {
	exceeded  bool
	requestID string
}

func (listener *headerLimitListener) Accept() (net.Conn, error) {
	connection, err := listener.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &headerLimitConn{Conn: connection, maxBytes: listener.maxBytes}, nil
}

// headerLimitConn buffers one HTTP/1 request head before exposing it to
// net/http. The server disables keep-alives, so every accepted connection has
// exactly one independently enforced 16 KiB request-head budget.
type headerLimitConn struct {
	net.Conn
	buffer   []byte
	complete bool
	limit    headerLimitState
	maxBytes int
}

func (connection *headerLimitConn) Read(destination []byte) (int, error) {
	if len(connection.buffer) != 0 && connection.complete {
		n := copy(destination, connection.buffer)
		connection.buffer = connection.buffer[n:]
		return n, nil
	}
	if connection.complete {
		return connection.Conn.Read(destination)
	}
	for {
		if end := bytes.Index(connection.buffer, []byte("\r\n\r\n")); end >= 0 {
			if end+4 > connection.maxBytes {
				return connection.replaceWithLimitRequest(destination)
			}
			connection.complete = true
			n := copy(destination, connection.buffer)
			connection.buffer = connection.buffer[n:]
			return n, nil
		}
		if len(connection.buffer) > connection.maxBytes {
			return connection.replaceWithLimitRequest(destination)
		}
		remaining := connection.maxBytes + 1 - len(connection.buffer)
		chunkSize := 4096
		if remaining < chunkSize {
			chunkSize = remaining
		}
		chunk := make([]byte, chunkSize)
		n, err := connection.Conn.Read(chunk)
		if n != 0 {
			connection.buffer = append(connection.buffer, chunk[:n]...)
			continue
		}
		if err != nil {
			return 0, err
		}
	}
}

func (connection *headerLimitConn) replaceWithLimitRequest(destination []byte) (int, error) {
	connection.limit.exceeded = true
	connection.limit.requestID = httpapi.RequestIDOrFallback(requestIDValues(connection.buffer))
	connection.buffer = []byte("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
	connection.complete = true
	n := copy(destination, connection.buffer)
	connection.buffer = connection.buffer[n:]
	return n, nil
}

func requestIDValues(requestHead []byte) []string {
	lines := bytes.Split(requestHead, []byte("\r\n"))
	values := make([]string, 0, 1)
	for _, line := range lines[1:] {
		separator := bytes.IndexByte(line, ':')
		if separator <= 0 || !bytes.EqualFold(line[:separator], []byte("JAT-Request-ID")) {
			continue
		}
		values = append(values, string(bytes.TrimSpace(line[separator+1:])))
	}
	return values
}

func closeListeners(listeners []net.Listener) {
	for _, listener := range listeners {
		_ = listener.Close()
	}
}
