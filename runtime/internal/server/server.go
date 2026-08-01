// Package server owns loopback listener creation and bounded HTTP lifecycle.
package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/config"
	"github.com/kciceblue/sshserver/runtime/internal/httpapi"
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

func runHTTP(ctx context.Context, addresses []string, handler http.Handler) error {
	listeners := make([]net.Listener, 0, len(addresses))
	for _, address := range addresses {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			closeListeners(listeners)
			return err
		}
		network := "tcp4"
		if net.ParseIP(host).To4() == nil {
			network = "tcp6"
		}
		listener, err := (&net.ListenConfig{}).Listen(ctx, network, address)
		if err != nil {
			closeListeners(listeners)
			return fmt.Errorf("listen on %s: %w", address, err)
		}
		listeners = append(listeners, listener)
	}

	servers := make([]*http.Server, 0, len(listeners))
	errCh := make(chan error, len(listeners))
	var wait sync.WaitGroup
	for _, listener := range listeners {
		server := &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       30 * time.Second,
			MaxHeaderBytes:    httpapi.MaxHeaderBytes,
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
				return 0, errors.New("HTTP request head exceeds limit")
			}
			connection.complete = true
			n := copy(destination, connection.buffer)
			connection.buffer = connection.buffer[n:]
			return n, nil
		}
		if len(connection.buffer) > connection.maxBytes {
			return 0, errors.New("HTTP request head exceeds limit")
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

func closeListeners(listeners []net.Listener) {
	for _, listener := range listeners {
		_ = listener.Close()
	}
}
