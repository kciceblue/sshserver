package server

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/config"
	"github.com/kciceblue/sshserver/runtime/internal/httpapi"
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

	if status := rawHeaderRequest(t, address, httpapi.MaxHeaderBytes); status != http.StatusOK {
		t.Fatalf("exact-limit request status = %d", status)
	}
	if status := rawHeaderRequest(t, address, httpapi.MaxHeaderBytes+1); status < 400 {
		t.Fatalf("over-limit request status = %d", status)
	}
}

func rawHeaderRequest(t *testing.T, address string, size int) int {
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
	statusLine, err := bufio.NewReader(connection).ReadString('\n')
	if err != nil {
		t.Fatalf("read response status: %v", err)
	}
	var status int
	if _, err := fmt.Sscanf(statusLine, "HTTP/1.1 %d", &status); err != nil {
		t.Fatalf("parse response status %q: %v", statusLine, err)
	}
	return status
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
