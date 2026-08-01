package server

import (
	"bufio"
	"context"
	"encoding/json"
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
