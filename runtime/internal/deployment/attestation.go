package deployment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"syscall"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/buildinfo"
	"github.com/kciceblue/sshserver/runtime/internal/config"
)

const maxIdentityBytes = 4096

var ErrRuntimeUnavailable = errors.New("deployed runtime is not running")

type IdentityInspector interface {
	Inspect(context.Context, string) (buildinfo.Identity, error)
}

type ExecutableIdentityInspector struct{}

func (ExecutableIdentityInspector) Inspect(ctx context.Context, binaryPath string) (buildinfo.Identity, error) {
	if !canonicalAbsolutePath(binaryPath) {
		return buildinfo.Identity{}, errors.New("identity inspection requires a canonical absolute binary path")
	}
	command := exec.CommandContext(ctx, binaryPath, "version", "--format=json")
	command.Env = []string{"HOME=/nonexistent", "LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	var stdout, stderr boundedBuffer
	stdout.limit = maxIdentityBytes
	stderr.limit = maxIdentityBytes
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return buildinfo.Identity{}, fmt.Errorf("inspect staged binary identity: %w: %s", err, bytes.TrimSpace(stderr.Bytes()))
	}
	if stdout.exceeded || stderr.exceeded {
		return buildinfo.Identity{}, errors.New("staged binary identity output exceeds its size boundary")
	}
	identity, err := parseIdentity(stdout.Bytes())
	if err != nil {
		return buildinfo.Identity{}, fmt.Errorf("validate staged binary identity: %w", err)
	}
	return identity, nil
}

func ProbeRunningIdentity(ctx context.Context, stateDir string) (buildinfo.Identity, error) {
	if !canonicalAbsolutePath(stateDir) {
		return buildinfo.Identity{}, errors.New("running identity probe requires a canonical absolute state directory")
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", config.ForStateDir(stateDir).AdminSocket)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) {
			return buildinfo.Identity{}, fmt.Errorf("%w: %v", ErrRuntimeUnavailable, err)
		}
		return buildinfo.Identity{}, fmt.Errorf("connect to owner-only deployment status socket: %w", err)
	}
	defer connection.Close()
	deadline := time.Now().Add(5 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return buildinfo.Identity{}, err
	}
	if _, err := io.WriteString(connection, `{"operation":"deployment_status"}`); err != nil {
		return buildinfo.Identity{}, fmt.Errorf("request running deployment identity: %w", err)
	}
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return buildinfo.Identity{}, errors.New("deployment status connection is not a Unix socket")
	}
	if err := unixConnection.CloseWrite(); err != nil {
		return buildinfo.Identity{}, fmt.Errorf("finish deployment status request: %w", err)
	}
	payload, err := io.ReadAll(io.LimitReader(connection, maxIdentityBytes+1))
	if err != nil {
		return buildinfo.Identity{}, fmt.Errorf("read running deployment identity: %w", err)
	}
	if len(payload) > maxIdentityBytes {
		return buildinfo.Identity{}, errors.New("running deployment identity exceeds its size boundary")
	}
	identity, err := parseIdentity(payload)
	if err != nil {
		return buildinfo.Identity{}, fmt.Errorf("validate running deployment identity: %w", err)
	}
	return identity, nil
}

func ValidateReleaseIdentity(identity buildinfo.Identity, expected InstalledRelease) error {
	if identity.Release != expected.Release || identity.SourceRevision != expected.SourceRevision ||
		identity.BuildToolchain != expected.BuildToolchain || identity.BuildIdentity != expected.BuildIdentity ||
		identity.ProtocolVersion != expected.ProtocolVersion || identity.StorageSchema != expected.StorageSchema {
		return errors.New("reported build identity does not match the pinned release artifact")
	}
	if !releaseIDPattern.MatchString(identity.Release) || !sourceRevisionPattern.MatchString(identity.SourceRevision) ||
		!toolchainPattern.MatchString(identity.BuildToolchain) || !hexDigestPattern.MatchString(identity.BuildIdentity) ||
		identity.ProtocolVersion != "1" || identity.StorageSchema != "1" {
		return errors.New("reported build identity is not an exact V1 release identity")
	}
	return nil
}

func parseIdentity(payload []byte) (buildinfo.Identity, error) {
	var identity buildinfo.Identity
	if len(payload) == 0 || len(payload) > maxIdentityBytes {
		return identity, errors.New("build identity exceeds its size boundary")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&identity); err != nil {
		return buildinfo.Identity{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return buildinfo.Identity{}, errors.New("build identity contains trailing data")
	}
	return identity, nil
}

type boundedBuffer struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func (buffer *boundedBuffer) Write(payload []byte) (int, error) {
	written := len(payload)
	remaining := buffer.limit - buffer.Len()
	if remaining <= 0 {
		buffer.exceeded = true
		return written, nil
	}
	if len(payload) > remaining {
		buffer.exceeded = true
		payload = payload[:remaining]
	}
	_, _ = buffer.Buffer.Write(payload)
	return written, nil
}
