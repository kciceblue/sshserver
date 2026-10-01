//go:build darwin || linux

package deployment

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type serviceManagerFuzzRunner struct {
	path   string
	result CommandResult
	err    error
}

func (runner serviceManagerFuzzRunner) LookPath(string) (string, error) {
	return runner.path, nil
}

func (runner serviceManagerFuzzRunner) Run(context.Context, string, ...string) (CommandResult, error) {
	return runner.result, runner.err
}

func exactManagerUnavailable(platform string, result CommandResult) bool {
	text := strings.ToLower(result.Stdout + "\n" + result.Stderr)
	if platform == "linux" {
		return strings.Contains(text, "failed to connect to bus") ||
			strings.Contains(text, "no medium found") ||
			strings.Contains(text, "system has not been booted with systemd") ||
			strings.Contains(text, "xdg_runtime_dir") && strings.Contains(text, "not set")
	}
	return strings.Contains(text, "could not find domain for") ||
		strings.Contains(text, "domain does not exist")
}

func exactManagerNotLoaded(platform string, result CommandResult) bool {
	text := strings.ToLower(result.Stdout + "\n" + result.Stderr)
	if platform == "linux" {
		return strings.Contains(text, "not loaded") ||
			(strings.Contains(text, "unit file") && strings.Contains(text, "does not exist")) ||
			(strings.Contains(text, "unit ") && strings.Contains(text, "could not be found")) ||
			strings.TrimSpace(result.Stdout) == "unknown"
	}
	return strings.Contains(text, "could not find service") ||
		strings.Contains(text, "could not find specified service") ||
		strings.Contains(text, "no such process")
}

func exactSystemdInactiveState(state string) bool {
	switch state {
	case "inactive", "failed", "deactivating", "unknown", "not-found":
		return true
	default:
		return false
	}
}

func exactManagerIsActive(platform string, result CommandResult, runErr error) (bool, bool) {
	if platform == "linux" {
		state := strings.TrimSpace(result.Stdout)
		if runErr == nil {
			return state == "active", false
		}
		if exactManagerNotLoaded(platform, result) || exactSystemdInactiveState(state) {
			return false, false
		}
		return false, true
	}
	if runErr == nil {
		return strings.Contains(result.Stdout, "state = running"), false
	}
	if exactManagerNotLoaded(platform, result) {
		return false, false
	}
	return false, true
}

func FuzzServiceManagerOutput(f *testing.F) {
	for _, seed := range []struct {
		stdout string
		stderr string
		failed bool
	}{
		{stdout: "active\n"},
		{stdout: "inactive\n", failed: true},
		{stderr: "Failed to connect to bus: No medium found", failed: true},
		{stdout: "XDG_RUNTIME_DIR", stderr: "not set", failed: true},
		{stderr: "Unit com.kciceblue.sshserver.service could not be found", failed: true},
		{stdout: "state = running\n"},
		{stderr: "Could not find specified service", failed: true},
		{stderr: "permission denied", failed: true},
	} {
		f.Add(seed.stdout, seed.stderr, seed.failed)
	}

	f.Fuzz(func(t *testing.T, stdout, stderr string, failed bool) {
		if len(stdout) > maxManagerCommandOutputBytes || len(stderr) > maxManagerCommandOutputBytes {
			return
		}
		result := CommandResult{Stdout: stdout, Stderr: stderr}
		var runErr error
		if failed {
			runErr = errors.New("service-manager fuzz failure")
		}
		for _, platform := range []string{"linux", "darwin"} {
			if got, want := managerUnavailable(platform, result), exactManagerUnavailable(platform, result); got != want {
				t.Fatalf("%s manager-unavailable classification=%t, exact oracle=%t for stdout=%q stderr=%q", platform, got, want, stdout, stderr)
			}
			if got, want := managerNotLoaded(platform, result), exactManagerNotLoaded(platform, result); got != want {
				t.Fatalf("%s manager-not-loaded classification=%t, exact oracle=%t for stdout=%q stderr=%q", platform, got, want, stdout, stderr)
			}

			path := "/usr/bin/systemctl"
			commandName := "systemctl"
			target := "com.kciceblue.sshserver.service"
			if platform == "darwin" {
				path = "/bin/launchctl"
				commandName = "launchctl"
				target = "gui/501/com.kciceblue.sshserver"
			}
			adapter := ServiceManagerAdapter{
				platform:    platform,
				runner:      serviceManagerFuzzRunner{path: path, result: result, err: runErr},
				commandName: commandName,
				target:      target,
			}
			gotActive, gotErr := adapter.IsActive(context.Background())
			wantActive, wantErr := exactManagerIsActive(platform, result, runErr)
			if gotActive != wantActive || (gotErr != nil) != wantErr {
				t.Fatalf(
					"%s IsActive=(%t, error=%t), exact oracle=(%t, error=%t) for stdout=%q stderr=%q failed=%t",
					platform,
					gotActive,
					gotErr != nil,
					wantActive,
					wantErr,
					stdout,
					stderr,
					failed,
				)
			}
		}
		if got, want := systemdInactiveState(strings.TrimSpace(stdout)), exactSystemdInactiveState(strings.TrimSpace(stdout)); got != want {
			t.Fatalf("systemd inactive-state classification=%t, exact oracle=%t for stdout=%q", got, want, stdout)
		}
		if runErr != nil && commandError(ManagerSystemd, "fuzz status", result, runErr) == nil {
			t.Fatal("commandError must retain a service-manager failure")
		}
	})
}
