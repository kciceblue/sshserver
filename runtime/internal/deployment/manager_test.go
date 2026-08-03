//go:build darwin || linux

package deployment

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

type managerCall struct {
	name string
	args []string
}

type managerResponse struct {
	result CommandResult
	err    error
}

type mockManagerRunner struct {
	path      string
	lookErr   error
	responses []managerResponse
	calls     []managerCall
}

func (runner *mockManagerRunner) LookPath(string) (string, error) {
	if runner.lookErr != nil {
		return "", runner.lookErr
	}
	return runner.path, nil
}

func (runner *mockManagerRunner) Run(_ context.Context, name string, args ...string) (CommandResult, error) {
	runner.calls = append(runner.calls, managerCall{name: name, args: append([]string(nil), args...)})
	if len(runner.responses) == 0 {
		return CommandResult{}, errors.New("unexpected manager command")
	}
	response := runner.responses[0]
	runner.responses = runner.responses[1:]
	return response.result, response.err
}

func TestSystemdManagerExactLifecycleArgv(t *testing.T) {
	home := secureTestHome(t)
	runner := &mockManagerRunner{
		path: "/usr/bin/systemctl",
		responses: []managerResponse{
			{}, {}, {},
			{result: CommandResult{Stdout: "active\n"}},
			{},
		},
	}
	adapter := mustManagerAdapter(t, "linux", home, runner)
	binary := filepath.Join(home, "install", "sshserver")
	state := filepath.Join(home, "state", "server")
	availability, err := adapter.Detect(context.Background(), binary, state)
	if err != nil {
		t.Fatal(err)
	}
	wantDefinition := filepath.Join(home, ".config", "systemd", "user", "com.kciceblue.sshserver.service")
	if !availability.Available || availability.Manager != ManagerSystemd || availability.ServiceDefinition != wantDefinition || availability.Foreground != nil {
		t.Fatalf("availability = %+v", availability)
	}
	if installed, err := adapter.InstallDefinition([]byte("[Unit]\nDescription=test\n")); err != nil || installed != wantDefinition {
		t.Fatalf("install definition path=%q error=%v", installed, err)
	}
	assertProtectedDefinition(t, wantDefinition, "[Unit]\nDescription=test\n")
	if err := adapter.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if active, err := adapter.IsActive(context.Background()); err != nil || !active {
		t.Fatalf("active=%t error=%v", active, err)
	}
	if err := adapter.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	wantCalls := []managerCall{
		{name: "/usr/bin/systemctl", args: []string{"--user", "show-environment"}},
		{name: "/usr/bin/systemctl", args: []string{"--user", "daemon-reload"}},
		{name: "/usr/bin/systemctl", args: []string{"--user", "enable", "--now", "com.kciceblue.sshserver.service"}},
		{name: "/usr/bin/systemctl", args: []string{"--user", "is-active", "com.kciceblue.sshserver.service"}},
		{name: "/usr/bin/systemctl", args: []string{"--user", "disable", "--now", "com.kciceblue.sshserver.service"}},
	}
	assertManagerCalls(t, runner.calls, wantCalls)
	assertNoForbiddenManagerCommands(t, runner.calls)
}

func TestSystemdManagerHonorsXDGConfigHome(t *testing.T) {
	home := secureTestHome(t)
	configHome := filepath.Join(home, "xdg-config")
	t.Setenv("XDG_CONFIG_HOME", configHome)
	adapter, err := NewServiceManagerAdapter("linux", home, &mockManagerRunner{})
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(configHome, "systemd", "user", "com.kciceblue.sshserver.service")
	if adapter.DefinitionPath() != want {
		t.Fatalf("definition path=%q, want=%q", adapter.DefinitionPath(), want)
	}
	if installed, err := adapter.InstallDefinition([]byte("definition\n")); err != nil || installed != want {
		t.Fatalf("install definition path=%q error=%v", installed, err)
	}
	assertProtectedDefinition(t, want, "definition\n")
}

func TestLaunchdManagerExactLifecycleArgv(t *testing.T) {
	home := secureTestHome(t)
	uid := strconv.Itoa(os.Geteuid())
	runner := &mockManagerRunner{
		path: "/bin/launchctl",
		responses: []managerResponse{
			{}, {}, {},
			{result: CommandResult{Stdout: "state = running\n"}},
			{},
		},
	}
	adapter := mustManagerAdapter(t, "darwin", home, runner)
	binary := filepath.Join(home, "install", "sshserver")
	state := filepath.Join(home, "state", "server")
	availability, err := adapter.Detect(context.Background(), binary, state)
	if err != nil {
		t.Fatal(err)
	}
	wantDefinition := filepath.Join(home, "Library", "LaunchAgents", "com.kciceblue.sshserver.plist")
	if !availability.Available || availability.Manager != ManagerLaunchd || availability.ServiceDefinition != wantDefinition || availability.Foreground != nil {
		t.Fatalf("availability = %+v", availability)
	}
	if _, err := adapter.InstallDefinition([]byte("<plist/>\n")); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if active, err := adapter.IsActive(context.Background()); err != nil || !active {
		t.Fatalf("active=%t error=%v", active, err)
	}
	if err := adapter.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	domain := "gui/" + uid
	target := domain + "/com.kciceblue.sshserver"
	wantCalls := []managerCall{
		{name: "/bin/launchctl", args: []string{"print", domain}},
		{name: "/bin/launchctl", args: []string{"bootstrap", domain, wantDefinition}},
		{name: "/bin/launchctl", args: []string{"kickstart", "-k", target}},
		{name: "/bin/launchctl", args: []string{"print", target}},
		{name: "/bin/launchctl", args: []string{"bootout", target}},
	}
	assertManagerCalls(t, runner.calls, wantCalls)
	assertNoForbiddenManagerCommands(t, runner.calls)
}

func TestManagerUnavailableReturnsOnlySupervisedForeground(t *testing.T) {
	for _, test := range []struct {
		name     string
		platform string
		path     string
		lookErr  error
		response managerResponse
		calls    int
	}{
		{name: "systemctl missing", platform: "linux", lookErr: exec.ErrNotFound},
		{name: "launchctl missing", platform: "darwin", lookErr: exec.ErrNotFound},
		{name: "systemd user bus unavailable", platform: "linux", path: "/usr/bin/systemctl", response: managerResponse{result: CommandResult{Stderr: "Failed to connect to bus: No medium found"}, err: errors.New("exit status 1")}, calls: 1},
		{name: "launchd gui domain unavailable", platform: "darwin", path: "/bin/launchctl", response: managerResponse{result: CommandResult{Stderr: "Could not find domain for gui user"}, err: errors.New("exit status 1")}, calls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := secureTestHome(t)
			runner := &mockManagerRunner{path: test.path, lookErr: test.lookErr}
			if test.calls != 0 {
				runner.responses = []managerResponse{test.response}
			}
			adapter := mustManagerAdapter(t, test.platform, home, runner)
			binary := filepath.Join(home, "install", "sshserver")
			state := filepath.Join(home, "state", "server")
			availability, err := adapter.Detect(context.Background(), binary, state)
			if err != nil {
				t.Fatal(err)
			}
			if availability.Available || availability.Manager != ManagerForeground || availability.ServiceDefinition != "" || availability.Foreground == nil ||
				!availability.Foreground.Required || !availability.Foreground.Supervised || availability.Foreground.Reason == "" ||
				!reflect.DeepEqual(availability.Foreground.Command, []string{binary, "serve", "--state-dir", state}) {
				t.Fatalf("foreground availability = %+v", availability)
			}
			if len(runner.calls) != test.calls {
				t.Fatalf("manager calls=%d, want=%d", len(runner.calls), test.calls)
			}
		})
	}
}

func TestManagerFailuresRemainExplicitAndNeverBecomeFallback(t *testing.T) {
	sentinel := errors.New("native manager failed")
	for _, test := range []struct {
		name      string
		platform  string
		responses []managerResponse
		operation func(ServiceManagerAdapter) error
		wantCalls int
	}{
		{
			name: "unexpected probe failure", platform: "linux",
			responses: []managerResponse{{result: CommandResult{Stderr: "permission denied"}, err: sentinel}},
			operation: func(adapter ServiceManagerAdapter) error {
				home := adapter.homeDir
				result, err := adapter.Detect(context.Background(), filepath.Join(home, "bin", "sshserver"), filepath.Join(home, "state"))
				if result.Foreground != nil {
					return errors.New("probe failure became foreground fallback")
				}
				return err
			}, wantCalls: 1,
		},
		{
			name: "systemd daemon reload failure", platform: "linux",
			responses: []managerResponse{{result: CommandResult{Stderr: "permission denied"}, err: sentinel}},
			operation: func(adapter ServiceManagerAdapter) error { return adapter.Activate(context.Background()) }, wantCalls: 1,
		},
		{
			name: "systemd enable failure", platform: "linux",
			responses: []managerResponse{{}, {result: CommandResult{Stderr: "enable rejected"}, err: sentinel}},
			operation: func(adapter ServiceManagerAdapter) error { return adapter.Activate(context.Background()) }, wantCalls: 2,
		},
		{
			name: "launchd bootstrap failure", platform: "darwin",
			responses: []managerResponse{{result: CommandResult{Stderr: "bootstrap rejected"}, err: sentinel}},
			operation: func(adapter ServiceManagerAdapter) error { return adapter.Activate(context.Background()) }, wantCalls: 1,
		},
		{
			name: "launchd kickstart failure", platform: "darwin",
			responses: []managerResponse{{}, {result: CommandResult{Stderr: "kickstart rejected"}, err: sentinel}},
			operation: func(adapter ServiceManagerAdapter) error { return adapter.Activate(context.Background()) }, wantCalls: 2,
		},
		{
			name: "systemd stop failure is not not-loaded", platform: "linux",
			responses: []managerResponse{{result: CommandResult{Stderr: "helper executable not found"}, err: sentinel}},
			operation: func(adapter ServiceManagerAdapter) error { return adapter.Stop(context.Background()) }, wantCalls: 1,
		},
		{
			name: "launchd stop failure is not not-loaded", platform: "darwin",
			responses: []managerResponse{{result: CommandResult{Stderr: "bootout permission denied"}, err: sentinel}},
			operation: func(adapter ServiceManagerAdapter) error { return adapter.Stop(context.Background()) }, wantCalls: 1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := secureTestHome(t)
			command := "/usr/bin/systemctl"
			if test.platform == "darwin" {
				command = "/bin/launchctl"
			}
			runner := &mockManagerRunner{path: command, responses: append([]managerResponse(nil), test.responses...)}
			adapter := mustManagerAdapter(t, test.platform, home, runner)
			err := test.operation(adapter)
			if err == nil || !strings.Contains(err.Error(), sentinel.Error()) {
				t.Fatalf("error=%v, want explicit native failure", err)
			}
			if len(runner.calls) != test.wantCalls {
				t.Fatalf("calls=%d, want=%d", len(runner.calls), test.wantCalls)
			}
			assertNoForbiddenManagerCommands(t, runner.calls)
		})
	}
}

func TestStopAndRemoveAreIdempotentOnlyWhenNotLoaded(t *testing.T) {
	for _, test := range []struct {
		platform string
		path     string
		message  string
		calls    int
	}{
		{platform: "linux", path: "/usr/bin/systemctl", message: "Unit com.kciceblue.sshserver.service not loaded.", calls: 2},
		{platform: "darwin", path: "/bin/launchctl", message: "Boot-out failed: 3: No such process", calls: 1},
	} {
		t.Run(test.platform, func(t *testing.T) {
			home := secureTestHome(t)
			responses := []managerResponse{{result: CommandResult{Stderr: test.message}, err: errors.New("exit status 1")}}
			if test.platform == "linux" {
				responses = append(responses, managerResponse{})
			}
			runner := &mockManagerRunner{path: test.path, responses: responses}
			adapter := mustManagerAdapter(t, test.platform, home, runner)
			if _, err := adapter.InstallDefinition([]byte("definition\n")); err != nil {
				t.Fatal(err)
			}
			if err := adapter.Remove(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(adapter.DefinitionPath()); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("definition survived remove: %v", err)
			}
			if len(runner.calls) != test.calls {
				t.Fatalf("calls=%d, want=%d: %+v", len(runner.calls), test.calls, runner.calls)
			}
			assertNoForbiddenManagerCommands(t, runner.calls)
		})
	}
}

func TestStatusDistinguishesInactiveFromCommandFailure(t *testing.T) {
	home := secureTestHome(t)
	runner := &mockManagerRunner{
		path: "/usr/bin/systemctl",
		responses: []managerResponse{
			{result: CommandResult{Stdout: "inactive\n"}, err: errors.New("exit status 3")},
			{result: CommandResult{Stderr: "permission denied"}, err: errors.New("exit status 1")},
		},
	}
	adapter := mustManagerAdapter(t, "linux", home, runner)
	if active, err := adapter.IsActive(context.Background()); err != nil || active {
		t.Fatalf("inactive result active=%t error=%v", active, err)
	}
	if _, err := adapter.IsActive(context.Background()); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("unexpected status failure: %v", err)
	}
}

func TestInstallDefinitionRejectsUnsafeParentAndPayload(t *testing.T) {
	home := secureTestHome(t)
	runner := &mockManagerRunner{path: "/usr/bin/systemctl"}
	adapter := mustManagerAdapter(t, "linux", home, runner)
	if _, err := adapter.InstallDefinition(nil); err == nil {
		t.Fatal("empty definition unexpectedly installed")
	}
	if err := os.Symlink(filepath.Join(home, "elsewhere"), filepath.Join(home, ".config")); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.InstallDefinition([]byte("definition\n")); err == nil {
		t.Fatal("definition traversed symlinked parent")
	}
}

func TestManagerConstructorRejectsUnsafeInputs(t *testing.T) {
	home := secureTestHome(t)
	if _, err := NewServiceManagerAdapter("freebsd", home, &mockManagerRunner{}); err == nil {
		t.Fatal("unsupported platform accepted")
	}
	if _, err := NewServiceManagerAdapter("linux", home+"/../home", &mockManagerRunner{}); err == nil {
		t.Fatal("noncanonical home accepted")
	}
	if _, err := NewServiceManagerAdapter("linux", home, nil); err == nil {
		t.Fatal("nil runner accepted")
	}
	for _, configHome := range []string{"relative/config", home + "/config/../config", filepath.Dir(home)} {
		t.Run("xdg "+configHome, func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", configHome)
			if _, err := NewServiceManagerAdapter("linux", home, &mockManagerRunner{}); err == nil {
				t.Fatalf("unsafe XDG_CONFIG_HOME %q accepted", configHome)
			}
		})
	}
}

func TestManagerCommandBufferBoundsHostileOutput(t *testing.T) {
	buffer := boundedCommandBuffer{limit: maxManagerCommandOutputBytes}
	payload := []byte(strings.Repeat("x", maxManagerCommandOutputBytes+1))
	written, err := buffer.Write(payload[:maxManagerCommandOutputBytes/2])
	if err != nil || written != maxManagerCommandOutputBytes/2 || buffer.overflow {
		t.Fatalf("first write=%d overflow=%t error=%v", written, buffer.overflow, err)
	}
	written, err = buffer.Write(payload[maxManagerCommandOutputBytes/2:])
	if err != nil || written != len(payload)-maxManagerCommandOutputBytes/2 || !buffer.overflow {
		t.Fatalf("second write=%d overflow=%t error=%v", written, buffer.overflow, err)
	}
	if buffer.Len() != maxManagerCommandOutputBytes {
		t.Fatalf("bounded output length=%d", buffer.Len())
	}
}

func TestExecCommandRunnerReportsOutputOverflow(t *testing.T) {
	printer, err := exec.LookPath("printf")
	if err != nil {
		t.Fatal(err)
	}
	result, err := (ExecCommandRunner{}).Run(
		context.Background(),
		printer,
		"%s",
		strings.Repeat("x", maxManagerCommandOutputBytes+1),
	)
	if !errors.Is(err, ErrManagerCommandOutputExceeded) {
		t.Fatalf("error=%v, want explicit output overflow", err)
	}
	if len(result.Stdout) != maxManagerCommandOutputBytes || result.Stderr != "" {
		t.Fatalf("bounded output lengths stdout=%d stderr=%d", len(result.Stdout), len(result.Stderr))
	}
}

func mustManagerAdapter(t *testing.T, platform, home string, runner CommandRunner) ServiceManagerAdapter {
	t.Helper()
	if platform == "linux" {
		t.Setenv("XDG_CONFIG_HOME", "")
	}
	adapter, err := NewServiceManagerAdapter(platform, home, runner)
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func assertProtectedDefinition(t *testing.T, path, want string) {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != want {
		t.Fatalf("definition=%q, want=%q", payload, want)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("definition mode=%v", info.Mode())
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if !parent.IsDir() || parent.Mode().Perm()&0o077 != 0 {
		t.Fatalf("definition parent mode=%v", parent.Mode())
	}
}

func assertManagerCalls(t *testing.T, got, want []managerCall) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("manager calls\n got: %#v\nwant: %#v", got, want)
	}
}

func assertNoForbiddenManagerCommands(t *testing.T, calls []managerCall) {
	t.Helper()
	for _, call := range calls {
		joined := strings.ToLower(call.name + " " + strings.Join(call.args, " "))
		for _, forbidden := range []string{"sudo", "loginctl", "enable-linger", "system/", "/library/launchdaemons"} {
			if strings.Contains(joined, forbidden) {
				t.Fatalf("manager command contains forbidden %q: %s", forbidden, joined)
			}
		}
		if strings.HasSuffix(call.name, "systemctl") && (len(call.args) == 0 || call.args[0] != "--user") {
			t.Fatalf("systemctl command is not user-scoped: %#v", call)
		}
		if strings.HasSuffix(call.name, "launchctl") {
			for _, arg := range call.args {
				if strings.HasPrefix(arg, "system/") {
					t.Fatalf("launchctl command is system-scoped: %#v", call)
				}
			}
		}
	}
}
