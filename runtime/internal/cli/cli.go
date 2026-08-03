// Package cli implements the dependency-free sshserver command surface.
package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/buildinfo"
	"github.com/kciceblue/sshserver/runtime/internal/config"
	"github.com/kciceblue/sshserver/runtime/internal/deployment"
	"github.com/kciceblue/sshserver/runtime/internal/instance"
	"github.com/kciceblue/sshserver/runtime/internal/server"
	"github.com/kciceblue/sshserver/runtime/internal/service"
	"github.com/kciceblue/sshserver/runtime/internal/uuidv4"
)

type Runner struct {
	Stdout io.Writer
	Stderr io.Writer
}

func (runner Runner) Run(ctx context.Context, args []string) int {
	if runner.Stdout == nil {
		runner.Stdout = io.Discard
	}
	if runner.Stderr == nil {
		runner.Stderr = io.Discard
	}
	if len(args) == 0 {
		runner.usage()
		return 2
	}
	var err error
	switch args[0] {
	case "init":
		err = runner.runInit(ctx, args[1:])
	case "serve":
		err = runner.runServe(ctx, args[1:])
	case "health":
		err = runner.runHealth(ctx, args[1:])
	case "enrollment":
		err = runner.runEnrollment(ctx, args[1:])
	case "endpoint":
		err = runner.runEndpoint(args[1:])
	case "service":
		err = runner.runService(args[1:])
	case "deploy":
		err = runner.runDeploy(ctx, args[1:])
	case "version":
		err = runner.runVersion(args[1:])
	case "help", "-h", "--help":
		runner.usage()
		return 0
	default:
		err = fmt.Errorf("unknown command %q", args[0])
	}
	if err != nil {
		fmt.Fprintf(runner.Stderr, "sshserver: %v\n", err)
		return 1
	}
	return 0
}

func (runner Runner) runVersion(args []string) error {
	format := "text"
	flags := runner.flagSet("version")
	flags.StringVar(&format, "format", format, "output format (text or json)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("version accepts no positional arguments")
	}
	identity, err := buildinfo.ValidatedCurrent()
	if err != nil {
		return fmt.Errorf("validate compiled build identity: %w", err)
	}
	switch format {
	case "text":
		_, err := fmt.Fprintf(runner.Stdout, "sshserver %s\n", identity.Release)
		return err
	case "json":
		return json.NewEncoder(runner.Stdout).Encode(identity)
	default:
		return errors.New("version supports only --format=text or --format=json")
	}
}

func (runner Runner) runDeploy(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("deploy requires apply, recover, status, rollback, or uninstall")
	}
	switch args[0] {
	case "apply", "recover":
		return runner.runDeployApply(ctx, args[0], args[1:])
	case "status":
		return runner.runDeployStatus(ctx, args[1:])
	case "rollback":
		return runner.runDeployRollback(ctx, args[1:])
	case "uninstall":
		return runner.runDeployUninstall(ctx, args[1:])
	default:
		return fmt.Errorf("unknown deploy command %q", args[0])
	}
}

func (runner Runner) runDeployApply(ctx context.Context, operation string, args []string) error {
	values, flags, err := runner.newDeploymentFlags("deploy " + operation)
	if err != nil {
		return err
	}
	manifestPath := ""
	manifestSHA256 := ""
	artifactPath := ""
	licensePath := ""
	noticePath := ""
	consumeInputs := false
	flags.StringVar(&manifestPath, "manifest", manifestPath, "absolute owner-only release manifest path")
	flags.StringVar(&manifestSHA256, "manifest-sha256", manifestSHA256, "pinned lowercase manifest SHA-256")
	flags.StringVar(&artifactPath, "artifact", artifactPath, "absolute verified release artifact path")
	flags.StringVar(&licensePath, "license", licensePath, "absolute verified LICENSE path")
	flags.StringVar(&noticePath, "notice", noticePath, "absolute verified NOTICE path")
	flags.BoolVar(&consumeInputs, "consume-inputs", consumeInputs, "remove verified manifest and artifact inputs after success")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("deploy %s accepts no positional arguments", operation)
	}
	if manifestPath == "" || manifestSHA256 == "" || artifactPath == "" || licensePath == "" || noticePath == "" {
		return fmt.Errorf("deploy %s requires --manifest, --manifest-sha256, --artifact, --license, and --notice", operation)
	}
	inputPaths := []string{manifestPath, artifactPath, licensePath, noticePath}
	seenInputs := make(map[string]bool, len(inputPaths))
	for _, inputPath := range inputPaths {
		if seenInputs[inputPath] {
			return errors.New("deployment input paths must be distinct")
		}
		seenInputs[inputPath] = true
	}
	lifecycle, err := values.lifecycle()
	if err != nil {
		return err
	}
	payload, err := deployment.ReadPinnedManifestFile(manifestPath, manifestSHA256)
	if err != nil {
		return err
	}
	result, err := lifecycle.Apply(ctx, deployment.ApplyRequest{
		ManifestPayload: payload,
		ManifestSHA256:  manifestSHA256,
		ArtifactPath:    artifactPath,
		LicensePath:     licensePath,
		NoticePath:      noticePath,
	})
	if err != nil {
		return err
	}
	if consumeInputs {
		var removalErrors []error
		for label, inputPath := range map[string]string{
			"manifest": manifestPath,
			"artifact": artifactPath,
			"LICENSE":  licensePath,
			"NOTICE":   noticePath,
		} {
			removalErrors = append(removalErrors, wrapOptionalError("remove consumed "+label, deployment.RemoveConsumedInput(inputPath)))
		}
		if err := errors.Join(removalErrors...); err != nil {
			return err
		}
	}
	return json.NewEncoder(runner.Stdout).Encode(result)
}

func wrapOptionalError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func (runner Runner) runDeployStatus(ctx context.Context, args []string) error {
	values, flags, err := runner.newDeploymentFlags("deploy status")
	if err != nil {
		return err
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("deploy status accepts no positional arguments")
	}
	lifecycle, err := values.statusLifecycle()
	if err != nil {
		return err
	}
	result, statusErr := lifecycle.Status(ctx)
	if result.Status != "" {
		if err := json.NewEncoder(runner.Stdout).Encode(result); err != nil {
			return err
		}
	}
	return statusErr
}

func (runner Runner) runDeployRollback(ctx context.Context, args []string) error {
	values, flags, err := runner.newDeploymentFlags("deploy rollback")
	if err != nil {
		return err
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("deploy rollback accepts no positional arguments")
	}
	lifecycle, err := values.lifecycle()
	if err != nil {
		return err
	}
	result, err := lifecycle.Rollback(ctx)
	if err != nil {
		return err
	}
	return json.NewEncoder(runner.Stdout).Encode(result)
}

func (runner Runner) runDeployUninstall(ctx context.Context, args []string) error {
	values, flags, err := runner.newDeploymentFlags("deploy uninstall")
	if err != nil {
		return err
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("deploy uninstall accepts no positional arguments")
	}
	lifecycle, err := values.lifecycle()
	if err != nil {
		return err
	}
	result, err := lifecycle.Uninstall(ctx)
	if err != nil {
		return err
	}
	return json.NewEncoder(runner.Stdout).Encode(result)
}

type deploymentFlagValues struct {
	homeDir     string
	installRoot string
	stateDir    string
}

func (runner Runner) newDeploymentFlags(name string) (*deploymentFlagValues, *flag.FlagSet, error) {
	// Parse explicit layout values before consulting environment-derived
	// defaults. A client retaining a verified lifecycle locator must be able to
	// refresh status after XDG or HOME changes without touching ambient paths.
	values := &deploymentFlagValues{}
	flags := runner.flagSet(name)
	flags.StringVar(&values.homeDir, "home-dir", "", "physical current-user home directory (default: current user home)")
	flags.StringVar(&values.installRoot, "install-root", "", "owner-only deployment root beneath home (default: platform data directory)")
	flags.StringVar(&values.stateDir, "state-dir", "", "protected instance state directory beneath home (default: platform state directory)")
	return values, flags, nil
}

func (values deploymentFlagValues) lifecycle() (*deployment.Lifecycle, error) {
	layout, err := values.layout()
	if err != nil {
		return nil, err
	}
	return deployment.NewNativeLifecycle(layout)
}

func (values deploymentFlagValues) statusLifecycle() (*deployment.Lifecycle, error) {
	layout, err := values.layout()
	if err != nil {
		return nil, err
	}
	return deployment.NewNativeStatusLifecycle(layout)
}

func (values deploymentFlagValues) layout() (deployment.Layout, error) {
	explicitCount := 0
	for _, value := range []string{values.homeDir, values.installRoot, values.stateDir} {
		if value != "" {
			explicitCount++
		}
	}
	if explicitCount == 0 {
		return deployment.DefaultLayout()
	}
	if explicitCount != 3 {
		return deployment.Layout{}, errors.New("--home-dir, --install-root, and --state-dir must be supplied together")
	}
	return deployment.NewLayout(values.homeDir, values.installRoot, values.stateDir)
}

func (runner Runner) runInit(ctx context.Context, args []string) error {
	stateDir, err := config.DefaultStateDir()
	if err != nil {
		return err
	}
	flags := runner.flagSet("init")
	flags.StringVar(&stateDir, "state-dir", stateDir, "absolute protected state directory")
	var listeners stringList
	flags.Var(&listeners, "listen", "literal loopback address; repeat for IPv4 and IPv6")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("init accepts no positional arguments")
	}
	var requested []string
	if listeners.set {
		requested = listeners.values
	}
	settings, err := instance.Initialize(ctx, stateDir, requested)
	if err != nil {
		return err
	}
	return json.NewEncoder(runner.Stdout).Encode(struct {
		Status     string   `json:"status"`
		InstanceID string   `json:"instance_id"`
		VaultID    string   `json:"vault_id"`
		Listeners  []string `json:"listeners"`
		StateDir   string   `json:"state_dir"`
	}{
		Status:     "initialized",
		InstanceID: settings.InstanceID,
		VaultID:    settings.VaultID,
		Listeners:  settings.Listeners,
		StateDir:   stateDir,
	})
}

func (runner Runner) runServe(ctx context.Context, args []string) (returnErr error) {
	stateDir, err := config.DefaultStateDir()
	if err != nil {
		return err
	}
	flags := runner.flagSet("serve")
	flags.StringVar(&stateDir, "state-dir", stateDir, "absolute protected state directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("serve accepts no positional arguments")
	}
	opened, err := instance.OpenForServe(ctx, stateDir)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := opened.Close(); closeErr != nil {
			returnErr = errors.Join(
				returnErr,
				fmt.Errorf("close server instance: %w", closeErr),
			)
		}
	}()
	for _, listener := range opened.Settings.Listeners {
		fmt.Fprintf(runner.Stderr, "sshserver: listening on %s\n", listener)
	}
	return server.RunWithAdmin(ctx, opened.Settings, opened.Store, opened.Paths)
}

func (runner Runner) runEnrollment(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] != "create" {
		return errors.New("enrollment requires create")
	}
	stateDir, err := config.DefaultStateDir()
	if err != nil {
		return err
	}
	format := "json"
	flags := runner.flagSet("enrollment create")
	flags.StringVar(&stateDir, "state-dir", stateDir, "absolute protected state directory")
	flags.StringVar(&format, "format", format, "output format (json)")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("enrollment create accepts no positional arguments")
	}
	if format != "json" {
		return errors.New("enrollment create supports only --format=json")
	}
	if err := config.EnsureStateDirectory(stateDir); err != nil {
		return err
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", config.ForStateDir(stateDir).AdminSocket)
	if err != nil {
		return errors.New("enrollment service is unavailable")
	}
	defer connection.Close()
	if _, err := io.WriteString(connection, `{"operation":"enrollment_create"}`); err != nil {
		return errors.New("enrollment service request failed")
	}
	if unixConnection, ok := connection.(*net.UnixConn); ok {
		if err := unixConnection.CloseWrite(); err != nil {
			return errors.New("enrollment service request failed")
		}
	}
	payload, err := io.ReadAll(io.LimitReader(connection, 4097))
	if err != nil || len(payload) == 0 || len(payload) > 4096 {
		return errors.New("enrollment service returned an invalid response")
	}
	var response struct {
		ProtocolVersion string `json:"protocol_version"`
		InstanceID      string `json:"instance_id"`
		VaultID         string `json:"vault_id"`
		InstanceSecret  string `json:"instance_secret"`
		EnrollmentGrant string `json:"enrollment_grant"`
		ExpiresAt       string `json:"expires_at"`
		LoopbackPort    int    `json:"loopback_port"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return errors.New("enrollment service returned an invalid response")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("enrollment service returned trailing data")
	}
	secret, secretErr := base64.RawURLEncoding.Strict().DecodeString(response.InstanceSecret)
	grant, grantErr := base64.RawURLEncoding.Strict().DecodeString(response.EnrollmentGrant)
	defer clear(secret)
	defer clear(grant)
	if response.ProtocolVersion != config.ProtocolMajor || len(secret) != 32 || len(grant) != 32 || secretErr != nil || grantErr != nil ||
		base64.RawURLEncoding.EncodeToString(secret) != response.InstanceSecret ||
		base64.RawURLEncoding.EncodeToString(grant) != response.EnrollmentGrant ||
		response.LoopbackPort < 1 || response.LoopbackPort > 65535 {
		return errors.New("enrollment service returned an invalid response")
	}
	if _, err := uuidv4.Parse(response.InstanceID); err != nil {
		return errors.New("enrollment service returned an invalid response")
	}
	if _, err := uuidv4.Parse(response.VaultID); err != nil || response.VaultID == response.InstanceID {
		return errors.New("enrollment service returned an invalid response")
	}
	parsedExpiry, err := time.Parse("2006-01-02T15:04:05.000Z", response.ExpiresAt)
	if err != nil || parsedExpiry.Format("2006-01-02T15:04:05.000Z") != response.ExpiresAt {
		return errors.New("enrollment service returned an invalid response")
	}
	return json.NewEncoder(runner.Stdout).Encode(response)
}

func (runner Runner) runEndpoint(args []string) error {
	if len(args) == 0 {
		return errors.New("endpoint requires show")
	}
	if args[0] != "show" {
		return errors.New("endpoint supports only show")
	}
	return runner.runEndpointShow(args[1:])
}

func (runner Runner) runEndpointShow(args []string) error {
	stateDir := ""
	format := "json"
	flags := flag.NewFlagSet("endpoint show", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&stateDir, "state-dir", stateDir, "absolute protected state directory; defaults to the platform state path")
	flags.StringVar(&format, "format", format, "output format (json)")
	if err := flags.Parse(args); err != nil {
		return errors.New("endpoint show has invalid options")
	}
	if flags.NArg() != 0 {
		return errors.New("endpoint show accepts no positional arguments")
	}
	if format != "json" {
		return errors.New("endpoint show supports only --format=json")
	}
	if stateDir == "" {
		executable, err := os.Executable()
		if err != nil {
			return errors.New("endpoint executable path is unavailable")
		}
		stateDir, err = endpointStateDirForExecutable(executable)
		if err != nil {
			return errors.New("endpoint instance state is unavailable")
		}
	}
	settings, err := instance.LoadCompletedSettings(stateDir)
	if err != nil {
		return errors.New("endpoint instance state is unavailable")
	}
	port, err := discoverableIPv4LoopbackPort(settings.Listeners)
	if err != nil {
		return err
	}
	return json.NewEncoder(runner.Stdout).Encode(struct {
		ProtocolVersion string `json:"protocol_version"`
		InstanceID      string `json:"instance_id"`
		VaultID         string `json:"vault_id"`
		LoopbackPort    int    `json:"loopback_port"`
	}{
		ProtocolVersion: config.ProtocolMajor,
		InstanceID:      settings.InstanceID,
		VaultID:         settings.VaultID,
		LoopbackPort:    port,
	})
}

func endpointStateDirForExecutable(executable string) (string, error) {
	stateDir, err := deployment.StateDirForExecutable(executable)
	if err == nil {
		return stateDir, nil
	}
	if !errors.Is(err, deployment.ErrNotDeployedExecutable) {
		return "", err
	}
	return config.DefaultStateDir()
}

func discoverableIPv4LoopbackPort(listeners []string) (int, error) {
	sharedPort := ""
	hasProductIPv4Listener := false
	for _, address := range listeners {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return 0, errors.New("endpoint listener configuration is invalid")
		}
		if sharedPort == "" {
			sharedPort = port
		} else if sharedPort != port {
			return 0, errors.New("endpoint listeners do not share one port")
		}
		if host == "127.0.0.1" {
			hasProductIPv4Listener = true
		}
	}
	if !hasProductIPv4Listener {
		return 0, errors.New("endpoint has no usable 127.0.0.1 listener")
	}
	port, err := strconv.Atoi(sharedPort)
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("endpoint listener port is invalid")
	}
	return port, nil
}

func (runner Runner) runHealth(ctx context.Context, args []string) error {
	address := config.DefaultListeners()[0]
	flags := runner.flagSet("health")
	flags.StringVar(&address, "address", address, "literal loopback server address")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("health accepts no positional arguments")
	}
	if err := config.ValidateListener(address); err != nil {
		return err
	}
	requestID, err := uuidv4.New()
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/v1/healthz", nil)
	if err != nil {
		return err
	}
	request.Header.Set("JAT-Protocol-Version", config.ProtocolMajor)
	request.Header.Set("JAT-Request-ID", requestID)
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 3 * time.Second, Transport: transport}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("health request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return fmt.Errorf("health returned HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(payload)))
	}
	if response.Header.Get("Content-Type") != "application/json; charset=utf-8" {
		return errors.New("health returned an unexpected content type")
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, 1025))
	if err != nil {
		return fmt.Errorf("read health response: %w", err)
	}
	if len(payload) > 1024 {
		return errors.New("health response exceeds 1024 bytes")
	}
	var body struct {
		Status          string `json:"status"`
		ProtocolVersion string `json:"protocol_version"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		return fmt.Errorf("decode health response: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("health returned trailing JSON data")
	}
	if body.Status != "ok" || body.ProtocolVersion != config.ProtocolMajor {
		return errors.New("health returned an invalid response")
	}
	_, err = fmt.Fprintln(runner.Stdout, "ok")
	return err
}

func (runner Runner) runService(args []string) error {
	if len(args) == 0 {
		return errors.New("service requires render or install")
	}
	switch args[0] {
	case "render":
		return runner.renderService(args[1:])
	case "install":
		return runner.installService(args[1:])
	default:
		return fmt.Errorf("unknown service command %q", args[0])
	}
}

func (runner Runner) renderService(args []string) error {
	platform, binary, stateDir, _, flags, err := runner.serviceFlags("service render", args, false)
	if err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("service render accepts no positional arguments")
	}
	payload, err := service.Render(platform, binary, stateDir)
	if err != nil {
		return err
	}
	_, err = runner.Stdout.Write(payload)
	return err
}

func (runner Runner) installService(args []string) error {
	platform, binary, stateDir, output, flags, err := runner.serviceFlags("service install", args, true)
	if err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("service install accepts no positional arguments")
	}
	installed, err := service.Install(platform, binary, stateDir, output)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(runner.Stdout, installed)
	return err
}

func (runner Runner) serviceFlags(name string, args []string, allowOutput bool) (platform, binary, stateDir, output string, flags *flag.FlagSet, err error) {
	platform = runtime.GOOS
	binary, err = os.Executable()
	if err != nil {
		return
	}
	binary, err = filepathAbs(binary)
	if err != nil {
		return
	}
	stateDir, err = config.DefaultStateDir()
	if err != nil {
		return
	}
	flags = runner.flagSet(name)
	flags.StringVar(&platform, "platform", platform, "linux or darwin")
	flags.StringVar(&binary, "binary", binary, "absolute sshserver binary path")
	flags.StringVar(&stateDir, "state-dir", stateDir, "absolute protected state directory")
	if allowOutput {
		flags.StringVar(&output, "output", "", "absolute service definition path")
	}
	err = flags.Parse(args)
	return
}

func (runner Runner) flagSet(name string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(runner.Stderr)
	return flags
}

func (runner Runner) usage() {
	fmt.Fprintln(runner.Stderr, "usage: sshserver <init|serve|health|enrollment|endpoint|service|deploy|version> [options]")
}

type stringList struct {
	values []string
	set    bool
}

func (values *stringList) String() string { return strings.Join(values.values, ",") }

func (values *stringList) Set(value string) error {
	values.set = true
	values.values = append(values.values, value)
	return nil
}

func filepathAbs(path string) (string, error) {
	if filepath.IsAbs(path) {
		return path, nil
	}
	return "", errors.New("executable path must be absolute")
}
