// Package cli implements the dependency-free sshserver command surface.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/config"
	"github.com/kciceblue/sshserver/runtime/internal/instance"
	"github.com/kciceblue/sshserver/runtime/internal/server"
	"github.com/kciceblue/sshserver/runtime/internal/service"
	"github.com/kciceblue/sshserver/runtime/internal/uuidv4"
)

var Version = "dev"

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
	case "service":
		err = runner.runService(args[1:])
	case "version":
		if len(args) != 1 {
			err = errors.New("version accepts no arguments")
		} else {
			_, err = fmt.Fprintf(runner.Stdout, "sshserver %s\n", Version)
		}
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
	return server.Run(ctx, opened.Settings, opened.Store)
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
	fmt.Fprintln(runner.Stderr, "usage: sshserver <init|serve|health|service|version> [options]")
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
