// Package service renders user-scoped service-manager configuration without
// placing credentials in arguments, environment, or service files.
package service

import (
	"bytes"
	_ "embed"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"

	"github.com/kciceblue/sshserver/runtime/internal/config"
)

const Label = "com.kciceblue.sshserver"

//go:embed templates/systemd.service.tmpl
var systemdTemplate string

//go:embed templates/launchagent.plist.tmpl
var launchdTemplate string

func Render(platform, binary, stateDir string) ([]byte, error) {
	if platform != "linux" && platform != "darwin" {
		return nil, fmt.Errorf("unsupported service platform %q", platform)
	}
	for name, value := range map[string]string{"binary": binary, "state directory": stateDir} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value || !validPathText(value) {
			return nil, fmt.Errorf("%s must be a canonical absolute path without control characters", name)
		}
	}
	if stateDir == string(filepath.Separator) {
		return nil, errors.New("state directory must not be the filesystem root")
	}
	if platform == "linux" {
		binaryArgument, err := quoteSystemd(binary)
		if err != nil {
			return nil, err
		}
		stateArgument, err := quoteSystemd(stateDir)
		if err != nil {
			return nil, err
		}
		execStart := strings.Join([]string{
			binaryArgument,
			"serve",
			"--state-dir",
			stateArgument,
		}, " ")
		result := strings.ReplaceAll(systemdTemplate, "{{EXEC_START}}", execStart)
		result = strings.ReplaceAll(result, "{{STATE_DIR}}", stateArgument)
		return []byte(result), nil
	}
	escape := func(value string) string {
		var output bytes.Buffer
		_ = xml.EscapeText(&output, []byte(value))
		return output.String()
	}
	result := strings.ReplaceAll(launchdTemplate, "{{BINARY}}", escape(binary))
	result = strings.ReplaceAll(result, "{{STATE_DIR}}", escape(stateDir))
	result = strings.ReplaceAll(result, "{{STDOUT}}", escape(filepath.Join(stateDir, "service.stdout.log")))
	result = strings.ReplaceAll(result, "{{STDERR}}", escape(filepath.Join(stateDir, "service.stderr.log")))
	return []byte(result), nil
}

func validPathText(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func quoteSystemd(value string) (string, error) {
	if !validPathText(value) {
		return "", errors.New("systemd argument contains invalid text")
	}
	var result strings.Builder
	result.WriteByte('"')
	for _, character := range value {
		switch character {
		case '\\':
			result.WriteString("\\\\")
		case '"':
			result.WriteString("\\\"")
		case '%':
			result.WriteString("%%")
		case '$':
			result.WriteString("$$")
		default:
			result.WriteRune(character)
		}
	}
	result.WriteByte('"')
	return result.String(), nil
}

func DefaultOutputPath(platform string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	switch platform {
	case "linux":
		configHome := os.Getenv("XDG_CONFIG_HOME")
		if configHome == "" {
			configHome = filepath.Join(home, ".config")
		} else if !filepath.IsAbs(configHome) {
			return "", errors.New("XDG_CONFIG_HOME must be absolute")
		}
		return filepath.Join(configHome, "systemd", "user", Label+".service"), nil
	case "darwin":
		return filepath.Join(home, "Library", "LaunchAgents", Label+".plist"), nil
	default:
		return "", fmt.Errorf("unsupported service platform %q", platform)
	}
}

func Install(platform, binary, stateDir, outputPath string) (string, error) {
	if platform == "auto" {
		platform = runtime.GOOS
	}
	payload, err := Render(platform, binary, stateDir)
	if err != nil {
		return "", err
	}
	if outputPath == "" {
		outputPath, err = DefaultOutputPath(platform)
		if err != nil {
			return "", err
		}
	}
	if !filepath.IsAbs(outputPath) || filepath.Clean(outputPath) != outputPath || !validPathText(outputPath) {
		return "", errors.New("service output path must be canonical, absolute, and free of control characters")
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o700); err != nil {
		return "", fmt.Errorf("create service directory: %w", err)
	}
	if err := config.WriteFileAtomic(outputPath, payload, 0o600); err != nil {
		return "", fmt.Errorf("install service definition: %w", err)
	}
	return outputPath, nil
}
