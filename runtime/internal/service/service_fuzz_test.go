package service

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func FuzzServiceDefinitionPaths(f *testing.F) {
	f.Add("linux", "/opt/jat/sshserver", "/home/alice/JAT state", "/home/alice/.config/systemd/user/com.kciceblue.sshserver.service")
	f.Add("darwin", "/Users/alice/$bin/sshserver%stable", "/Users/alice/JAT & Sync", "/Users/alice/Library/LaunchAgents/com.kciceblue.sshserver.plist")
	f.Add("linux", "/opt/JAT \\\"$%/sshserver", "/home/alice/state \\\"$%", "/home/alice/systemd/service.conf")
	f.Add("linux", "/tmp/../bin", "/", "relative.service")
	f.Add("linux", "/opt/jat/sshserver", "/home/alice/state", "/")
	f.Add("darwin", string([]byte{'/', 0xff}), "/Users/alice/state\ufffe", "/tmp/output\nplist")

	f.Fuzz(func(t *testing.T, platform, binary, stateDir, outputPath string) {
		if len(platform) > 32 || len(binary) > 4096 || len(stateDir) > 4096 || len(outputPath) > 4096 {
			return
		}

		if got, want := validPathText(binary), exactServicePathText(binary); got != want {
			t.Fatalf("path-text acceptance=%v want=%v for %q", got, want, binary)
		}
		assertExactSystemdQuote(t, binary, true, quoteSystemdExecArgument)
		assertExactSystemdQuote(t, binary, false, quoteSystemdPath)
		assertExactSystemdQuote(t, binary, len(outputPath)%2 == 0, func(value string) (string, error) {
			return quoteSystemd(value, len(outputPath)%2 == 0)
		})

		outputErr := validateServicePath("service output path", outputPath, false)
		if got, want := outputErr == nil, exactServicePath(outputPath, false); got != want {
			t.Fatalf("output-path acceptance=%v want=%v for %q", got, want, outputPath)
		}

		first, firstErr := Render(platform, binary, stateDir)
		second, secondErr := Render(platform, binary, stateDir)
		want, wantOK := exactServiceDefinition(platform, binary, stateDir)
		if (firstErr == nil) != wantOK || (secondErr == nil) != wantOK {
			t.Fatalf("render acceptance first=%v second=%v want=%v", firstErr == nil, secondErr == nil, wantOK)
		}
		if !wantOK {
			return
		}
		if string(first) != want || string(second) != want {
			t.Fatalf("rendered service definition differs from exact grammar")
		}
		for _, placeholder := range []string{"{{EXEC_START}}", "{{STATE_DIR}}", "{{BINARY}}", "{{STDOUT}}", "{{STDERR}}"} {
			if strings.Contains(string(first), placeholder) {
				t.Fatalf("rendered service definition retained placeholder %q", placeholder)
			}
		}
	})
}

func assertExactSystemdQuote(t *testing.T, value string, escapeDollar bool, production func(string) (string, error)) {
	t.Helper()
	got, err := production(value)
	want, wantOK := exactSystemdQuote(value, escapeDollar)
	if (err == nil) != wantOK {
		t.Fatalf("systemd quote acceptance=%v want=%v for %q", err == nil, wantOK, value)
	}
	if wantOK && got != want {
		t.Fatalf("systemd quote=%q want=%q", got, want)
	}
}

func exactServicePathText(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f || character == 0xfffe || character == 0xffff {
			return false
		}
	}
	return true
}

func exactServicePath(value string, allowRoot bool) bool {
	if !exactServicePathText(value) || value == "" || value[0] != '/' {
		return false
	}
	if value == "/" {
		return allowRoot
	}
	if strings.HasSuffix(value, "/") || strings.Contains(value, "//") {
		return false
	}
	for _, component := range strings.Split(value[1:], "/") {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	return true
}

func exactSystemdQuote(value string, escapeDollar bool) (string, bool) {
	if !exactServicePathText(value) {
		return "", false
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
			if escapeDollar {
				result.WriteString("$$")
			} else {
				result.WriteRune(character)
			}
		default:
			result.WriteRune(character)
		}
	}
	result.WriteByte('"')
	return result.String(), true
}

func exactServiceDefinition(platform, binary, stateDir string) (string, bool) {
	if (platform != "linux" && platform != "darwin") ||
		!exactServicePath(binary, true) || !exactServicePath(stateDir, false) {
		return "", false
	}
	if platform == "linux" {
		binaryArgument, _ := exactSystemdQuote(binary, true)
		stateArgument, _ := exactSystemdQuote(stateDir, true)
		statePath, _ := exactSystemdQuote(stateDir, false)
		execStart := strings.Join([]string{binaryArgument, "serve", "--state-dir", stateArgument}, " ")
		result := strings.ReplaceAll(systemdTemplate, "{{EXEC_START}}", execStart)
		return strings.ReplaceAll(result, "{{STATE_DIR}}", statePath), true
	}
	result := strings.ReplaceAll(launchdTemplate, "{{BINARY}}", exactXMLEscape(binary))
	result = strings.ReplaceAll(result, "{{STATE_DIR}}", exactXMLEscape(stateDir))
	result = strings.ReplaceAll(result, "{{STDOUT}}", exactXMLEscape(stateDir+"/service.stdout.log"))
	result = strings.ReplaceAll(result, "{{STDERR}}", exactXMLEscape(stateDir+"/service.stderr.log"))
	return result, true
}

func exactXMLEscape(value string) string {
	var result strings.Builder
	for _, character := range value {
		switch character {
		case '&':
			result.WriteString("&amp;")
		case '<':
			result.WriteString("&lt;")
		case '>':
			result.WriteString("&gt;")
		case '"':
			result.WriteString("&#34;")
		case '\'':
			result.WriteString("&#39;")
		default:
			result.WriteRune(character)
		}
	}
	return result.String()
}
