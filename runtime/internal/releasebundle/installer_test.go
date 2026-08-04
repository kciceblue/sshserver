package releasebundle

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kciceblue/sshserver/runtime/internal/deployment"
)

func TestGeneratedInstallerAndOneLineCommandHavePinnedShellSyntax(t *testing.T) {
	options := testBundleOptions(t)
	result, err := generate(options, acceptTestMetadata)
	if err != nil {
		t.Fatal(err)
	}
	installer, err := os.ReadFile(result.InstallerPath)
	if err != nil {
		t.Fatal(err)
	}
	command, err := os.ReadFile(result.InstallCommandPath)
	if err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"installer": result.InstallerPath, "install command": result.InstallCommandPath} {
		if output, err := exec.Command("/bin/sh", "-n", path).CombinedOutput(); err != nil {
			t.Fatalf("%s shell syntax: %v\n%s", name, err, output)
		}
	}
	installerText := string(installer)
	commandText := string(command)
	for _, required := range []string{
		`"$curl_tool" --disable --proto '=https'`,
		`--connect-timeout 15 --max-time 900 --max-filesize`,
		`curl 7.58.0 or newer is required`,
		`"$curl_tool" --disable --version`,
		`ulimit -c 0`,
		`trap '' XFSZ`,
		`ulimit -f "$file_limit_blocks"`,
		`"$physical_home/.jat-sshserver-install.XXXXXXXX"`,
		`run_clean ./sshserver deploy preview`,
		`run_clean ./sshserver deploy apply`,
		`command : 3<'/dev/tty'`,
		`command : 4>'/dev/tty'`,
		`exec 3<'/dev/tty'`,
		`exec 4>'/dev/tty'`,
		`exec 3<&-`,
		`exec 4>&-`,
		`[ "$confirmation" = yes ]`,
		`--consume-inputs --supervise-foreground`,
		`"$env_tool" -i HOME=`,
	} {
		if !strings.Contains(installerText, required) {
			t.Fatalf("installer lacks %q", required)
		}
	}
	for _, forbidden := range []string{
		"sudo", "--location", `"$curl_tool" -L`, "http://", " eval ", " source ", "| /bin/sh", "| sh", ".sha256",
	} {
		if strings.Contains(installerText, forbidden) || strings.Contains(commandText, forbidden) {
			t.Fatalf("generated installer boundary contains forbidden %q", forbidden)
		}
	}
	manifestPayload, err := os.ReadFile(result.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := deployment.ParsePinnedManifest(manifestPayload, result.ManifestSHA256)
	if err != nil {
		t.Fatal(err)
	}
	for _, pin := range append(
		[]string{result.ManifestSHA256, fmt.Sprint(len(manifestPayload))},
		installerManifestPins(manifest)...,
	) {
		if !strings.Contains(installerText, pin) {
			t.Fatalf("installer lacks frozen pin %q", pin)
		}
	}
	if strings.Count(commandText, "\n") != 1 || !strings.Contains(commandText, result.InstallerURL) ||
		!strings.Contains(commandText, result.InstallerSHA256) || !strings.Contains(commandText, fmt.Sprint(result.InstallerBytes)) {
		t.Fatalf("one-line command is not exactly pinned: %q", commandText)
	}
	if !strings.Contains(commandText, "ulimit -c 0") || !strings.Contains(commandText, "trap") ||
		!strings.Contains(commandText, "XFSZ") || !strings.Contains(commandText, "ulimit -f") {
		t.Fatalf("one-line command lacks independent file and core limits: %q", commandText)
	}

	if _, err := InstallerScript(manifest, int64(len(manifestPayload)), strings.Repeat("0", 64)); err == nil {
		t.Fatal("installer accepted the wrong manifest pin")
	}
	if _, err := InstallCommand("http://downloads.example.test/releases/v1.2.3/install.sh", installer); err == nil {
		t.Fatal("installer command accepted a non-HTTPS URL")
	}
}

func TestInstallerSelectsExecutionTargetAndAppliesOnlyAfterLiteralConfirmation(t *testing.T) {
	for _, test := range []struct {
		name       string
		kernel     string
		machine    string
		wantTarget string
	}{
		{name: "linux amd64", kernel: "Linux", machine: "x86_64", wantTarget: "linux-amd64"},
		{name: "linux arm64", kernel: "Linux", machine: "aarch64", wantTarget: "linux-arm64"},
		{name: "darwin amd64 including Rosetta", kernel: "Darwin", machine: "x86_64", wantTarget: "darwin-amd64"},
		{name: "darwin arm64", kernel: "Darwin", machine: "arm64", wantTarget: "darwin-arm64"},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := runInstallerShellFixture(t, installerShellCase{
				kernel: test.kernel, machine: test.machine, confirmation: "yes\n",
			})
			if result.err != nil {
				t.Fatalf("installer failed: %v\nstdout=%q\nstderr=%q\ntty=%q", result.err, result.stdout, result.stderr, result.tty)
			}
			if result.stdout != "{\"status\":\"active\"}\n" || !strings.Contains(result.tty, "deployment preview") ||
				!strings.Contains(result.tty, "Type yes to apply exactly this preview") {
				t.Fatalf("stdout=%q tty=%q", result.stdout, result.tty)
			}
			lines := nonemptyLines(result.executions)
			if len(lines) != 2 || !strings.HasPrefix(lines[0], "deploy preview ") || !strings.HasPrefix(lines[1], "deploy apply ") ||
				!strings.Contains(lines[1], "--consume-inputs --supervise-foreground") {
				t.Fatalf("artifact executions=%q", result.executions)
			}
			curlLines := nonemptyLines(result.curlCalls)
			if len(curlLines) != 4 {
				t.Fatalf("curl calls=%q", result.curlCalls)
			}
			for _, line := range curlLines {
				if !strings.HasPrefix(line, "--disable ") {
					t.Fatalf("curl did not receive --disable first: %q", line)
				}
			}
			if !strings.Contains(result.curlCalls, "sshserver-"+test.wantTarget) {
				t.Fatalf("selected target not downloaded: %q", result.curlCalls)
			}
			if result.curlVersionCalls != "--disable --version\n" {
				t.Fatalf("curl version argv=%q", result.curlVersionCalls)
			}
			for _, executionDir := range nonemptyLines(result.executionDirs) {
				wantPrefix := filepath.Join(result.physicalHome, ".jat-sshserver-install.")
				if !strings.HasPrefix(executionDir, wantPrefix) {
					t.Fatalf("artifact executed outside the pinned user workspace: %q", executionDir)
				}
			}
			assertSanitizedFixtureEnvironments(t, result.environments, result.home)
		})
	}
}

func TestInstallerWorkspaceSwapCannotReplaceVerifiedExecutable(t *testing.T) {
	result := runInstallerShellFixture(t, installerShellCase{
		kernel: "Linux", machine: "x86_64", confirmation: "yes\n", swapWorkspace: true,
	})
	if result.err != nil || result.stdout != "{\"status\":\"active\"}\n" {
		t.Fatalf("installer failed after workspace swap: %v stdout=%q stderr=%q", result.err, result.stdout, result.stderr)
	}
	if result.replacementExecuted != "" {
		t.Fatalf("replacement artifact executed: %q", result.replacementExecuted)
	}
	if lines := nonemptyLines(result.executions); len(lines) != 2 || !strings.HasSuffix(nonemptyLines(result.executionDirs)[0], ".moved") {
		t.Fatalf("verified artifact did not remain pinned after swap: executions=%q dirs=%q", result.executions, result.executionDirs)
	}
}

func TestInstallerUsesPhysicalPinnedWorkspaceForSymlinkHome(t *testing.T) {
	result := runInstallerShellFixture(t, installerShellCase{
		kernel: "Darwin", machine: "arm64", confirmation: "yes\n", symlinkHome: true,
	})
	if result.err != nil || result.stdout != "{\"status\":\"active\"}\n" {
		t.Fatalf("symlink HOME install failed: %v stdout=%q stderr=%q", result.err, result.stdout, result.stderr)
	}
	directories := nonemptyLines(result.executionDirs)
	if result.home == result.physicalHome || len(directories) != 2 ||
		!strings.HasPrefix(directories[0], filepath.Join(result.physicalHome, ".jat-sshserver-install.")) {
		t.Fatalf("HOME=%q physical=%q execution dirs=%q", result.home, result.physicalHome, result.executionDirs)
	}
	assertSanitizedFixtureEnvironments(t, result.environments, result.home)
}

func TestInstallerFailuresNeverReachUnverifiedArtifactOrUnconfirmedApply(t *testing.T) {
	for _, test := range []struct {
		name          string
		configure     installerShellCase
		wantError     string
		wantExecCount int
		wantCurlCount int
	}{
		{
			name: "old system curl", configure: installerShellCase{kernel: "Linux", machine: "x86_64", confirmation: "yes\n", curlVersion: "7.57.0"},
			wantError: "curl 7.58.0 or newer", wantExecCount: 0, wantCurlCount: 0,
		},
		{
			name: "missing tty", configure: installerShellCase{kernel: "Linux", machine: "x86_64", missingTTY: true},
			wantError: "controlling terminal", wantExecCount: 0, wantCurlCount: 0,
		},
		{
			name: "unknown target", configure: installerShellCase{kernel: "Plan9", machine: "sparc", confirmation: "yes\n"},
			wantError: "unsupported execution target", wantExecCount: 0, wantCurlCount: 0,
		},
		{
			name: "curl failure", configure: installerShellCase{kernel: "Linux", machine: "x86_64", confirmation: "yes\n", curlFailure: true},
			wantError: "download failed", wantExecCount: 0, wantCurlCount: 1,
		},
		{
			name: "truncated artifact", configure: installerShellCase{kernel: "Linux", machine: "x86_64", confirmation: "yes\n", artifactMutation: "truncate"},
			wantError: "byte count mismatch", wantExecCount: 0, wantCurlCount: 4,
		},
		{
			name: "oversize artifact", configure: installerShellCase{kernel: "Linux", machine: "x86_64", confirmation: "yes\n", artifactMutation: "oversize"},
			wantError: "byte count mismatch", wantExecCount: 0, wantCurlCount: 4,
		},
		{
			name: "unknown length artifact flood", configure: installerShellCase{kernel: "Linux", machine: "x86_64", confirmation: "yes\n", artifactMutation: "flood"},
			wantError: "independent file limit", wantExecCount: 0, wantCurlCount: 4,
		},
		{
			name: "wrong artifact digest", configure: installerShellCase{kernel: "Linux", machine: "x86_64", confirmation: "yes\n", artifactMutation: "digest"},
			wantError: "SHA-256 mismatch", wantExecCount: 0, wantCurlCount: 4,
		},
		{
			name: "declined", configure: installerShellCase{kernel: "Linux", machine: "x86_64", confirmation: "no\n"},
			wantError: "installation declined", wantExecCount: 1, wantCurlCount: 4,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := runInstallerShellFixture(t, test.configure)
			if result.err == nil || !strings.Contains(result.stderr, test.wantError) || result.stdout != "" {
				t.Fatalf("err=%v stdout=%q stderr=%q tty=%q", result.err, result.stdout, result.stderr, result.tty)
			}
			if got := len(nonemptyLines(result.executions)); got != test.wantExecCount {
				t.Fatalf("artifact executions=%d want=%d: %q", got, test.wantExecCount, result.executions)
			}
			if got := len(nonemptyLines(result.curlCalls)); got != test.wantCurlCount {
				t.Fatalf("curl calls=%d want=%d: %q", got, test.wantCurlCount, result.curlCalls)
			}
		})
	}
}

func TestOneLineBootstrapVerifiesExactInstallerBeforeShellExecution(t *testing.T) {
	for _, test := range []struct {
		name          string
		mutation      string
		curlFailure   bool
		wantSuccess   bool
		wantErrorText string
		curlVersion   string
		wantCurlCount int
		swapWorkspace bool
	}{
		{name: "exact", wantSuccess: true, wantCurlCount: 1},
		{name: "truncated", mutation: "truncate", wantErrorText: "byte count mismatch", wantCurlCount: 1},
		{name: "oversize", mutation: "oversize", wantErrorText: "byte count mismatch", wantCurlCount: 1},
		{name: "unknown length flood", mutation: "flood", wantErrorText: "independent file limit", wantCurlCount: 1},
		{name: "digest", mutation: "digest", wantErrorText: "SHA-256 mismatch", wantCurlCount: 1},
		{name: "redirect refused by curl", curlFailure: true, wantErrorText: "download pinned installer", wantCurlCount: 1},
		{name: "old system curl", curlVersion: "7.57.0", wantErrorText: "curl 7.58.0 or newer", wantCurlCount: 0},
		{name: "workspace swap", wantSuccess: true, wantCurlCount: 1, swapWorkspace: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			tools := filepath.Join(root, "tools")
			if err := os.Mkdir(tools, 0o700); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(root, "executed")
			replacementMarker := filepath.Join(root, "replacement-executed")
			environmentLog := filepath.Join(root, "environments.log")
			versionLog := filepath.Join(root, "curl-version.log")
			installer := []byte("#!/bin/sh\n" + installerEnvironmentLogScript(environmentLog) +
				"printf '%s\\n' executed > " + shellQuote(marker) + "\n")
			served := append([]byte(nil), installer...)
			switch test.mutation {
			case "":
			case "truncate":
				served = served[:len(served)-1]
			case "oversize":
				served = append(served, 'x')
			case "flood":
				served = append(served, bytes.Repeat([]byte{'x'}, 4096)...)
			case "digest":
				served[0] ^= 1
			default:
				t.Fatalf("unknown mutation %q", test.mutation)
			}
			servedPath := writeInstallerFixtureFile(t, root, "served-install.sh", served)
			curlLog := filepath.Join(root, "curl.log")
			if err := os.WriteFile(curlLog, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			failure := ""
			if test.curlFailure {
				failure = "exit 47\n"
			}
			curlVersion := test.curlVersion
			if curlVersion == "" {
				curlVersion = "8.0.0"
			}
			swapScript := ""
			if test.swapWorkspace {
				swapScript = "current=$(/bin/pwd -P)\nmoved=$current.moved\n/bin/mv \"$current\" \"$moved\" || exit 95\n/bin/mkdir \"$current\" || exit 96\nprintf '%s\\n' '#!/bin/sh' 'printf replacement > " + shellQuote(replacementMarker) + "' > \"$current/install.sh\"\n/bin/chmod 700 \"$current/install.sh\"\n"
			}
			writeInstallerTool(t, tools, "curl", "#!/bin/sh\n"+
				installerEnvironmentLogScript(environmentLog)+
				"if [ \"$#\" -eq 2 ] && [ \"$1\" = --disable ] && [ \"$2\" = --version ]; then printf '%s\\n' \"$*\" >> "+shellQuote(versionLog)+"; printf '%s\\n' 'curl "+curlVersion+" fixture'; exit 0; fi\n"+
				"first=${1-}\noutput=\nurl=\n"+
				"while [ \"$#\" -gt 0 ]; do case \"$1\" in --output) output=$2; shift 2 ;; --url) url=$2; shift 2 ;; *) shift ;; esac; done\n"+
				"printf '%s\\n' \"$first $url\" >> "+shellQuote(curlLog)+"\n"+
				"[ \"$first\" = --disable ] || exit 91\n"+failure+
				"/bin/cp "+shellQuote(servedPath)+" \"$output\"\n"+swapScript)
			writeInstallerTool(t, tools, "sha256sum", installerChecksumTool(t))
			options := installerRenderOptions{
				ToolPath: tools + ":/usr/bin:/bin", TTYReadPath: "/dev/tty", TTYWritePath: "/dev/tty",
				EnvPath: "/usr/bin/env", ShellPath: "/bin/sh",
			}
			installerURL := "https://downloads.example.test/releases/v1.2.3/install.sh"
			commandPayload, err := installCommandWithOptions(installerURL, installer, options)
			if err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			command := exec.Command("/bin/sh", "-c", strings.TrimSuffix(string(commandPayload), "\n"))
			sentinelFile := filepath.Join(root, "empty-shell-environment")
			if err := os.WriteFile(sentinelFile, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			command.Env = hostileFixtureEnvironment(root, sentinelFile)
			command.Stdout = &stdout
			command.Stderr = &stderr
			runErr := command.Run()
			_, markerErr := os.Lstat(marker)
			if test.wantSuccess {
				if runErr != nil || markerErr != nil || stdout.Len() != 0 || stderr.Len() != 0 {
					t.Fatalf("run=%v marker=%v stdout=%q stderr=%q", runErr, markerErr, stdout.String(), stderr.String())
				}
			} else if runErr == nil || !os.IsNotExist(markerErr) || !strings.Contains(stderr.String(), test.wantErrorText) {
				t.Fatalf("run=%v marker=%v stdout=%q stderr=%q", runErr, markerErr, stdout.String(), stderr.String())
			}
			if _, err := os.Lstat(replacementMarker); !os.IsNotExist(err) {
				t.Fatalf("replacement installer executed: %v", err)
			}
			versionCalls, err := os.ReadFile(versionLog)
			if err != nil {
				t.Fatal(err)
			}
			if string(versionCalls) != "--disable --version\n" {
				t.Fatalf("bootstrap curl version argv=%q", versionCalls)
			}
			environments, err := os.ReadFile(environmentLog)
			if err != nil {
				t.Fatal(err)
			}
			assertSanitizedFixtureEnvironments(t, string(environments), root)
			curlCalls, err := os.ReadFile(curlLog)
			if err != nil {
				t.Fatal(err)
			}
			if lines := nonemptyLines(string(curlCalls)); len(lines) != test.wantCurlCount ||
				(test.wantCurlCount == 1 && (!strings.HasPrefix(lines[0], "--disable ") || !strings.Contains(lines[0], installerURL))) {
				t.Fatalf("bootstrap curl calls=%q", curlCalls)
			}
		})
	}
}

func installerManifestPins(manifest deployment.ReleaseManifest) []string {
	pins := make([]string, 0, 18)
	for _, artifact := range manifest.Artifacts {
		pins = append(pins, artifact.URL, fmt.Sprint(artifact.Bytes), artifact.SHA256)
	}
	for _, file := range manifest.ReleaseFiles {
		pins = append(pins, file.URL, fmt.Sprint(file.Bytes), file.SHA256)
	}
	return pins
}

type installerShellCase struct {
	kernel           string
	machine          string
	confirmation     string
	missingTTY       bool
	curlFailure      bool
	artifactMutation string
	curlVersion      string
	swapWorkspace    bool
	symlinkHome      bool
}

type installerShellResult struct {
	stdout              string
	stderr              string
	tty                 string
	home                string
	physicalHome        string
	executions          string
	executionDirs       string
	curlVersionCalls    string
	environments        string
	replacementExecuted string
	curlCalls           string
	err                 error
}

func runInstallerShellFixture(t *testing.T, test installerShellCase) installerShellResult {
	t.Helper()
	root := t.TempDir()
	physicalHome := filepath.Join(root, "home")
	if err := os.Mkdir(physicalHome, 0o700); err != nil {
		t.Fatal(err)
	}
	physicalHome, err := filepath.EvalSymlinks(physicalHome)
	if err != nil {
		t.Fatal(err)
	}
	home := physicalHome
	if test.symlinkHome {
		home = filepath.Join(root, "home-link")
		if err := os.Symlink(physicalHome, home); err != nil {
			t.Fatal(err)
		}
	}
	sources := filepath.Join(root, "sources")
	tools := filepath.Join(root, "tools")
	if err := os.Mkdir(sources, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(tools, 0o700); err != nil {
		t.Fatal(err)
	}
	executionLog := filepath.Join(root, "artifact-executions.log")
	executionDirLog := filepath.Join(root, "artifact-directories.log")
	versionLog := filepath.Join(root, "curl-version.log")
	environmentLog := filepath.Join(root, "environments.log")
	replacementMarker := filepath.Join(root, "replacement-executed")
	curlLog := filepath.Join(root, "curl.log")
	fakeArtifact := []byte("#!/bin/sh\n" +
		installerEnvironmentLogScript(environmentLog) +
		"printf '%s\\n' \"$*\" >> " + shellQuote(executionLog) + "\n" +
		"/bin/pwd -P >> " + shellQuote(executionDirLog) + "\n" +
		"case \"${1-}/${2-}\" in\n" +
		"  deploy/preview) printf '%s\\n' '{\"version\":\"1\",\"apply_allowed\":true}' ;;\n" +
		"  deploy/apply) if /bin/sh -c ': <&3' 2>/dev/null || /bin/sh -c ': >&4' 2>/dev/null; then exit 75; fi; case \" $* \" in *' --consume-inputs --supervise-foreground '*) printf '%s\\n' '{\"status\":\"active\"}' ;; *) exit 73 ;; esac ;;\n" +
		"  *) exit 74 ;;\n" +
		"esac\n")
	artifactSource := writeInstallerFixtureFile(t, sources, "artifact", fakeArtifact)
	mutatedArtifact := append([]byte(nil), fakeArtifact...)
	switch test.artifactMutation {
	case "":
	case "truncate":
		mutatedArtifact = mutatedArtifact[:len(mutatedArtifact)-1]
	case "oversize":
		mutatedArtifact = append(mutatedArtifact, 'x')
	case "flood":
		mutatedArtifact = append(mutatedArtifact, bytes.Repeat([]byte{'x'}, 4096)...)
	case "digest":
		mutatedArtifact[0] ^= 1
	default:
		t.Fatalf("unknown artifact mutation %q", test.artifactMutation)
	}
	servedArtifact := artifactSource
	if test.artifactMutation != "" {
		servedArtifact = writeInstallerFixtureFile(t, sources, "mutated-artifact", mutatedArtifact)
	}
	licensePayload := []byte("Apache-2.0 installer fixture\n")
	noticePayload := []byte("installer NOTICE fixture\n")
	licenseSource := writeInstallerFixtureFile(t, sources, "LICENSE", licensePayload)
	noticeSource := writeInstallerFixtureFile(t, sources, "NOTICE", noticePayload)
	release := "v1.2.3"
	origin := "https://downloads.example.test"
	manifest := deployment.ReleaseManifest{
		ManifestVersion: deployment.ManifestVersion,
		Release:         release,
		SourceRevision:  strings.Repeat("a", 40),
		BuildToolchain:  "go1.25.0",
		ProtocolVersion: "1",
		StorageSchema:   "1",
		DownloadOrigin:  origin,
		ReleaseFiles: []deployment.ReleaseFile{
			{Name: "LICENSE", URL: origin + "/releases/" + release + "/LICENSE", Bytes: int64(len(licensePayload)), SHA256: deployment.SHA256Hex(licensePayload)},
			{Name: "NOTICE", URL: origin + "/releases/" + release + "/NOTICE", Bytes: int64(len(noticePayload)), SHA256: deployment.SHA256Hex(noticePayload)},
		},
	}
	for _, target := range deployment.SupportedTargets() {
		identity, err := deployment.DeriveBuildIdentity(release, manifest.SourceRevision, manifest.BuildToolchain, target)
		if err != nil {
			t.Fatal(err)
		}
		manifest.Artifacts = append(manifest.Artifacts, deployment.ReleaseArtifact{
			OS: target.OS, Architecture: target.Architecture, BuildIdentity: identity,
			URL:   origin + "/releases/" + release + "/sshserver-" + target.OS + "-" + target.Architecture,
			Bytes: int64(len(fakeArtifact)), SHA256: deployment.SHA256Hex(fakeArtifact),
		})
	}
	manifestPayload, err := manifest.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	manifestSource := writeInstallerFixtureFile(t, sources, "release-manifest.json", manifestPayload)

	writeInstallerTool(t, tools, "uname", "#!/bin/sh\ncase \"${1-}\" in -s) printf '%s\\n' "+shellQuote(test.kernel)+" ;; -m) printf '%s\\n' "+shellQuote(test.machine)+" ;; *) exit 2 ;; esac\n")
	writeInstallerTool(t, tools, "sha256sum", installerChecksumTool(t))
	curlFailure := ""
	if test.curlFailure {
		curlFailure = "exit 55\n"
	}
	curlVersion := test.curlVersion
	if curlVersion == "" {
		curlVersion = "8.0.0"
	}
	swapScript := ""
	if test.swapWorkspace {
		swapScript = "if [ \"$is_artifact\" = yes ]; then current=$(/bin/pwd -P); moved=$current.moved; /bin/mv \"$current\" \"$moved\" || exit 95; /bin/mkdir \"$current\" || exit 96; printf '%s\\n' '#!/bin/sh' 'printf replacement > " + shellQuote(replacementMarker) + "' > \"$current/sshserver\"; /bin/chmod 700 \"$current/sshserver\"; fi\n"
	}
	curlScript := "#!/bin/sh\n" +
		installerEnvironmentLogScript(environmentLog) +
		"if [ \"$#\" -eq 2 ] && [ \"$1\" = --disable ] && [ \"$2\" = --version ]; then printf '%s\\n' \"$*\" >> " + shellQuote(versionLog) + "; printf '%s\\n' 'curl " + curlVersion + " fixture'; exit 0; fi\n" +
		"first=${1-}\n" +
		"output=\nurl=\nis_artifact=no\n" +
		"while [ \"$#\" -gt 0 ]; do case \"$1\" in --output) output=$2; shift 2 ;; --url) url=$2; shift 2 ;; *) shift ;; esac; done\n" +
		"printf '%s\\n' \"$first $url\" >> " + shellQuote(curlLog) + "\n" +
		"[ \"$first\" = --disable ] || exit 91\n" + curlFailure +
		"case \"$url\" in\n" +
		"  " + shellQuote(origin+"/releases/"+release+"/release-manifest.json") + ") source_path=" + shellQuote(manifestSource) + " ;;\n" +
		"  " + shellQuote(origin+"/releases/"+release+"/LICENSE") + ") source_path=" + shellQuote(licenseSource) + " ;;\n" +
		"  " + shellQuote(origin+"/releases/"+release+"/NOTICE") + ") source_path=" + shellQuote(noticeSource) + " ;;\n" +
		"  " + shellQuote(origin+"/releases/"+release+"/sshserver-"+strings.ToLower(test.kernel)+"-invalid") + ") exit 92 ;;\n" +
		"  */sshserver-*) source_path=" + shellQuote(servedArtifact) + "; is_artifact=yes ;;\n" +
		"  *) exit 93 ;;\n" +
		"esac\n" +
		"/bin/cp \"$source_path\" \"$output\"\n" + swapScript
	writeInstallerTool(t, tools, "curl", curlScript)

	ttyRead := filepath.Join(root, "tty-input")
	if !test.missingTTY {
		if err := os.WriteFile(ttyRead, []byte(test.confirmation), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ttyWrite := filepath.Join(root, "tty-output")
	if err := os.WriteFile(ttyWrite, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	renderOptions := installerRenderOptions{
		ToolPath: tools + ":/usr/bin:/bin", TTYReadPath: ttyRead, TTYWritePath: ttyWrite,
		EnvPath: "/usr/bin/env", ShellPath: "/bin/sh",
	}
	installer, err := installerScriptWithOptions(
		manifest, int64(len(manifestPayload)), deployment.SHA256Hex(manifestPayload), renderOptions,
	)
	if err != nil {
		t.Fatal(err)
	}
	installerPath := filepath.Join(root, "install.sh")
	if err := os.WriteFile(installerPath, installer, 0o400); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	command := exec.Command("/bin/sh", installerPath)
	sentinelFile := filepath.Join(root, "empty-shell-environment")
	if err := os.WriteFile(sentinelFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	command.Env = hostileFixtureEnvironment(home, sentinelFile)
	command.Stdout = &stdout
	command.Stderr = &stderr
	runErr := command.Run()
	readText := func(path string) string {
		payload, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				return ""
			}
			t.Fatal(err)
		}
		return string(payload)
	}
	return installerShellResult{
		stdout: stdout.String(), stderr: stderr.String(), tty: readText(ttyWrite), home: home, physicalHome: physicalHome,
		executions: readText(executionLog), executionDirs: readText(executionDirLog),
		curlCalls: readText(curlLog), curlVersionCalls: readText(versionLog), environments: readText(environmentLog),
		replacementExecuted: readText(replacementMarker), err: runErr,
	}
}

func installerEnvironmentLogScript(path string) string {
	return "printf 'HOME=%s|XDG_DATA_HOME=%s|XDG_STATE_HOME=%s|XDG_CONFIG_HOME=%s|XDG_RUNTIME_DIR=%s|PATH=%s|LC_ALL=%s|sentinels=%s%s%s%s%s%s%s%s%s%s\\n' \"${HOME-}\" \"${XDG_DATA_HOME-}\" \"${XDG_STATE_HOME-}\" \"${XDG_CONFIG_HOME-}\" \"${XDG_RUNTIME_DIR-}\" \"${PATH-}\" \"${LC_ALL-}\" \"${HTTP_PROXY+x}\" \"${HTTPS_PROXY+x}\" \"${ALL_PROXY+x}\" \"${http_proxy+x}\" \"${https_proxy+x}\" \"${CURL_HOME+x}\" \"${SSL_CERT_FILE+x}\" \"${PERL5OPT+x}\" \"${ENV+x}\" \"${BASH_ENV+x}\" >> " + shellQuote(path) + "\n"
}

func hostileFixtureEnvironment(home, shellEnvironmentFile string) []string {
	return []string{
		"HOME=" + home,
		"XDG_DATA_HOME=", "XDG_STATE_HOME=", "XDG_CONFIG_HOME=", "XDG_RUNTIME_DIR=",
		"PATH=/usr/bin:/bin", "LC_ALL=C",
		"HTTP_PROXY=jat-sentinel", "HTTPS_PROXY=jat-sentinel", "ALL_PROXY=jat-sentinel",
		"http_proxy=jat-sentinel", "https_proxy=jat-sentinel", "CURL_HOME=jat-sentinel",
		"SSL_CERT_FILE=jat-sentinel", "PERL5OPT=jat-sentinel",
		"ENV=" + shellEnvironmentFile, "BASH_ENV=" + shellEnvironmentFile,
	}
}

func assertSanitizedFixtureEnvironments(t *testing.T, environments, home string) {
	t.Helper()
	lines := nonemptyLines(environments)
	if len(lines) == 0 {
		t.Fatal("fixture recorded no child environments")
	}
	wantPrefix := "HOME=" + home + "|XDG_DATA_HOME=|XDG_STATE_HOME=|XDG_CONFIG_HOME=|XDG_RUNTIME_DIR=|PATH="
	for _, line := range lines {
		if !strings.HasPrefix(line, wantPrefix) || !strings.Contains(line, "|LC_ALL=C|sentinels=") || !strings.HasSuffix(line, "|sentinels=") {
			t.Fatalf("unsanitized child environment: %q", line)
		}
	}
}

func installerChecksumTool(t *testing.T) string {
	t.Helper()
	if path, err := exec.LookPath("sha256sum"); err == nil {
		path, err = filepath.Abs(path)
		if err != nil {
			t.Fatal(err)
		}
		return "#!/bin/sh\nexec " + shellQuote(path) + " \"$@\"\n"
	}
	if path, err := exec.LookPath("shasum"); err == nil {
		path, err = filepath.Abs(path)
		if err != nil {
			t.Fatal(err)
		}
		return "#!/bin/sh\nexec " + shellQuote(path) + " -a 256 \"$@\"\n"
	}
	t.Skip("host has neither sha256sum nor shasum")
	return ""
}

func writeInstallerTool(t *testing.T, directory, name, payload string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(payload), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeInstallerFixtureFile(t *testing.T, directory, name string, payload []byte) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func nonemptyLines(value string) []string {
	var lines []string
	for _, line := range strings.Split(value, "\n") {
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
