package releasebundle

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/kciceblue/sshserver/runtime/internal/deployment"
	"github.com/kciceblue/sshserver/runtime/internal/releaseid"
)

// The verified installer is passed as one /bin/sh -c argument. Keep the
// boundary comfortably below Linux's per-argument MAX_ARG_STRLEN as well as
// the overall exec limits on every supported target.
const maxInstallerBytes = 64 * 1024

var installerURLSegmentPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

type installerPin struct {
	URL    string
	Bytes  int64
	SHA256 string
}

type installerTemplateData struct {
	Release      string
	ToolPath     string
	TTYReadPath  string
	TTYWritePath string
	EnvPath      string
	ShellPath    string
	Manifest     installerPin
	License      installerPin
	Notice       installerPin
	LinuxAMD64   installerPin
	LinuxARM64   installerPin
	DarwinAMD64  installerPin
	DarwinARM64  installerPin
}

type installerRenderOptions struct {
	ToolPath     string
	TTYReadPath  string
	TTYWritePath string
	EnvPath      string
	ShellPath    string
}

var productionInstallerRenderOptions = installerRenderOptions{
	ToolPath:     "/usr/bin:/bin",
	TTYReadPath:  "/dev/tty",
	TTYWritePath: "/dev/tty",
	EnvPath:      "/usr/bin/env",
	ShellPath:    "/bin/sh",
}

func InstallerScript(manifest deployment.ReleaseManifest, manifestBytes int64, manifestSHA256 string) ([]byte, error) {
	return installerScriptWithOptions(manifest, manifestBytes, manifestSHA256, productionInstallerRenderOptions)
}

func installerScriptWithOptions(
	manifest deployment.ReleaseManifest,
	manifestBytes int64,
	manifestSHA256 string,
	options installerRenderOptions,
) ([]byte, error) {
	canonical, err := manifest.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	if manifestBytes != int64(len(canonical)) || manifestBytes <= 0 || manifestBytes > 64*1024 ||
		deployment.SHA256Hex(canonical) != manifestSHA256 {
		return nil, errors.New("installer manifest size or pin does not match its canonical bytes")
	}
	if err := validateInstallerRenderOptions(options); err != nil {
		return nil, err
	}
	artifacts := make(map[string]installerPin, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		artifacts[artifact.OS+"/"+artifact.Architecture] = installerPin{
			URL: artifact.URL, Bytes: artifact.Bytes, SHA256: artifact.SHA256,
		}
	}
	data := installerTemplateData{
		Release:      manifest.Release,
		ToolPath:     options.ToolPath,
		TTYReadPath:  options.TTYReadPath,
		TTYWritePath: options.TTYWritePath,
		EnvPath:      options.EnvPath,
		ShellPath:    options.ShellPath,
		Manifest: installerPin{
			URL:   manifest.DownloadOrigin + "/releases/" + manifest.Release + "/release-manifest.json",
			Bytes: manifestBytes, SHA256: manifestSHA256,
		},
		License: installerPin{
			URL: manifest.ReleaseFiles[0].URL, Bytes: manifest.ReleaseFiles[0].Bytes, SHA256: manifest.ReleaseFiles[0].SHA256,
		},
		Notice: installerPin{
			URL: manifest.ReleaseFiles[1].URL, Bytes: manifest.ReleaseFiles[1].Bytes, SHA256: manifest.ReleaseFiles[1].SHA256,
		},
		LinuxAMD64:  artifacts["linux/amd64"],
		LinuxARM64:  artifacts["linux/arm64"],
		DarwinAMD64: artifacts["darwin/amd64"],
		DarwinARM64: artifacts["darwin/arm64"],
	}
	parsed, err := template.New("installer").Funcs(template.FuncMap{"quote": shellQuote}).Parse(installerScriptTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse installer template: %w", err)
	}
	var payload bytes.Buffer
	if err := parsed.Execute(&payload, data); err != nil {
		return nil, fmt.Errorf("render installer template: %w", err)
	}
	if payload.Len() == 0 || payload.Len() > maxInstallerBytes || !strings.HasSuffix(payload.String(), "\n") || strings.ContainsRune(payload.String(), '\x00') {
		return nil, errors.New("rendered installer exceeds its deterministic output boundary")
	}
	return payload.Bytes(), nil
}

func InstallCommand(installerURL string, installerPayload []byte) ([]byte, error) {
	return installCommandWithOptions(installerURL, installerPayload, productionInstallerRenderOptions)
}

func installCommandWithOptions(installerURL string, installerPayload []byte, options installerRenderOptions) ([]byte, error) {
	if err := validateInstallerRenderOptions(options); err != nil {
		return nil, err
	}
	parsedURL, err := url.Parse(installerURL)
	if err != nil || len(installerURL) > 640 || !strings.HasPrefix(installerURL, "https://") ||
		parsedURL.String() != installerURL || parsedURL.Scheme != "https" || parsedURL.Host == "" || parsedURL.User != nil ||
		parsedURL.RawQuery != "" || parsedURL.Fragment != "" || parsedURL.Opaque != "" || parsedURL.RawPath != "" ||
		parsedURL.Hostname() == "" || parsedURL.Port() != "" || strings.ToLower(parsedURL.Host) != parsedURL.Host ||
		len(parsedURL.Path) > 384 || pathpkg.Clean(parsedURL.Path) != parsedURL.Path || parsedURL.EscapedPath() != parsedURL.Path {
		return nil, errors.New("installer URL must be one canonical direct HTTPS install.sh URL")
	}
	segments := strings.Split(strings.TrimPrefix(parsedURL.Path, "/"), "/")
	releaseIndex := len(segments) - 2
	if len(segments) < 3 || segments[releaseIndex-1] != "releases" ||
		!releaseid.Valid(segments[releaseIndex]) || segments[releaseIndex+1] != "install.sh" {
		return nil, errors.New("installer URL must use the exact download-origin/releases/<release>/install.sh layout")
	}
	for _, segment := range segments {
		if !installerURLSegmentPattern.MatchString(segment) || segment == "." || segment == ".." {
			return nil, errors.New("installer URL contains an unsafe path segment")
		}
	}
	if len(installerPayload) == 0 || len(installerPayload) > maxInstallerBytes ||
		!bytes.HasSuffix(installerPayload, []byte("\n")) || bytes.IndexByte(installerPayload, 0) >= 0 {
		return nil, errors.New("installer payload must be NUL-free, newline-terminated, and within its shell-argument size boundary")
	}
	data := struct {
		ToolPath       string
		EnvPath        string
		ShellPath      string
		InstallerURL   string
		InstallerBytes string
		InstallerSHA   string
	}{
		ToolPath: options.ToolPath, EnvPath: options.EnvPath, ShellPath: options.ShellPath,
		InstallerURL: installerURL, InstallerBytes: fmt.Sprint(len(installerPayload)), InstallerSHA: deployment.SHA256Hex(installerPayload),
	}
	parsed, err := template.New("bootstrap").Funcs(template.FuncMap{"quote": shellQuote}).Parse(installerBootstrapTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse installer bootstrap template: %w", err)
	}
	var program bytes.Buffer
	if err := parsed.Execute(&program, data); err != nil {
		return nil, fmt.Errorf("render installer bootstrap template: %w", err)
	}
	if strings.ContainsRune(program.String(), '\n') || strings.ContainsRune(program.String(), '\x00') {
		return nil, errors.New("installer bootstrap must be one shell program line")
	}
	line := options.EnvPath + " -i HOME=\"${HOME-}\" XDG_DATA_HOME=\"${XDG_DATA_HOME-}\" XDG_STATE_HOME=\"${XDG_STATE_HOME-}\" XDG_CONFIG_HOME=\"${XDG_CONFIG_HOME-}\" XDG_RUNTIME_DIR=\"${XDG_RUNTIME_DIR-}\" PATH=" +
		shellQuote(options.ToolPath) + " LC_ALL=C " + options.ShellPath + " -c " + shellQuote(program.String()) + "\n"
	if strings.Count(line, "\n") != 1 || !strings.HasSuffix(line, "\n") || strings.ContainsRune(line, '\x00') {
		return nil, errors.New("installer command is not exactly one line")
	}
	return []byte(line), nil
}

func validateInstallerRenderOptions(options installerRenderOptions) error {
	if options.ToolPath == "" || options.TTYReadPath == "" || options.TTYWritePath == "" || options.EnvPath == "" || options.ShellPath == "" {
		return errors.New("installer render paths are required")
	}
	for _, path := range strings.Split(options.ToolPath, ":") {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, '\x00') {
			return errors.New("installer tool path must contain only canonical absolute directories")
		}
	}
	for _, path := range []string{options.TTYReadPath, options.TTYWritePath, options.EnvPath, options.ShellPath} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, '\x00') {
			return errors.New("installer runtime path must be canonical and absolute")
		}
	}
	return nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

const installerScriptTemplate = `#!/bin/sh
set -efu
if [ "$#" -eq 0 ]; then
  exec {{quote .EnvPath}} -i HOME="${HOME-}" XDG_DATA_HOME="${XDG_DATA_HOME-}" XDG_STATE_HOME="${XDG_STATE_HOME-}" XDG_CONFIG_HOME="${XDG_CONFIG_HOME-}" XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR-}" PATH={{quote .ToolPath}} LC_ALL=C {{quote .ShellPath}} "$0" --jat-installer-v1-sanitized
fi
if [ "$#" -ne 1 ] || [ "$1" != "--jat-installer-v1-sanitized" ]; then
  printf '%s\n' 'sshserver installer: arguments are not supported' >&2
  exit 2
fi
shift
umask 077
PATH={{quote .ToolPath}}
LC_ALL=C
export PATH LC_ALL

fail() {
  printf '%s\n' "sshserver installer: $*" >&2
  exit 1
}

validate_absolute_path() {
  path_label=$1
  path_value=$2
  case "$path_value" in
    /*) ;;
    *) fail "$path_label must be absolute" ;;
  esac
  case "$path_value" in
    /|*/|*//*|*/./*|*/../*|*/.|*/..) fail "$path_label must be canonical and non-root" ;;
  esac
}

HOME=${HOME-}
XDG_DATA_HOME=${XDG_DATA_HOME-}
XDG_STATE_HOME=${XDG_STATE_HOME-}
XDG_CONFIG_HOME=${XDG_CONFIG_HOME-}
XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR-}
validate_absolute_path HOME "$HOME"
[ -d "$HOME" ] || fail 'HOME is not a directory'
for xdg_pair in "XDG_DATA_HOME:$XDG_DATA_HOME" "XDG_STATE_HOME:$XDG_STATE_HOME" "XDG_CONFIG_HOME:$XDG_CONFIG_HOME" "XDG_RUNTIME_DIR:$XDG_RUNTIME_DIR"; do
  xdg_label=${xdg_pair%%:*}
  xdg_value=${xdg_pair#*:}
  if [ -n "$xdg_value" ]; then
    validate_absolute_path "$xdg_label" "$xdg_value"
  fi
done

# A redirection failure on the POSIX special builtin exec may terminate dash
# before its OR handler runs. Probe each fixed terminal path through the
# regular command builtin first so every supported /bin/sh reports the
# product diagnostic, then retain the descriptors for the exact preview and
# confirmation exchange.
command : 3<{{quote .TTYReadPath}} || fail 'an interactive controlling terminal is required'
command : 4>{{quote .TTYWritePath}} || fail 'an interactive controlling terminal is required'
exec 3<{{quote .TTYReadPath}}
exec 4>{{quote .TTYWritePath}}

tool_path() {
  resolved_tool=$(command -v "$1" 2>/dev/null || true)
  case "$resolved_tool" in
    /*) printf '%s\n' "$resolved_tool" ;;
    *) fail "required tool $1 is unavailable on the fixed system PATH" ;;
  esac
}

curl_tool=$(tool_path curl)
mktemp_tool=$(tool_path mktemp)
wc_tool=$(tool_path wc)
chmod_tool=$(tool_path chmod)
rm_tool=$(tool_path rm)
rmdir_tool=$(tool_path rmdir)
uname_tool=$(tool_path uname)
cat_tool=$(tool_path cat)
env_tool=$(tool_path env)
if checksum_tool=$(command -v sha256sum 2>/dev/null); then
  checksum_kind=sha256sum
elif checksum_tool=$(command -v shasum 2>/dev/null); then
  checksum_kind=shasum
else
  fail 'sha256sum or shasum is required'
fi
case "$checksum_tool" in
  /*) ;;
  *) fail 'checksum tool did not resolve to an absolute system path' ;;
esac

require_supported_curl() {
  curl_version_output=$("$curl_tool" --disable --version) || fail 'query system curl version'
  curl_version=${curl_version_output#curl }
  curl_version=${curl_version%% *}
  curl_version=${curl_version%%-*}
  case "$curl_version" in
    ''|*[!0-9.]*|.*|*.|*..*) fail 'system curl returned an unsupported version string' ;;
  esac
  saved_ifs=$IFS
  IFS=.
  set -- $curl_version
  IFS=$saved_ifs
  [ "$#" -eq 3 ] || fail 'system curl returned an unsupported version string'
  curl_major=$1
  curl_minor=$2
  curl_patch=$3
  case "$curl_major:$curl_minor:$curl_patch" in
    *[!0-9:]*) fail 'system curl returned an unsupported version string' ;;
  esac
  if [ "$curl_major" -lt 7 ] || { [ "$curl_major" -eq 7 ] && [ "$curl_minor" -lt 58 ]; }; then
    fail 'curl 7.58.0 or newer is required for the pinned HTTPS installer'
  fi
}
require_supported_curl

file_sha256() {
  if [ "$checksum_kind" = sha256sum ]; then
    checksum_output=$("$checksum_tool" < "$1") || fail 'sha256sum failed'
  else
    checksum_output=$("$checksum_tool" -a 256 < "$1") || fail 'shasum failed'
  fi
  set -- $checksum_output
  [ "$#" -ge 1 ] || fail 'checksum tool returned no digest'
  printf '%s\n' "$1"
}

verify_exact_file() {
  verification_path=$1
  verification_bytes=$2
  verification_sha256=$3
  verification_label=$4
  [ -f "$verification_path" ] && [ ! -L "$verification_path" ] || fail "$verification_label is not a regular file"
  actual_bytes=$("$wc_tool" -c < "$verification_path") || fail "count $verification_label bytes"
  set -- $actual_bytes
  [ "$#" -eq 1 ] || fail "$verification_label byte count is invalid"
  actual_bytes=$1
  [ "$actual_bytes" = "$verification_bytes" ] || fail "$verification_label byte count mismatch"
  actual_sha256=$(file_sha256 "$verification_path")
  [ "$actual_sha256" = "$verification_sha256" ] || fail "$verification_label SHA-256 mismatch"
}

download_exact() {
  download_url=$1
  expected_bytes=$2
  expected_sha256=$3
  destination=$4
  destination_mode=$5
  [ ! -e "$destination" ] && [ ! -L "$destination" ] || fail 'download destination already exists'
  file_limit_blocks=$(( (expected_bytes + 511) / 512 ))
  [ "$file_limit_blocks" -gt 0 ] || fail 'download file limit is invalid'
  (
    ulimit -c 0 2>/dev/null || exit 96
    trap '' XFSZ
    ulimit -f "$file_limit_blocks" 2>/dev/null || exit 97
    "$curl_tool" --disable --proto '=https' --tlsv1.2 --fail --silent --show-error --connect-timeout 15 --max-time 900 --max-filesize "$expected_bytes" --output "$destination" --url "$download_url"
  ) || fail "download failed or exceeded its independent file limit: $download_url"
  verify_exact_file "$destination" "$expected_bytes" "$expected_sha256" "download: $download_url"
  "$chmod_tool" "$destination_mode" "$destination" || fail 'protect verified download'
}

kernel=$("$uname_tool" -s) || fail 'detect operating system'
machine=$("$uname_tool" -m) || fail 'detect execution architecture'
case "$kernel/$machine" in
  Linux/x86_64|Linux/amd64)
    target=linux/amd64
    artifact_url={{quote .LinuxAMD64.URL}}
    artifact_bytes={{.LinuxAMD64.Bytes}}
    artifact_sha256={{quote .LinuxAMD64.SHA256}}
    ;;
  Linux/aarch64|Linux/arm64)
    target=linux/arm64
    artifact_url={{quote .LinuxARM64.URL}}
    artifact_bytes={{.LinuxARM64.Bytes}}
    artifact_sha256={{quote .LinuxARM64.SHA256}}
    ;;
  Darwin/x86_64|Darwin/amd64)
    target=darwin/amd64
    artifact_url={{quote .DarwinAMD64.URL}}
    artifact_bytes={{.DarwinAMD64.Bytes}}
    artifact_sha256={{quote .DarwinAMD64.SHA256}}
    ;;
  Darwin/arm64|Darwin/aarch64)
    target=darwin/arm64
    artifact_url={{quote .DarwinARM64.URL}}
    artifact_bytes={{.DarwinARM64.Bytes}}
    artifact_sha256={{quote .DarwinARM64.SHA256}}
    ;;
  *) fail "unsupported execution target: $kernel/$machine" ;;
esac

cd "$HOME" || fail 'enter HOME'
physical_home=$(pwd -P) || fail 'resolve physical HOME'
work_dir=$("$mktemp_tool" -d "$physical_home/.jat-sshserver-install.XXXXXXXX") || fail 'create installer workspace'
case "$work_dir" in
  "$physical_home"/.jat-sshserver-install.*) ;;
  *) fail 'mktemp returned an unexpected workspace' ;;
esac
[ -d "$work_dir" ] && [ ! -L "$work_dir" ] || fail 'installer workspace is unsafe'
cd "$work_dir" || fail 'enter installer workspace'
[ "$(pwd -P)" = "$work_dir" ] || fail 'installer workspace identity changed before entry'
"$chmod_tool" 700 . || fail 'protect pinned installer workspace'
cleanup() {
  cleanup_dir=$(pwd -P 2>/dev/null || true)
  "$rm_tool" -f ./release-manifest.json ./LICENSE ./NOTICE ./sshserver ./deployment-preview.json 2>/dev/null || :
  if [ "$cleanup_dir" != "$work_dir" ]; then
    "$rm_tool" -f "$work_dir/release-manifest.json" "$work_dir/LICENSE" "$work_dir/NOTICE" "$work_dir/sshserver" "$work_dir/deployment-preview.json" 2>/dev/null || :
  fi
  cd / || :
  [ -z "$cleanup_dir" ] || "$rmdir_tool" "$cleanup_dir" 2>/dev/null || :
  [ "$cleanup_dir" = "$work_dir" ] || "$rmdir_tool" "$work_dir" 2>/dev/null || :
}
trap cleanup 0

download_exact {{quote .Manifest.URL}} {{.Manifest.Bytes}} {{quote .Manifest.SHA256}} ./release-manifest.json 400
download_exact {{quote .License.URL}} {{.License.Bytes}} {{quote .License.SHA256}} ./LICENSE 400
download_exact {{quote .Notice.URL}} {{.Notice.Bytes}} {{quote .Notice.SHA256}} ./NOTICE 400
download_exact "$artifact_url" "$artifact_bytes" "$artifact_sha256" ./sshserver 500

# A parent rename does not change this shell's current-directory inode, but it
# does stale an earlier physical pathname. Rebind every absolute child input
# after the download hooks and again after the unbounded confirmation wait.
rebind_input_paths() {
  pinned_work_dir=$(pwd -P) || fail 'resolve pinned installer workspace'
  case "$pinned_work_dir" in
    "$physical_home"/.jat-sshserver-install.*) ;;
    *) fail 'installer workspace moved outside the physical home boundary' ;;
  esac
  [ -d "$pinned_work_dir" ] && [ ! -L "$pinned_work_dir" ] || fail 'pinned installer workspace is no longer addressable'
  manifest_path=$pinned_work_dir/release-manifest.json
  license_path=$pinned_work_dir/LICENSE
  notice_path=$pinned_work_dir/NOTICE
  artifact_path=$pinned_work_dir/sshserver
}
rebind_input_paths

run_clean() {
  "$env_tool" -i HOME="$HOME" XDG_DATA_HOME="$XDG_DATA_HOME" XDG_STATE_HOME="$XDG_STATE_HOME" XDG_CONFIG_HOME="$XDG_CONFIG_HOME" XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" PATH="$PATH" LC_ALL=C "$@"
}

verify_exact_file ./sshserver "$artifact_bytes" "$artifact_sha256" 'artifact before deployment preview'
run_clean ./sshserver deploy preview --manifest "$manifest_path" --manifest-sha256 {{quote .Manifest.SHA256}} --artifact "$artifact_path" --license "$license_path" --notice "$notice_path" > ./deployment-preview.json || fail 'verified deployment preview failed'
preview_bytes=$("$wc_tool" -c < ./deployment-preview.json) || fail 'count deployment preview bytes'
set -- $preview_bytes
[ "$#" -eq 1 ] || fail 'deployment preview byte count is invalid'
preview_bytes=$1
case "$preview_bytes" in
  ''|*[!0-9]*) fail 'deployment preview byte count is invalid' ;;
esac
[ "$preview_bytes" -gt 0 ] && [ "$preview_bytes" -le 524288 ] || fail 'deployment preview exceeds its output boundary'
"$chmod_tool" 400 ./deployment-preview.json || fail 'protect deployment preview'
preview_sha256=$(file_sha256 ./deployment-preview.json)
printf '%s\n' "Verified sshserver {{.Release}} deployment preview for $target:" >&4
"$cat_tool" ./deployment-preview.json >&4 || fail 'display deployment preview'
printf '%s' 'Type yes to apply exactly this preview: ' >&4
IFS= read -r confirmation <&3 || fail 'read deployment confirmation'
[ "$confirmation" = yes ] || fail 'installation declined'
"$rm_tool" -f ./deployment-preview.json || fail 'remove confirmed preview file'
exec 3<&-
exec 4>&-

rebind_input_paths
verify_exact_file ./sshserver "$artifact_bytes" "$artifact_sha256" 'artifact before deployment apply'
run_clean ./sshserver deploy apply --manifest "$manifest_path" --manifest-sha256 {{quote .Manifest.SHA256}} --artifact "$artifact_path" --license "$license_path" --notice "$notice_path" --confirmed-preview-sha256 "$preview_sha256" --consume-inputs --supervise-foreground || fail 'verified deployment apply or supervised foreground server failed'
`

var installerBootstrapTemplate = strings.Join([]string{
	`set -efu;`,
	`umask 077;`,
	`PATH={{quote .ToolPath}}; LC_ALL=C; export PATH LC_ALL;`,
	`fail() { printf '%s\n' "sshserver installer bootstrap: $*" >&2; exit 1; };`,
	`tool_path() { bootstrap_tool=$(command -v "$1" 2>/dev/null || true); case "$bootstrap_tool" in /*) printf '%s\n' "$bootstrap_tool" ;; *) fail "required tool $1 is unavailable on the fixed system PATH" ;; esac; };`,
	`curl_tool=$(tool_path curl); mktemp_tool=$(tool_path mktemp); wc_tool=$(tool_path wc); chmod_tool=$(tool_path chmod); rm_tool=$(tool_path rm); rmdir_tool=$(tool_path rmdir); cat_tool=$(tool_path cat); env_tool=$(tool_path env);`,
	`curl_version_output=$("$curl_tool" --disable --version) || fail 'query system curl version';`,
	`curl_version=${curl_version_output#curl }; curl_version=${curl_version%% *}; curl_version=${curl_version%%-*};`,
	`case "$curl_version" in ''|*[!0-9.]*|.*|*.|*..*) fail 'system curl returned an unsupported version string' ;; esac;`,
	`saved_ifs=$IFS; IFS=.; set -- $curl_version; IFS=$saved_ifs; [ "$#" -eq 3 ] || fail 'system curl returned an unsupported version string';`,
	`curl_major=$1; curl_minor=$2; curl_patch=$3; case "$curl_major:$curl_minor:$curl_patch" in *[!0-9:]*) fail 'system curl returned an unsupported version string' ;; esac;`,
	`if [ "$curl_major" -lt 7 ] || { [ "$curl_major" -eq 7 ] && [ "$curl_minor" -lt 58 ]; }; then fail 'curl 7.58.0 or newer is required for the pinned HTTPS installer'; fi;`,
	`if checksum_tool=$(command -v sha256sum 2>/dev/null); then checksum_kind=sha256sum; elif checksum_tool=$(command -v shasum 2>/dev/null); then checksum_kind=shasum; else fail 'sha256sum or shasum is required'; fi;`,
	`case "$checksum_tool" in /*) ;; *) fail 'checksum tool did not resolve to an absolute system path' ;; esac;`,
	`cd /tmp || fail 'enter installer bootstrap root'; bootstrap_root=$(pwd -P) || fail 'resolve installer bootstrap root'; case "$bootstrap_root" in /*) ;; *) fail 'installer bootstrap root is not absolute' ;; esac;`,
	`work_dir=$("$mktemp_tool" -d "$bootstrap_root/jat-sshserver-bootstrap.XXXXXXXX") || fail 'create installer bootstrap workspace';`,
	`case "$work_dir" in "$bootstrap_root"/jat-sshserver-bootstrap.*) ;; *) fail 'mktemp returned an unexpected workspace' ;; esac;`,
	`[ -d "$work_dir" ] && [ ! -L "$work_dir" ] || fail 'installer bootstrap workspace is unsafe';`,
	`cd "$work_dir" || fail 'enter installer bootstrap workspace'; [ "$(pwd -P)" = "$work_dir" ] || fail 'installer bootstrap workspace identity changed before entry'; "$chmod_tool" 700 . || fail 'protect pinned installer bootstrap workspace';`,
	`cleanup() { cleanup_dir=$(pwd -P 2>/dev/null || true); "$rm_tool" -f ./install.sh "$work_dir/install.sh" 2>/dev/null || :; cd / || :; [ -z "$cleanup_dir" ] || "$rmdir_tool" "$cleanup_dir" 2>/dev/null || :; [ "$cleanup_dir" = "$work_dir" ] || "$rmdir_tool" "$work_dir" 2>/dev/null || :; }; trap cleanup 0;`,
	`installer_path=./install.sh; installer_file_limit_blocks=$(( ({{.InstallerBytes}} + 511) / 512 )); [ "$installer_file_limit_blocks" -gt 0 ] || fail 'installer file limit is invalid';`,
	`( ulimit -c 0 2>/dev/null || exit 96; trap '' XFSZ; ulimit -f "$installer_file_limit_blocks" 2>/dev/null || exit 97; "$curl_tool" --disable --proto '=https' --tlsv1.2 --fail --silent --show-error --connect-timeout 15 --max-time 120 --max-filesize {{.InstallerBytes}} --output "$installer_path" --url {{quote .InstallerURL}} ) || fail 'download pinned installer or enforce its independent file limit';`,
	`[ -f "$installer_path" ] && [ ! -L "$installer_path" ] || fail 'installer download is not a regular file'; "$chmod_tool" 400 "$installer_path" || fail 'protect downloaded installer';`,
	`command : 5<"$installer_path" || fail 'open downloaded installer'; exec 5<"$installer_path"; "$rm_tool" -f "$installer_path" || fail 'unlink downloaded installer';`,
	`installer_sentinel=__JAT_INSTALLER_EOF_7f29a4a2__; installer_with_sentinel=$("$cat_tool" <&5 || exit 98; printf '%s' "$installer_sentinel") || fail 'read downloaded installer from retained descriptor'; exec 5<&-;`,
	`case "$installer_with_sentinel" in *"$installer_sentinel") ;; *) fail 'installer sentinel is missing' ;; esac; installer_program=${installer_with_sentinel%"$installer_sentinel"}; unset installer_with_sentinel;`,
	`actual_bytes=$(printf '%s' "$installer_program" | "$wc_tool" -c) || fail 'count retained installer bytes'; set -- $actual_bytes; [ "$#" -eq 1 ] || fail 'installer byte count is invalid'; actual_bytes=$1; [ "$actual_bytes" = {{quote .InstallerBytes}} ] || fail 'installer byte count mismatch';`,
	`if [ "$checksum_kind" = sha256sum ]; then checksum_output=$(printf '%s' "$installer_program" | "$checksum_tool") || fail 'sha256sum failed'; else checksum_output=$(printf '%s' "$installer_program" | "$checksum_tool" -a 256) || fail 'shasum failed'; fi;`,
	`set -- $checksum_output; [ "$#" -ge 1 ] || fail 'checksum tool returned no digest'; [ "$1" = {{quote .InstallerSHA}} ] || fail 'installer SHA-256 mismatch';`,
	`"$env_tool" -i HOME="${HOME-}" XDG_DATA_HOME="${XDG_DATA_HOME-}" XDG_STATE_HOME="${XDG_STATE_HOME-}" XDG_CONFIG_HOME="${XDG_CONFIG_HOME-}" XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR-}" PATH={{quote .ToolPath}} LC_ALL=C {{quote .ShellPath}} -c "$installer_program" install.sh --jat-installer-v1-sanitized`,
}, " ")
