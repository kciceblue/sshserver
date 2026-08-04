#!/bin/sh
set -efu
if [ "$#" -eq 0 ]; then
  exec '/usr/bin/env' -i HOME="${HOME-}" XDG_DATA_HOME="${XDG_DATA_HOME-}" XDG_STATE_HOME="${XDG_STATE_HOME-}" XDG_CONFIG_HOME="${XDG_CONFIG_HOME-}" XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR-}" PATH='/usr/bin:/bin' LC_ALL=C '/bin/sh' "$0" --jat-installer-v1-sanitized
fi
if [ "$#" -ne 1 ] || [ "$1" != "--jat-installer-v1-sanitized" ]; then
  printf '%s\n' 'sshserver installer: arguments are not supported' >&2
  exit 2
fi
shift
umask 077
PATH='/usr/bin:/bin'
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
command : 3<'/dev/tty' || fail 'an interactive controlling terminal is required'
command : 4>'/dev/tty' || fail 'an interactive controlling terminal is required'
exec 3<'/dev/tty'
exec 4>'/dev/tty'

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
    artifact_url='https://kciceblue.github.io/sshserver/releases/v0.1.0/sshserver-linux-amd64'
    artifact_bytes=17831066
    artifact_sha256='3658b1ea36a87c6d828f4b5ee3c7e8839f408de98426342d92f556ca2f056432'
    ;;
  Linux/aarch64|Linux/arm64)
    target=linux/arm64
    artifact_url='https://kciceblue.github.io/sshserver/releases/v0.1.0/sshserver-linux-arm64'
    artifact_bytes=16840384
    artifact_sha256='cc3b4d986cd4d81a2d4200a67db48a3587f40ca7e1dbfeeec26e7cb1c993d23b'
    ;;
  Darwin/x86_64|Darwin/amd64)
    target=darwin/amd64
    artifact_url='https://kciceblue.github.io/sshserver/releases/v0.1.0/sshserver-darwin-amd64'
    artifact_bytes=17828272
    artifact_sha256='1cb8b0d55be08845efd51ce5b340d24e08799871a19faac9ea04ec520307979c'
    ;;
  Darwin/arm64|Darwin/aarch64)
    target=darwin/arm64
    artifact_url='https://kciceblue.github.io/sshserver/releases/v0.1.0/sshserver-darwin-arm64'
    artifact_bytes=17182722
    artifact_sha256='a7ac875cde84b03e83933b936682da54182f1cf53ff273d1de7106ab43d9daea'
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

download_exact 'https://kciceblue.github.io/sshserver/releases/v0.1.0/release-manifest.json' 2180 'c8ce47fb83fb3a1ea6f16e96916070254a1e535f8b66c2d0b2776e1866751b68' ./release-manifest.json 400
download_exact 'https://kciceblue.github.io/sshserver/releases/v0.1.0/LICENSE' 11357 'c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4' ./LICENSE 400
download_exact 'https://kciceblue.github.io/sshserver/releases/v0.1.0/NOTICE' 2175 'd06400efad26daf67b6fa6dd97e8acce6d391070789ea60762f8b9d8c99a29ea' ./NOTICE 400
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
run_clean ./sshserver deploy preview --manifest "$manifest_path" --manifest-sha256 'c8ce47fb83fb3a1ea6f16e96916070254a1e535f8b66c2d0b2776e1866751b68' --artifact "$artifact_path" --license "$license_path" --notice "$notice_path" > ./deployment-preview.json || fail 'verified deployment preview failed'
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
printf '%s\n' "Verified sshserver v0.1.0 deployment preview for $target:" >&4
"$cat_tool" ./deployment-preview.json >&4 || fail 'display deployment preview'
printf '%s' 'Type yes to apply exactly this preview: ' >&4
IFS= read -r confirmation <&3 || fail 'read deployment confirmation'
[ "$confirmation" = yes ] || fail 'installation declined'
"$rm_tool" -f ./deployment-preview.json || fail 'remove confirmed preview file'
exec 3<&-
exec 4>&-

rebind_input_paths
verify_exact_file ./sshserver "$artifact_bytes" "$artifact_sha256" 'artifact before deployment apply'
run_clean ./sshserver deploy apply --manifest "$manifest_path" --manifest-sha256 'c8ce47fb83fb3a1ea6f16e96916070254a1e535f8b66c2d0b2776e1866751b68' --artifact "$artifact_path" --license "$license_path" --notice "$notice_path" --confirmed-preview-sha256 "$preview_sha256" --consume-inputs --supervise-foreground || fail 'verified deployment apply or supervised foreground server failed'
