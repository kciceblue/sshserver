// Package deployment implements the verified, user-scoped server deployment
// lifecycle. This file owns the immutable release manifest boundary; no
// downloaded program may execute before its selected artifact satisfies it.
package deployment

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/kciceblue/sshserver/runtime/internal/releaseid"
)

const (
	ManifestVersion     = 1
	maxManifestBytes    = 64 * 1024
	maxArtifactBytes    = 256 * 1024 * 1024
	maxReleaseFileBytes = 4 * 1024 * 1024
)

var (
	hexDigestPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	sourceRevisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	toolchainPattern      = regexp.MustCompile(`^go[1-9][0-9]*\.[0-9]+\.[0-9]+$`)
	urlSegmentPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

type Target struct {
	OS           string
	Architecture string
}

var supportedTargets = []Target{
	{OS: "linux", Architecture: "amd64"},
	{OS: "linux", Architecture: "arm64"},
	{OS: "darwin", Architecture: "amd64"},
	{OS: "darwin", Architecture: "arm64"},
}

type ReleaseManifest struct {
	ManifestVersion int               `json:"manifest_version"`
	Release         string            `json:"release"`
	SourceRevision  string            `json:"source_revision"`
	BuildToolchain  string            `json:"build_toolchain"`
	ProtocolVersion string            `json:"protocol_version"`
	StorageSchema   string            `json:"storage_schema"`
	DownloadOrigin  string            `json:"download_origin"`
	Artifacts       []ReleaseArtifact `json:"artifacts"`
	ReleaseFiles    []ReleaseFile     `json:"release_files"`
}

type ReleaseArtifact struct {
	OS            string `json:"os"`
	Architecture  string `json:"architecture"`
	BuildIdentity string `json:"build_identity"`
	URL           string `json:"url"`
	Bytes         int64  `json:"bytes"`
	SHA256        string `json:"sha256"`
}

type ReleaseFile struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

func ParsePinnedManifest(payload []byte, expectedSHA256 string) (ReleaseManifest, error) {
	var manifest ReleaseManifest
	if len(payload) == 0 || len(payload) > maxManifestBytes {
		return manifest, errors.New("release manifest exceeds its size boundary")
	}
	if !hexDigestPattern.MatchString(expectedSHA256) {
		return manifest, errors.New("release manifest pin must be a lowercase SHA-256 digest")
	}
	digest := sha256.Sum256(payload)
	if !bytes.Equal(digest[:], mustDecodeDigest(expectedSHA256)) {
		return manifest, errors.New("release manifest SHA-256 does not match the pinned digest")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return ReleaseManifest{}, fmt.Errorf("decode release manifest: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ReleaseManifest{}, errors.New("release manifest contains trailing data")
	}
	if err := manifest.Validate(); err != nil {
		return ReleaseManifest{}, err
	}
	canonical, err := manifest.CanonicalBytes()
	if err != nil {
		return ReleaseManifest{}, err
	}
	if !bytes.Equal(payload, canonical) {
		return ReleaseManifest{}, errors.New("release manifest is not in canonical byte form")
	}
	return manifest, nil
}

func (manifest ReleaseManifest) Validate() error {
	if manifest.ManifestVersion != ManifestVersion {
		return fmt.Errorf("unsupported release manifest version %d", manifest.ManifestVersion)
	}
	if !releaseid.Valid(manifest.Release) {
		return errors.New("release identifier is not immutable and path-safe")
	}
	if !sourceRevisionPattern.MatchString(manifest.SourceRevision) {
		return errors.New("release source revision must be an exact lowercase Git commit ID")
	}
	if !toolchainPattern.MatchString(manifest.BuildToolchain) {
		return errors.New("release build toolchain must be an exact Go patch release")
	}
	if manifest.ProtocolVersion != "1" {
		return errors.New("release manifest protocol version must be 1")
	}
	if manifest.StorageSchema != "1" {
		return errors.New("release manifest storage schema must be 1")
	}
	origin, err := parseDownloadOrigin(manifest.DownloadOrigin)
	if err != nil {
		return err
	}
	if len(manifest.Artifacts) != len(supportedTargets) {
		return errors.New("release manifest must contain exactly four supported artifacts")
	}
	for index, target := range supportedTargets {
		artifact := manifest.Artifacts[index]
		if artifact.OS != target.OS || artifact.Architecture != target.Architecture {
			return errors.New("release manifest artifacts are missing or not canonically ordered")
		}
		if artifact.Bytes <= 0 || artifact.Bytes > maxArtifactBytes {
			return fmt.Errorf("%s/%s artifact size is outside the release boundary", artifact.OS, artifact.Architecture)
		}
		if !hexDigestPattern.MatchString(artifact.BuildIdentity) {
			return fmt.Errorf("%s/%s artifact build identity must be lowercase hexadecimal", artifact.OS, artifact.Architecture)
		}
		expectedBuildIdentity, err := DeriveBuildIdentity(manifest.Release, manifest.SourceRevision, manifest.BuildToolchain, target)
		if err != nil || artifact.BuildIdentity != expectedBuildIdentity {
			return fmt.Errorf("%s/%s artifact build identity does not match the deterministic release inputs", artifact.OS, artifact.Architecture)
		}
		if !hexDigestPattern.MatchString(artifact.SHA256) {
			return fmt.Errorf("%s/%s artifact SHA-256 must be lowercase hexadecimal", artifact.OS, artifact.Architecture)
		}
		artifactURL, err := parseReleaseURL(artifact.URL, origin, manifest.Release)
		if err != nil {
			return fmt.Errorf("%s/%s artifact URL is not an exact direct download on the approved origin", artifact.OS, artifact.Architecture)
		}
		wantName := "sshserver-" + artifact.OS + "-" + artifact.Architecture
		if path.Base(artifactURL.Path) != wantName {
			return fmt.Errorf("%s/%s artifact URL must end in %q", artifact.OS, artifact.Architecture, wantName)
		}
	}
	if len(manifest.ReleaseFiles) != 2 || manifest.ReleaseFiles[0].Name != "LICENSE" || manifest.ReleaseFiles[1].Name != "NOTICE" {
		return errors.New("release manifest must contain LICENSE and NOTICE in canonical order")
	}
	for _, releaseFile := range manifest.ReleaseFiles {
		if releaseFile.Bytes <= 0 || releaseFile.Bytes > maxReleaseFileBytes {
			return fmt.Errorf("%s size is outside the release boundary", releaseFile.Name)
		}
		if !hexDigestPattern.MatchString(releaseFile.SHA256) {
			return fmt.Errorf("%s SHA-256 must be lowercase hexadecimal", releaseFile.Name)
		}
		releaseURL, err := parseReleaseURL(releaseFile.URL, origin, manifest.Release)
		if err != nil || path.Base(releaseURL.Path) != releaseFile.Name {
			return fmt.Errorf("%s URL is not an exact direct download on the approved origin", releaseFile.Name)
		}
	}
	return nil
}

func parseReleaseURL(value string, origin *url.URL, release string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != origin.Scheme || parsed.Host != origin.Host ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" ||
		parsed.Path == "" || parsed.RawPath != "" || path.Clean(parsed.Path) != parsed.Path ||
		parsed.EscapedPath() != parsed.Path {
		return nil, errors.New("release URL is not canonical")
	}
	segments := strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
	if len(segments) != 3 || segments[0] != "releases" || segments[1] != release {
		return nil, errors.New("release URL must use the exact /releases/<release>/<file> layout")
	}
	for _, segment := range segments {
		if !urlSegmentPattern.MatchString(segment) || segment == "." || segment == ".." {
			return nil, errors.New("release URL contains an unsafe path segment")
		}
	}
	return parsed, nil
}

func parseDownloadOrigin(value string) (*url.URL, error) {
	origin, err := url.Parse(value)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil ||
		origin.Path != "" || origin.RawPath != "" || origin.RawQuery != "" || origin.Fragment != "" || origin.Opaque != "" {
		return nil, errors.New("download origin must be an exact HTTPS origin without credentials, path, query, or fragment")
	}
	if origin.Hostname() == "" || origin.Port() != "" || strings.Contains(origin.Host, "@") {
		return nil, errors.New("download origin host is not canonical")
	}
	if strings.ToLower(origin.Host) != origin.Host {
		return nil, errors.New("download origin host must be lowercase")
	}
	return origin, nil
}

func (manifest ReleaseManifest) CanonicalBytes() ([]byte, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	payload, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode release manifest: %w", err)
	}
	return append(payload, '\n'), nil
}

func (manifest ReleaseManifest) Artifact(target Target) (ReleaseArtifact, error) {
	if err := manifest.Validate(); err != nil {
		return ReleaseArtifact{}, err
	}
	for _, artifact := range manifest.Artifacts {
		if artifact.OS == target.OS && artifact.Architecture == target.Architecture {
			return artifact, nil
		}
	}
	return ReleaseArtifact{}, fmt.Errorf("release does not support %s/%s", target.OS, target.Architecture)
}

func SupportedTargets() []Target {
	return slices.Clone(supportedTargets)
}

func SHA256Hex(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func DeriveBuildIdentity(release, sourceRevision, buildToolchain string, target Target) (string, error) {
	if !releaseid.Valid(release) {
		return "", errors.New("build identity release is invalid")
	}
	if !sourceRevisionPattern.MatchString(sourceRevision) {
		return "", errors.New("build identity source revision is invalid")
	}
	if !toolchainPattern.MatchString(buildToolchain) {
		return "", errors.New("build identity toolchain is invalid")
	}
	if !isSupportedTarget(target) {
		return "", errors.New("build identity target is unsupported")
	}
	input := strings.Join([]string{
		"sshserver-build-identity-v1",
		"release=" + release,
		"source_revision=" + sourceRevision,
		"build_toolchain=" + buildToolchain,
		"os=" + target.OS,
		"architecture=" + target.Architecture,
		"",
	}, "\n")
	return SHA256Hex([]byte(input)), nil
}

func mustDecodeDigest(value string) []byte {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return decoded
}
