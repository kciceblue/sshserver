// Package buildinfo owns the immutable identity compiled into each release
// artifact. One encoded record is generated before compilation, so the release
// manifest can bind it without creating a self-referential binary hash.
package buildinfo

import (
	"errors"
	"regexp"
	"runtime"
	"strings"
)

const AttestationPrefix = "jat-release-v1|"

// EncodedIdentity is the one production linker assignment. Keeping every
// identity field in one record prevents independently drifted -X values.
var EncodedIdentity = "dev"

var (
	releasePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	revisionPattern  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	toolchainPattern = regexp.MustCompile(`^go[1-9][0-9]*\.[0-9]+\.[0-9]+$`)
	digestPattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type Identity struct {
	Release         string `json:"release"`
	SourceRevision  string `json:"source_revision"`
	BuildToolchain  string `json:"build_toolchain"`
	BuildIdentity   string `json:"build_identity"`
	ProtocolVersion string `json:"protocol_version"`
	StorageSchema   string `json:"storage_schema"`
}

func Encode(identity Identity) (string, error) {
	if err := validate(identity); err != nil {
		return "", err
	}
	return strings.Join([]string{
		strings.TrimSuffix(AttestationPrefix, "|"),
		identity.Release,
		identity.SourceRevision,
		identity.BuildToolchain,
		identity.BuildIdentity,
		identity.ProtocolVersion,
		identity.StorageSchema,
	}, "|"), nil
}

func Parse(value string) (Identity, error) {
	parts := strings.Split(value, "|")
	if len(parts) != 7 || parts[0] != strings.TrimSuffix(AttestationPrefix, "|") {
		return Identity{}, errors.New("build attestation has an invalid field set")
	}
	identity := Identity{
		Release:         parts[1],
		SourceRevision:  parts[2],
		BuildToolchain:  parts[3],
		BuildIdentity:   parts[4],
		ProtocolVersion: parts[5],
		StorageSchema:   parts[6],
	}
	if err := validate(identity); err != nil {
		return Identity{}, err
	}
	return identity, nil
}

func ValidatedCurrent() (Identity, error) {
	if EncodedIdentity == "dev" {
		return Identity{
			Release:         "dev",
			SourceRevision:  "dev",
			BuildToolchain:  runtime.Version(),
			BuildIdentity:   "dev",
			ProtocolVersion: "1",
			StorageSchema:   "1",
		}, nil
	}
	return Parse(EncodedIdentity)
}

func validate(identity Identity) error {
	if !releasePattern.MatchString(identity.Release) || strings.Contains(identity.Release, "..") || strings.EqualFold(identity.Release, "latest") {
		return errors.New("build attestation release is invalid")
	}
	if !revisionPattern.MatchString(identity.SourceRevision) {
		return errors.New("build attestation source revision is invalid")
	}
	if !toolchainPattern.MatchString(identity.BuildToolchain) {
		return errors.New("build attestation toolchain is invalid")
	}
	if !digestPattern.MatchString(identity.BuildIdentity) {
		return errors.New("build attestation identity is invalid")
	}
	if identity.ProtocolVersion != "1" || identity.StorageSchema != "1" {
		return errors.New("build attestation protocol or storage schema is invalid")
	}
	return nil
}
