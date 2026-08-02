// Package auth contains the server's credential-hash boundary. It does not
// implement vault encryption or parse client payloads.
package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"

	"github.com/kciceblue/sshserver/runtime/internal/uuidv4"
)

const credentialSize = 32

var (
	ErrCredentialSize = errors.New("credential must contain exactly 32 bytes")
	ErrScopes         = errors.New("scopes must equal the fixed V1 scope set")
)

// fixedScopes is the sorted, complete V1 device scope set. Keep it private so
// callers cannot mutate the authorization profile for the whole process.
var fixedScopes = [...]string{
	"devices:manage",
	"devices:read",
	"envelope:read",
	"envelope:write",
	"sync:read",
	"sync:write",
}

// FixedScopes returns a fresh copy of the canonical V1 device scope set.
func FixedScopes() []string {
	return append([]string(nil), fixedScopes[:]...)
}

// ValidateScopes rejects partial, additional, duplicate, and reordered V1
// scope sets. Enrollment persists this one canonical representation.
func ValidateScopes(scopes []string) error {
	if !slices.Equal(scopes, fixedScopes[:]) {
		return ErrScopes
	}
	return nil
}

// VerifyHash compares a stored credential hash with a freshly computed hash
// without leaking the matching prefix through comparison timing.
func VerifyHash(stored, computed [32]byte) bool {
	return subtle.ConstantTimeCompare(stored[:], computed[:]) == 1
}

// DeviceTokenHash implements SYNC-PROTOCOL.md section 6 exactly.
func DeviceTokenHash(instanceID, vaultID, deviceID string, token []byte) ([32]byte, error) {
	if len(token) != credentialSize {
		return [32]byte{}, ErrCredentialSize
	}
	instanceBytes, err := uuidv4.Parse(instanceID)
	if err != nil {
		return [32]byte{}, fmt.Errorf("instance ID: %w", err)
	}
	vaultBytes, err := uuidv4.Parse(vaultID)
	if err != nil {
		return [32]byte{}, fmt.Errorf("vault ID: %w", err)
	}
	deviceBytes, err := uuidv4.Parse(deviceID)
	if err != nil {
		return [32]byte{}, fmt.Errorf("device ID: %w", err)
	}

	hash := sha256.New()
	writeLengthPrefixed(hash, []byte("JAT device token hash v1"))
	hash.Write(instanceBytes[:])
	hash.Write(vaultBytes[:])
	hash.Write(deviceBytes[:])
	hash.Write(token)
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result, nil
}

// EnrollmentGrantHash implements SYNC-PROTOCOL.md section 6 exactly. Only the
// returned digest is persisted; the plaintext grant exists only in the
// daemon's bounded bootstrap response and the protected SSH channel.
func EnrollmentGrantHash(instanceID, vaultID string, grant []byte) ([32]byte, error) {
	if len(grant) != credentialSize {
		return [32]byte{}, ErrCredentialSize
	}
	instanceBytes, err := uuidv4.Parse(instanceID)
	if err != nil {
		return [32]byte{}, fmt.Errorf("instance ID: %w", err)
	}
	vaultBytes, err := uuidv4.Parse(vaultID)
	if err != nil {
		return [32]byte{}, fmt.Errorf("vault ID: %w", err)
	}
	hash := sha256.New()
	writeLengthPrefixed(hash, []byte("JAT enrollment grant hash v1"))
	hash.Write(instanceBytes[:])
	hash.Write(vaultBytes[:])
	hash.Write(grant)
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result, nil
}

// RequestBodyFingerprint binds exact raw authenticated request bytes to the
// instance, vault, device, and operation-specific domain. Callers choose only
// fixed source-code labels; no untrusted text is used as a domain.
func RequestBodyFingerprint(label, instanceID, vaultID, deviceID string, body []byte) ([32]byte, error) {
	instanceBytes, err := uuidv4.Parse(instanceID)
	if err != nil {
		return [32]byte{}, fmt.Errorf("instance ID: %w", err)
	}
	vaultBytes, err := uuidv4.Parse(vaultID)
	if err != nil {
		return [32]byte{}, fmt.Errorf("vault ID: %w", err)
	}
	deviceBytes, err := uuidv4.Parse(deviceID)
	if err != nil {
		return [32]byte{}, fmt.Errorf("device ID: %w", err)
	}
	hash := sha256.New()
	writeLengthPrefixed(hash, []byte(label))
	hash.Write(instanceBytes[:])
	hash.Write(vaultBytes[:])
	hash.Write(deviceBytes[:])
	writeLengthPrefixed(hash, body)
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result, nil
}

type writer interface {
	Write([]byte) (int, error)
}

func writeLengthPrefixed(destination writer, value []byte) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = destination.Write(length[:])
	_, _ = destination.Write(value)
}
