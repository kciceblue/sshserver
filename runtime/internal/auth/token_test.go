package auth

import (
	"encoding/hex"
	"testing"
)

const (
	testInstanceID = "00000000-0000-4000-8000-000000000001"
	testVaultID    = "00000000-0000-4000-8000-000000000002"
	testDeviceID   = "00000000-0000-4000-8000-000000000003"
)

func TestDeviceTokenHashIsDomainAndIdentityBound(t *testing.T) {
	token := make([]byte, 32)
	for index := range token {
		token[index] = byte(index)
	}
	hash, err := DeviceTokenHash(testInstanceID, testVaultID, testDeviceID, token)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(hash[:]); got != "7079053dfde32cbd77a06af1b757c7380942df625aa021eca0b042977eeb61cf" {
		t.Fatalf("unexpected hash %s", got)
	}

	changed, err := DeviceTokenHash(testInstanceID, testVaultID, "00000000-0000-4000-8000-000000000004", token)
	if err != nil {
		t.Fatal(err)
	}
	if changed == hash {
		t.Fatal("device ID did not bind token hash")
	}
}

func TestEnrollmentGrantHashMatchesFrozenVector(t *testing.T) {
	grant := make([]byte, 32)
	for index := range grant {
		grant[index] = byte(index)
	}
	hash, err := EnrollmentGrantHash(testInstanceID, testVaultID, grant)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(hash[:]); got != "866f5c6cb8cf09a5c95134b5e5137a41bb6aaf5d2a743c17e4f5289947de07e4" {
		t.Fatalf("unexpected hash %s", got)
	}
}

func TestRequestBodyFingerprintMatchesFrozenVector(t *testing.T) {
	fingerprint, err := RequestBodyFingerprint(
		"JAT sync request fingerprint v1",
		testInstanceID,
		testVaultID,
		testDeviceID,
		[]byte(`{"a":1}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(fingerprint[:]); got != "84e348665f14ec9ed192804549aec8a56806dcfd15226db3b3e8e84111ace317" {
		t.Fatalf("unexpected fingerprint %s", got)
	}
}

func TestCredentialAndScopeValidationFailsClosed(t *testing.T) {
	if _, err := DeviceTokenHash(testInstanceID, testVaultID, testDeviceID, make([]byte, 31)); err != ErrCredentialSize {
		t.Fatalf("wrong token length error: %v", err)
	}
	scopes := FixedScopes()
	if err := ValidateScopes(scopes); err != nil {
		t.Fatal(err)
	}
	scopes[0] = "mutated"
	if err := ValidateScopes(FixedScopes()); err != nil {
		t.Fatal("caller mutation changed the canonical scope set")
	}
	partial := FixedScopes()[:len(FixedScopes())-1]
	if err := ValidateScopes(partial); err != ErrScopes {
		t.Fatalf("partial scopes error: %v", err)
	}
}

func TestVerifyHash(t *testing.T) {
	var left, right [32]byte
	left[0] = 1
	right[0] = 1
	if !VerifyHash(left, right) {
		t.Fatal("equal hashes did not verify")
	}
	right[31] = 1
	if VerifyHash(left, right) {
		t.Fatal("different hashes verified")
	}
}
