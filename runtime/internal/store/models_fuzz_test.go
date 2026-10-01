package store

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

var (
	canonicalBaseVaultEnvelopeFuzzSeed       = []byte(`{"protocol_version":"1","crypto_suite":"jat-xchacha-hkdf-argon2id-draft2","instance_id":"00000000-0000-4000-8000-000000000001","vault_id":"00000000-0000-4000-8000-000000000002","envelope_generation":"1","instance_secret_generation":"1","mode":"base","hkdf_salt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","argon2":null,"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","wrapped_vmk":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)
	canonicalPassphraseVaultEnvelopeFuzzSeed = []byte(`{"protocol_version":"1","crypto_suite":"jat-xchacha-hkdf-argon2id-draft2","instance_id":"00000000-0000-4000-8000-000000000001","vault_id":"00000000-0000-4000-8000-000000000002","envelope_generation":"1","instance_secret_generation":"1","mode":"passphrase","hkdf_salt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","argon2":{"version":19,"salt":"AAAAAAAAAAAAAAAAAAAAAA","memory_kib":65536,"iterations":3,"parallelism":1,"output_length":32},"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","wrapped_vmk":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)
	canonicalPutEnvelopeRequestFuzzSeed      = bytes.Join([][]byte{[]byte(`{"expected_generation":"0","new_generation":"1","envelope":`), canonicalBaseVaultEnvelopeFuzzSeed, []byte(`}`)}, nil)
	mismatchedPutEnvelopeGenerationFuzzSeed  = bytes.Replace(canonicalPutEnvelopeRequestFuzzSeed, []byte(`"expected_generation":"0"`), []byte(`"expected_generation":"1"`), 1)
	parserFuzzIdentity                       = Identity{InstanceID: "00000000-0000-4000-8000-000000000001", VaultID: "00000000-0000-4000-8000-000000000002"}
)

const parserFuzzStoredEnvelopeGeneration uint64 = 0

var strictJSONFuzzTargets = []struct {
	name           string
	acceptedSeeds  [][]byte
	newDestination func() any
	validate       func(any) error
}{
	{
		name:           "enrollment request",
		acceptedSeeds:  [][]byte{[]byte(`{"protocol_version":"1","enrollment_id":"00000000-0000-4000-8000-000000000004","device_id":"00000000-0000-4000-8000-000000000003","device_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","scopes":["devices:manage","devices:read","envelope:read","envelope:write","sync:read","sync:write"]}`)},
		newDestination: func() any { return &enrollmentRequest{} },
		validate: func(destination any) error {
			token, err := validateEnrollmentRequest(*destination.(*enrollmentRequest))
			clear(token)
			return err
		},
	},
	{
		name:           "put envelope request",
		acceptedSeeds:  [][]byte{canonicalPutEnvelopeRequestFuzzSeed},
		newDestination: func() any { return &putEnvelopeRequest{} },
		validate: func(destination any) error {
			request := *destination.(*putEnvelopeRequest)
			newGeneration, err := validatePutEnvelopeRequestGenerations(request, parserFuzzStoredEnvelopeGeneration)
			if err != nil {
				return err
			}
			return validatePutEnvelopeRequestEnvelope(request, parserFuzzIdentity, newGeneration, 1)
		},
	},
	{
		name:           "sync request",
		acceptedSeeds:  [][]byte{[]byte(`{"protocol_version":"1","device_id":"00000000-0000-4000-8000-000000000003","request_id":"00000000-0000-4000-8000-000000000004","after_cursor":"0","ack_cursor":"0","mutations":[]}`)},
		newDestination: func() any { return &syncRequest{} },
		validate: func(destination any) error {
			_, _, err := validateSyncRequest(*destination.(*syncRequest))
			return err
		},
	},
	{
		name:           "snapshot create request",
		acceptedSeeds:  [][]byte{[]byte(`{"protocol_version":"1","device_id":"00000000-0000-4000-8000-000000000003","request_id":"00000000-0000-4000-8000-000000000004","required_capabilities":["authenticated-collection-frontiers-v2","snapshot-collection-markers-v1","snapshot-device-registry-v1","snapshot-read-v1"]}`)},
		newDestination: func() any { return &snapshotCreateRequest{} },
		validate: func(destination any) error {
			return validateSnapshotCreateRequest(*destination.(*snapshotCreateRequest))
		},
	},
	{
		name:           "snapshot page request",
		acceptedSeeds:  [][]byte{[]byte(`{"protocol_version":"1","device_id":"00000000-0000-4000-8000-000000000003","page_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)},
		newDestination: func() any { return &snapshotPageRequest{} },
		validate:       func(destination any) error { return validateSnapshotPageRequest(*destination.(*snapshotPageRequest)) },
	},
	{
		name:           "record revision",
		acceptedSeeds:  [][]byte{canonicalRecordRevisionFuzzSeed},
		newDestination: func() any { return &recordRevision{} },
		validate: func(destination any) error {
			_, _, err := validateRevision(*destination.(*recordRevision))
			return err
		},
	},
	{
		name: "vault envelope",
		acceptedSeeds: [][]byte{
			canonicalBaseVaultEnvelopeFuzzSeed,
			canonicalPassphraseVaultEnvelopeFuzzSeed,
		},
		newDestination: func() any { return &vaultEnvelope{} },
		validate: func(destination any) error {
			_, _, err := validateEnvelope(*destination.(*vaultEnvelope), parserFuzzIdentity)
			return err
		},
	},
	{
		name:           "revoke device request",
		acceptedSeeds:  [][]byte{[]byte(`{"request_id":"00000000-0000-4000-8000-000000000004","allow_zero_active":false}`)},
		newDestination: func() any { return &revokeDeviceRequest{} },
		validate:       func(destination any) error { return validateRevokeDeviceRequest(*destination.(*revokeDeviceRequest)) },
	},
	{
		name:           "token rotation request",
		acceptedSeeds:  [][]byte{[]byte(`{"rotation_id":"00000000-0000-4000-8000-000000000004","device_id":"00000000-0000-4000-8000-000000000003","new_device_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)},
		newDestination: func() any { return &tokenRotationRequest{} },
		validate: func(destination any) error {
			token, err := validateTokenRotationRequest(*destination.(*tokenRotationRequest))
			clear(token)
			return err
		},
	},
}

func FuzzDecodeStrictJSON(f *testing.F) {
	for _, target := range strictJSONFuzzTargets {
		for _, seed := range target.acceptedSeeds {
			f.Add(seed)
		}
	}
	f.Add(mismatchedPutEnvelopeGenerationFuzzSeed)
	f.Fuzz(func(t *testing.T, payload []byte) {
		for _, target := range strictJSONFuzzTargets {
			first := target.newDestination()
			firstErr := decodeStrict(payload, first)
			second := target.newDestination()
			secondErr := decodeStrict(payload, second)
			if (firstErr == nil) != (secondErr == nil) {
				t.Fatalf("strict decoder acceptance changed across identical input: first=%v second=%v", firstErr, secondErr)
			}
			if firstErr == nil && !reflect.DeepEqual(first, second) {
				t.Fatalf("strict decoder output changed across identical input: first=%+v second=%+v", first, second)
			}
			if firstErr != nil {
				continue
			}
			firstValidationErr := target.validate(first)
			secondValidationErr := target.validate(second)
			if (firstValidationErr == nil) != (secondValidationErr == nil) {
				t.Fatalf("%s semantic acceptance changed across identical input: first=%v second=%v", target.name, firstValidationErr, secondValidationErr)
			}
			if firstValidationErr != nil {
				continue
			}

			encoded, err := json.Marshal(first)
			if err != nil {
				t.Fatalf("marshal accepted typed value: %v", err)
			}
			roundTripped := target.newDestination()
			if err := decodeStrict(encoded, roundTripped); err != nil {
				t.Fatalf("strict decoder rejected its typed value encoding: %v; encoded=%q", err, encoded)
			}
			if err := target.validate(roundTripped); err != nil {
				t.Fatalf("%s semantic validator rejected its round-tripped typed value: %v", target.name, err)
			}
			if !reflect.DeepEqual(first, roundTripped) {
				t.Fatalf("typed value changed across encode/decode: first=%+v round_tripped=%+v", first, roundTripped)
			}
			reencoded, err := json.Marshal(roundTripped)
			if err != nil {
				t.Fatalf("marshal round-tripped typed value: %v", err)
			}
			if !bytes.Equal(encoded, reencoded) {
				t.Fatalf("encoding changed after round trip: first=%q second=%q", encoded, reencoded)
			}
		}
	})
}

func TestPutEnvelopeFuzzValidationUsesFixedStoredGeneration(t *testing.T) {
	var request putEnvelopeRequest
	if err := decodeStrict(mismatchedPutEnvelopeGenerationFuzzSeed, &request); err != nil {
		t.Fatalf("decode mismatched put-envelope generation seed: %v", err)
	}
	if _, err := validatePutEnvelopeRequestGenerations(request, parserFuzzStoredEnvelopeGeneration); err == nil {
		t.Fatal("put-envelope fuzz validation accepted a request that mismatches fixed stored generation zero")
	}
	for _, target := range strictJSONFuzzTargets {
		if target.name == "put envelope request" {
			if err := target.validate(&request); err == nil {
				t.Fatal("put-envelope semantic callback accepted the fixed-state mismatch seed")
			}
			return
		}
	}
	t.Fatal("put-envelope strict JSON target is missing")
}

func TestFuzzDecodeStrictJSONHasAcceptedSeedsForEveryDestination(t *testing.T) {
	for _, target := range strictJSONFuzzTargets {
		t.Run(target.name, func(t *testing.T) {
			if len(target.acceptedSeeds) == 0 {
				t.Fatal("strict destination has no canonical accepted seed")
			}
			if target.validate == nil {
				t.Fatal("strict destination has no production semantic validator")
			}
			for seedIndex, seed := range target.acceptedSeeds {
				destination := target.newDestination()
				if err := decodeStrict(seed, destination); err != nil {
					t.Fatalf("canonical fuzz seed %d was rejected: %v", seedIndex, err)
				}
				if err := target.validate(destination); err != nil {
					t.Fatalf("canonical fuzz seed %d failed production semantics: %v", seedIndex, err)
				}
			}
		})
	}
}

func TestFuzzDecodeStrictJSONPassphraseSeedExercisesArgon2Object(t *testing.T) {
	var envelope vaultEnvelope
	if err := decodeStrict(canonicalPassphraseVaultEnvelopeFuzzSeed, &envelope); err != nil {
		t.Fatalf("decode passphrase envelope seed: %v", err)
	}
	identity := Identity{InstanceID: envelope.InstanceID, VaultID: envelope.VaultID}
	if _, _, err := validateEnvelope(envelope, identity); err != nil {
		t.Fatalf("passphrase envelope seed does not satisfy the supported profile: %v", err)
	}
	if envelope.Argon2 == nil {
		t.Fatal("passphrase envelope seed did not traverse the nested Argon2 object")
	}

	var document map[string]any
	if err := json.Unmarshal(canonicalPassphraseVaultEnvelopeFuzzSeed, &document); err != nil {
		t.Fatal(err)
	}
	parameters, ok := document["argon2"].(map[string]any)
	if !ok {
		t.Fatalf("passphrase envelope seed Argon2 value has type %T", document["argon2"])
	}
	for _, field := range []string{"version", "salt", "memory_kib", "iterations", "parallelism", "output_length"} {
		t.Run("missing "+field, func(t *testing.T) {
			adversarialParameters := make(map[string]any, len(parameters)-1)
			for key, value := range parameters {
				if key != field {
					adversarialParameters[key] = value
				}
			}
			document["argon2"] = adversarialParameters
			adversarialSeed, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if err := decodeStrict(adversarialSeed, &vaultEnvelope{}); err == nil {
				t.Fatalf("passphrase envelope missing required Argon2 field %q was accepted", field)
			}
		})
	}
}
