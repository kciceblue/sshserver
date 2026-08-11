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
)

var strictJSONFuzzTargets = []struct {
	name           string
	acceptedSeeds  [][]byte
	newDestination func() any
}{
	{
		name:           "enrollment request",
		acceptedSeeds:  [][]byte{[]byte(`{"protocol_version":"1","enrollment_id":"00000000-0000-4000-8000-000000000004","device_id":"00000000-0000-4000-8000-000000000003","device_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","scopes":["devices:manage","devices:read","envelope:read","envelope:write","sync:read","sync:write"]}`)},
		newDestination: func() any { return &enrollmentRequest{} },
	},
	{
		name:           "put envelope request",
		acceptedSeeds:  [][]byte{append([]byte(`{"expected_generation":"0","new_generation":"1","envelope":`), append(canonicalBaseVaultEnvelopeFuzzSeed, '}')...)},
		newDestination: func() any { return &putEnvelopeRequest{} },
	},
	{
		name:           "sync request",
		acceptedSeeds:  [][]byte{[]byte(`{"protocol_version":"1","device_id":"00000000-0000-4000-8000-000000000003","request_id":"00000000-0000-4000-8000-000000000004","after_cursor":"0","ack_cursor":"0","mutations":[]}`)},
		newDestination: func() any { return &syncRequest{} },
	},
	{
		name:           "snapshot create request",
		acceptedSeeds:  [][]byte{[]byte(`{"protocol_version":"1","device_id":"00000000-0000-4000-8000-000000000003","request_id":"00000000-0000-4000-8000-000000000004","required_capabilities":["snapshot-device-registry-v1","snapshot-collection-markers-v1"]}`)},
		newDestination: func() any { return &snapshotCreateRequest{} },
	},
	{
		name:           "snapshot page request",
		acceptedSeeds:  [][]byte{[]byte(`{"protocol_version":"1","device_id":"00000000-0000-4000-8000-000000000003","page_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)},
		newDestination: func() any { return &snapshotPageRequest{} },
	},
	{
		name:           "record revision",
		acceptedSeeds:  [][]byte{canonicalRecordRevisionFuzzSeed},
		newDestination: func() any { return &recordRevision{} },
	},
	{
		name: "vault envelope",
		acceptedSeeds: [][]byte{
			canonicalBaseVaultEnvelopeFuzzSeed,
			canonicalPassphraseVaultEnvelopeFuzzSeed,
		},
		newDestination: func() any { return &vaultEnvelope{} },
	},
	{
		name:           "revoke device request",
		acceptedSeeds:  [][]byte{[]byte(`{"request_id":"00000000-0000-4000-8000-000000000004","allow_zero_active":false}`)},
		newDestination: func() any { return &revokeDeviceRequest{} },
	},
	{
		name:           "token rotation request",
		acceptedSeeds:  [][]byte{[]byte(`{"rotation_id":"00000000-0000-4000-8000-000000000004","device_id":"00000000-0000-4000-8000-000000000003","new_device_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)},
		newDestination: func() any { return &tokenRotationRequest{} },
	},
}

func FuzzDecodeStrictJSON(f *testing.F) {
	for _, target := range strictJSONFuzzTargets {
		for _, seed := range target.acceptedSeeds {
			f.Add(seed)
		}
	}
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

			encoded, err := json.Marshal(first)
			if err != nil {
				t.Fatalf("marshal accepted typed value: %v", err)
			}
			roundTripped := target.newDestination()
			if err := decodeStrict(encoded, roundTripped); err != nil {
				t.Fatalf("strict decoder rejected its typed value encoding: %v; encoded=%q", err, encoded)
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

func TestFuzzDecodeStrictJSONHasAcceptedSeedsForEveryDestination(t *testing.T) {
	for _, target := range strictJSONFuzzTargets {
		t.Run(target.name, func(t *testing.T) {
			if len(target.acceptedSeeds) == 0 {
				t.Fatal("strict destination has no canonical accepted seed")
			}
			for seedIndex, seed := range target.acceptedSeeds {
				if err := decodeStrict(seed, target.newDestination()); err != nil {
					t.Fatalf("canonical fuzz seed %d was rejected: %v", seedIndex, err)
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
