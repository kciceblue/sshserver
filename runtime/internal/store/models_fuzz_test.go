package store

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

var strictJSONFuzzTargets = []struct {
	name           string
	acceptedSeed   []byte
	newDestination func() any
}{
	{
		name:           "sync request",
		acceptedSeed:   []byte(`{"protocol_version":"1","device_id":"00000000-0000-4000-8000-000000000003","request_id":"00000000-0000-4000-8000-000000000004","after_cursor":"0","ack_cursor":"0","mutations":[]}`),
		newDestination: func() any { return &syncRequest{} },
	},
	{
		name:           "record revision",
		acceptedSeed:   []byte(`{"record_id":"00000000-0000-4000-8000-000000000020","revision_id":"00000000-0000-4000-8000-000000000021","author_device_id":"00000000-0000-4000-8000-000000000003","author_counter":"1","version_vector":[{"device_id":"00000000-0000-4000-8000-000000000003","counter":"1"}],"collection_witness_authenticator":null,"payload_schema":"1","crypto_suite":"jat-xchacha-hkdf-argon2id-draft2","tombstone":false,"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAA"}`),
		newDestination: func() any { return &recordRevision{} },
	},
	{
		name:           "vault envelope",
		acceptedSeed:   []byte(`{"protocol_version":"1","crypto_suite":"jat-xchacha-hkdf-argon2id-draft2","instance_id":"00000000-0000-4000-8000-000000000001","vault_id":"00000000-0000-4000-8000-000000000002","envelope_generation":"1","instance_secret_generation":"1","mode":"base","hkdf_salt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","argon2":null,"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","wrapped_vmk":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`),
		newDestination: func() any { return &vaultEnvelope{} },
	},
	{
		name:           "revoke device request",
		acceptedSeed:   []byte(`{"request_id":"00000000-0000-4000-8000-000000000004","allow_zero_active":false}`),
		newDestination: func() any { return &revokeDeviceRequest{} },
	},
}

func FuzzDecodeStrictJSON(f *testing.F) {
	for _, target := range strictJSONFuzzTargets {
		f.Add(target.acceptedSeed)
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

func TestFuzzDecodeStrictJSONHasAcceptedSeedForEveryDestination(t *testing.T) {
	for _, target := range strictJSONFuzzTargets {
		t.Run(target.name, func(t *testing.T) {
			if err := decodeStrict(target.acceptedSeed, target.newDestination()); err != nil {
				t.Fatalf("canonical fuzz seed was rejected: %v", err)
			}
		})
	}
}
