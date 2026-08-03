package store

import "testing"

func TestDecodeStrictRequiresEveryFrozenWireField(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		destination any
	}{
		{
			name:        "missing mutations",
			body:        `{"protocol_version":"1","device_id":"00000000-0000-4000-8000-000000000003","request_id":"00000000-0000-4000-8000-000000000004","after_cursor":"0","ack_cursor":"0"}`,
			destination: &syncRequest{},
		},
		{
			name:        "null mutations",
			body:        `{"protocol_version":"1","device_id":"00000000-0000-4000-8000-000000000003","request_id":"00000000-0000-4000-8000-000000000004","after_cursor":"0","ack_cursor":"0","mutations":null}`,
			destination: &syncRequest{},
		},
		{
			name:        "missing required nullable revision authenticator",
			body:        `{"record_id":"00000000-0000-4000-8000-000000000020","revision_id":"00000000-0000-4000-8000-000000000021","author_device_id":"00000000-0000-4000-8000-000000000003","author_counter":"1","version_vector":[{"device_id":"00000000-0000-4000-8000-000000000003","counter":"1"}],"payload_schema":"1","crypto_suite":"jat-xchacha-hkdf-argon2id-draft2","tombstone":false,"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAA"}`,
			destination: &recordRevision{},
		},
		{
			name:        "missing required nullable Argon2 object",
			body:        `{"protocol_version":"1","crypto_suite":"jat-xchacha-hkdf-argon2id-draft2","instance_id":"00000000-0000-4000-8000-000000000001","vault_id":"00000000-0000-4000-8000-000000000002","envelope_generation":"1","instance_secret_generation":"1","mode":"base","hkdf_salt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","wrapped_vmk":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`,
			destination: &vaultEnvelope{},
		},
		{
			name:        "missing required false boolean",
			body:        `{"request_id":"00000000-0000-4000-8000-000000000004"}`,
			destination: &revokeDeviceRequest{},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := decodeStrict([]byte(test.body), test.destination); err == nil {
				t.Fatal("incomplete wire object unexpectedly accepted")
			}
		})
	}
}

func TestDecodeStrictAcceptsExplicitNullableFields(t *testing.T) {
	body := []byte(`{"record_id":"00000000-0000-4000-8000-000000000020","revision_id":"00000000-0000-4000-8000-000000000021","author_device_id":"00000000-0000-4000-8000-000000000003","author_counter":"1","version_vector":[{"device_id":"00000000-0000-4000-8000-000000000003","counter":"1"}],"collection_witness_authenticator":null,"payload_schema":"1","crypto_suite":"jat-xchacha-hkdf-argon2id-draft2","tombstone":false,"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAA"}`)
	var revision recordRevision
	if err := decodeStrict(body, &revision); err != nil {
		t.Fatal(err)
	}
}
