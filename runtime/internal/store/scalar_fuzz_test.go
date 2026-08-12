package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/api"
	"github.com/kciceblue/sshserver/runtime/internal/auth"
)

type storedJSONShapeFuzzTarget struct {
	name           string
	acceptedSeeds  [][]byte
	newDestination func() any
	validate       func([]byte, any) error
	exactAccept    func(any) bool
}

var (
	canonicalRecordRevisionFuzzSeed     = []byte(`{"record_id":"00000000-0000-4000-8000-000000000020","revision_id":"00000000-0000-4000-8000-000000000021","author_device_id":"00000000-0000-4000-8000-000000000003","author_counter":"1","version_vector":[{"device_id":"00000000-0000-4000-8000-000000000003","counter":"1"}],"collection_witness_authenticator":null,"payload_schema":"1","crypto_suite":"jat-xchacha-hkdf-argon2id-draft2","tombstone":false,"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAA"}`)
	canonicalActiveDeviceFuzzSeed       = []byte(`{"device_id":"00000000-0000-4000-8000-000000000003","scopes":["devices:manage","devices:read","envelope:read","envelope:write","sync:read","sync:write"],"status":"active","created_at":"2026-08-03T10:00:00.000Z","revoked_at":null,"last_sync_at":null,"ack_cursor":"0","max_author_counter":"0"}`)
	canonicalRevokedDeviceFuzzSeed      = []byte(`{"device_id":"00000000-0000-4000-8000-000000000003","scopes":["devices:manage","devices:read","envelope:read","envelope:write","sync:read","sync:write"],"status":"revoked","created_at":"2026-08-03T10:00:00.000Z","revoked_at":"2026-08-03T10:00:00.000Z","last_sync_at":null,"ack_cursor":"0","max_author_counter":"0"}`)
	canonicalSyncResponseFuzzSeed       = []byte(`{"protocol_version":"1","server_cursor":"0","next_cursor":"0","has_more":false,"envelope_generation":"1","changes":[]}`)
	canonicalEnrollmentResponseFuzzSeed = bytes.Join([][]byte{
		[]byte(`{"protocol_version":"1","instance_id":"00000000-0000-4000-8000-000000000001","vault_id":"00000000-0000-4000-8000-000000000002","device":`),
		canonicalActiveDeviceFuzzSeed,
		[]byte(`,"envelope_generation":"1","became_first_active_device":false}`),
	}, nil)
	canonicalSnapshotCreateResponseFuzzSeed = bytes.Join([][]byte{
		[]byte(`{"protocol_version":"1","snapshot_id":"00000000-0000-4000-8000-000000000004","cut_cursor":"0","envelope_generation":"1","envelope":`),
		canonicalBaseVaultEnvelopeFuzzSeed,
		[]byte(`,"expires_at":"2026-08-03T10:00:00.000Z","first_page_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`),
	}, nil)
	canonicalSelfRevocationHeadersFuzzSeed = mustMarshalStoredFuzzSeed(api.V1ResponseHeaders(
		"00000000-0000-4000-8000-000000000004",
		len(canonicalRevokedDeviceFuzzSeed),
	))
)

func mustMarshalStoredFuzzSeed(value any) []byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return encoded
}

var storedJSONShapeFuzzTargets = []storedJSONShapeFuzzTarget{
	{
		name:           "device scopes",
		acceptedSeeds:  [][]byte{[]byte(`["devices:manage","devices:read","envelope:read","envelope:write","sync:read","sync:write"]`)},
		newDestination: func() any { return &[]string{} },
		validate: func(_ []byte, destination any) error {
			return auth.ValidateScopes(*destination.(*[]string))
		},
		exactAccept: func(destination any) bool {
			return exactFixedScopeSet(*destination.(*[]string))
		},
	},
	{
		name:           "self-revocation response headers",
		acceptedSeeds:  [][]byte{canonicalSelfRevocationHeadersFuzzSeed},
		newDestination: func() any { return &[]api.Header{} },
		validate: func(_ []byte, destination any) error {
			expected := api.V1ResponseHeaders("00000000-0000-4000-8000-000000000004", len(canonicalRevokedDeviceFuzzSeed))
			if !slices.Equal(*destination.(*[]api.Header), expected) {
				return errors.New("stored self-revocation headers are invalid")
			}
			return nil
		},
	},
	{
		name:           "vault envelope",
		acceptedSeeds:  [][]byte{canonicalBaseVaultEnvelopeFuzzSeed, canonicalPassphraseVaultEnvelopeFuzzSeed},
		newDestination: func() any { return &vaultEnvelope{} },
		validate: func(_ []byte, destination any) error {
			_, _, err := validateEnvelope(*destination.(*vaultEnvelope), parserFuzzIdentity)
			return err
		},
	},
	{
		name:           "record revision",
		acceptedSeeds:  [][]byte{canonicalRecordRevisionFuzzSeed},
		newDestination: func() any { return &recordRevision{} },
		validate: func(_ []byte, destination any) error {
			_, _, err := validateRevision(*destination.(*recordRevision))
			return err
		},
	},
	{
		name:           "version vector",
		acceptedSeeds:  [][]byte{[]byte(`[{"device_id":"00000000-0000-4000-8000-000000000003","counter":"1"}]`)},
		newDestination: func() any { return &[]vectorEntry{} },
		validate: func(_ []byte, destination any) error {
			_, err := validateVector(*destination.(*[]vectorEntry))
			return err
		},
	},
	{
		name:           "collection marker",
		acceptedSeeds:  [][]byte{[]byte(`{"record_id":"00000000-0000-4000-8000-000000000020","witness_revision_id":"00000000-0000-4000-8000-000000000021","frontier":[{"device_id":"00000000-0000-4000-8000-000000000003","counter":"1"}],"collection_witness_authenticator":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","barrier_cursor":"1"}`)},
		newDestination: func() any { return &collectionMarker{} },
		validate: func(_ []byte, destination any) error {
			_, _, authenticator, err := validateCollectionMarker(*destination.(*collectionMarker))
			clear(authenticator)
			return err
		},
	},
	{
		name:           "snapshot page descriptor",
		acceptedSeeds:  [][]byte{[]byte(`{"revision_ids":[],"collection_markers":[],"source_devices":[],"next_page_token":null,"has_more":false}`)},
		newDestination: func() any { return &snapshotPageDescriptor{} },
		validate: func(payload []byte, destination any) error {
			return decodeStoredSnapshotPageDescriptor(payload, destination.(*snapshotPageDescriptor))
		},
	},
	{
		name:           "sync response",
		acceptedSeeds:  [][]byte{canonicalSyncResponseFuzzSeed},
		newDestination: func() any { return &syncResponse{} },
		validate: func(_ []byte, destination any) error {
			return validateSyncResponse(*destination.(*syncResponse))
		},
	},
	{
		name:           "device response",
		acceptedSeeds:  [][]byte{canonicalActiveDeviceFuzzSeed},
		newDestination: func() any { return &device{} },
		validate: func(_ []byte, destination any) error {
			return validateDevice(*destination.(*device))
		},
	},
	{
		name:           "enrollment response",
		acceptedSeeds:  [][]byte{canonicalEnrollmentResponseFuzzSeed},
		newDestination: func() any { return &enrollmentResponse{} },
		validate: func(payload []byte, _ any) error {
			return validateStoredEnrollmentResponse(payload, parserFuzzIdentity, "00000000-0000-4000-8000-000000000003")
		},
	},
	{
		name:           "snapshot-create response",
		acceptedSeeds:  [][]byte{canonicalSnapshotCreateResponseFuzzSeed},
		newDestination: func() any { return &snapshotCreateResponse{} },
		validate: func(payload []byte, _ any) error {
			return validateStoredSnapshotCreateResponse(
				payload,
				parserFuzzIdentity,
				"00000000-0000-4000-8000-000000000004",
				"00000000-0000-4000-8000-000000000003",
				0,
				1,
				time.Date(2026, time.August, 3, 10, 0, 0, 0, time.UTC).UnixMilli(),
			)
		},
	},
}

func FuzzStoredJSONShapes(f *testing.F) {
	for _, target := range storedJSONShapeFuzzTargets {
		for _, seed := range target.acceptedSeeds {
			f.Add(seed)
		}
	}
	for _, rejectedScopeSeed := range [][]byte{
		[]byte(`["devices:read","devices:manage","envelope:read","envelope:write","sync:read","sync:write"]`),
		[]byte(`["devices:manage","devices:read","envelope:read","envelope:write","sync:read","sync:write","sync:admin"]`),
		[]byte(`["devices:manage","devices:read","envelope:read","envelope:write","sync:read","sync:write","sync:write"]`),
		[]byte(`["devices:manage","devices:read","envelope:read","envelope:write","sync:read"]`),
		[]byte(`["Devices:manage","devices:read","envelope:read","envelope:write","sync:read","sync:write"]`),
	} {
		f.Add(rejectedScopeSeed)
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		for _, target := range storedJSONShapeFuzzTargets {
			first := target.newDestination()
			firstErr := decodeStoredCanonical(payload, first)
			second := target.newDestination()
			secondErr := decodeStoredCanonical(payload, second)
			if (firstErr == nil) != (secondErr == nil) {
				t.Fatalf("%s acceptance changed across identical input", target.name)
			}
			if firstErr != nil {
				continue
			}
			if !reflect.DeepEqual(first, second) {
				t.Fatalf("%s output changed across identical input", target.name)
			}
			firstValidationErr := target.validate(payload, first)
			secondValidationErr := target.validate(payload, second)
			if (firstValidationErr == nil) != (secondValidationErr == nil) {
				t.Fatalf("%s semantic acceptance changed across identical input: first=%v second=%v", target.name, firstValidationErr, secondValidationErr)
			}
			if target.exactAccept != nil {
				firstWant := target.exactAccept(first)
				secondWant := target.exactAccept(second)
				if (firstValidationErr == nil) != firstWant || (secondValidationErr == nil) != secondWant || firstWant != secondWant {
					t.Fatalf("%s production acceptance first=%v second=%v exact first=%v second=%v", target.name, firstValidationErr == nil, secondValidationErr == nil, firstWant, secondWant)
				}
			}
			if firstValidationErr != nil {
				continue
			}
			encoded, err := json.Marshal(first)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(encoded, payload) {
				t.Fatalf("%s accepted noncanonical bytes", target.name)
			}
			roundTrip := target.newDestination()
			if err := decodeStoredCanonical(encoded, roundTrip); err != nil || !reflect.DeepEqual(first, roundTrip) {
				t.Fatalf("%s did not round trip: error=%v", target.name, err)
			}
			if err := target.validate(encoded, roundTrip); err != nil {
				t.Fatalf("%s semantic validator rejected its round trip: %v", target.name, err)
			}
		}
	})
}

func TestFuzzStoredJSONShapesHasAcceptedSeedsForEveryDestination(t *testing.T) {
	for _, target := range storedJSONShapeFuzzTargets {
		t.Run(target.name, func(t *testing.T) {
			if len(target.acceptedSeeds) == 0 {
				t.Fatal("stored JSON destination has no canonical accepted seed")
			}
			if target.validate == nil {
				t.Fatal("stored JSON destination has no production semantic validator")
			}
			for seedIndex, seed := range target.acceptedSeeds {
				destination := target.newDestination()
				if err := decodeStoredCanonical(seed, destination); err != nil {
					t.Fatalf("canonical seed %d was rejected: %v", seedIndex, err)
				}
				if err := target.validate(seed, destination); err != nil {
					t.Fatalf("canonical seed %d failed production semantics: %v", seedIndex, err)
				}
				if target.exactAccept != nil && !target.exactAccept(destination) {
					t.Fatalf("canonical seed %d failed its independent exact oracle", seedIndex)
				}
			}
		})
	}
}

func exactFixedScopeSet(scopes []string) bool {
	expected := [...]string{
		"devices:manage",
		"devices:read",
		"envelope:read",
		"envelope:write",
		"sync:read",
		"sync:write",
	}
	if len(scopes) != len(expected) {
		return false
	}
	for index := range expected {
		if scopes[index] != expected[index] {
			return false
		}
	}
	return true
}

func FuzzStoreScalarAndStoredParsers(f *testing.F) {
	base64Token := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	diverseBase64Token := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	marker := []byte(`{"record_id":"00000000-0000-4000-8000-000000000020","witness_revision_id":"00000000-0000-4000-8000-000000000021","frontier":[{"device_id":"00000000-0000-4000-8000-000000000003","counter":"1"}],"collection_witness_authenticator":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","barrier_cursor":"1"}`)
	descriptor := []byte(`{"revision_ids":[],"collection_markers":[],"source_devices":[],"next_page_token":null,"has_more":false}`)
	for _, authorization := range []string{
		"Bearer " + base64Token,
		"Bearer " + diverseBase64Token,
		"JAT-Enrollment " + base64Token,
		"JAT-Enrollment " + diverseBase64Token,
		"bearer " + base64Token,
		"Bearer  " + base64Token,
		"Bearer\t" + base64Token,
		"Bearer " + base64Token[:len(base64Token)-1],
		"Bearer " + base64Token + "=",
		"Bearer +" + base64Token[1:],
		"Bearer " + base64Token[:len(base64Token)-1] + "B",
	} {
		f.Add("1", base64Token, authorization, marker, descriptor)
	}
	f.Fuzz(func(t *testing.T, numberText, base64Text, authorization string, markerBody, descriptorBody []byte) {
		firstNumber, firstNumberErr := parseUint64(numberText)
		secondNumber, secondNumberErr := parseUint64(numberText)
		if (firstNumberErr == nil) != (secondNumberErr == nil) || firstNumber != secondNumber {
			t.Fatal("uint64 text parser changed across identical input")
		}

		firstBase64, firstBase64Err := decodeBase64(base64Text, 32, 0, 0)
		secondBase64, secondBase64Err := decodeBase64(base64Text, 32, 0, 0)
		if (firstBase64Err == nil) != (secondBase64Err == nil) || !bytes.Equal(firstBase64, secondBase64) {
			t.Fatal("base64 parser changed across identical input")
		}
		clear(firstBase64)
		clear(secondBase64)

		for _, scheme := range []string{"Bearer", "JAT-Enrollment"} {
			firstAuthorization, firstAuthorizationErr := parseAuthorization(authorization, scheme)
			secondAuthorization, secondAuthorizationErr := parseAuthorization(authorization, scheme)
			wantAuthorization, wantAuthorizationOK := exactAuthorization(authorization, scheme)
			if (firstAuthorizationErr == nil) != wantAuthorizationOK || (secondAuthorizationErr == nil) != wantAuthorizationOK {
				t.Fatalf("%s authorization acceptance first=%v second=%v want=%v", scheme, firstAuthorizationErr == nil, secondAuthorizationErr == nil, wantAuthorizationOK)
			}
			if wantAuthorizationOK && (!bytes.Equal(firstAuthorization, wantAuthorization) || !bytes.Equal(secondAuthorization, wantAuthorization)) {
				t.Fatalf("%s authorization bytes differ from exact grammar", scheme)
			}
			clear(firstAuthorization)
			clear(secondAuthorization)
			clear(wantAuthorization)
		}

		firstMarker, firstMarkerErr := decodeStoredCollectionMarker(markerBody)
		secondMarker, secondMarkerErr := decodeStoredCollectionMarker(markerBody)
		if (firstMarkerErr == nil) != (secondMarkerErr == nil) || !reflect.DeepEqual(firstMarker, secondMarker) {
			t.Fatal("stored collection-marker parser changed across identical input")
		}

		var firstDescriptor, secondDescriptor snapshotPageDescriptor
		firstDescriptorErr := decodeStoredSnapshotPageDescriptor(descriptorBody, &firstDescriptor)
		secondDescriptorErr := decodeStoredSnapshotPageDescriptor(descriptorBody, &secondDescriptor)
		if (firstDescriptorErr == nil) != (secondDescriptorErr == nil) || !reflect.DeepEqual(firstDescriptor, secondDescriptor) {
			t.Fatal("stored snapshot-page parser changed across identical input")
		}

		firstUint64BytesErr := decodeUint64Error([]byte(numberText))
		secondUint64BytesErr := decodeUint64Error([]byte(numberText))
		if (firstUint64BytesErr == nil) != (secondUint64BytesErr == nil) {
			t.Fatal("stored uint64 parser changed across identical input")
		}
		firstTokenErr := decodeBase64Token(base64Text)
		secondTokenErr := decodeBase64Token(base64Text)
		if (firstTokenErr == nil) != (secondTokenErr == nil) {
			t.Fatal("stored token parser changed across identical input")
		}
	})
}

func exactAuthorization(value, scheme string) ([]byte, bool) {
	prefix := scheme + " "
	if len(value) != len(prefix)+43 || value[:len(prefix)] != prefix {
		return nil, false
	}
	return exactRawURLToken32(value[len(prefix):])
}

func exactRawURLToken32(value string) ([]byte, bool) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	if len(value) != 43 {
		return nil, false
	}
	decoded := make([]byte, 0, 32)
	var accumulator uint32
	bits := 0
	for index := 0; index < len(value); index++ {
		sextet := -1
		for alphabetIndex := 0; alphabetIndex < len(alphabet); alphabetIndex++ {
			if value[index] == alphabet[alphabetIndex] {
				sextet = alphabetIndex
				break
			}
		}
		if sextet < 0 {
			clear(decoded)
			return nil, false
		}
		accumulator = accumulator<<6 | uint32(sextet)
		bits += 6
		if bits >= 8 {
			bits -= 8
			decoded = append(decoded, byte(accumulator>>bits))
			if bits == 0 {
				accumulator = 0
			} else {
				accumulator &= 1<<bits - 1
			}
		}
	}
	if len(decoded) != 32 || bits != 2 || accumulator != 0 {
		clear(decoded)
		return nil, false
	}
	return decoded, true
}
