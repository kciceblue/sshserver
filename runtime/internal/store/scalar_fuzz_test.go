package store

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func FuzzStoredJSONShapes(f *testing.F) {
	f.Add([]byte(`[]`))
	f.Add(canonicalBaseVaultEnvelopeFuzzSeed)
	f.Add([]byte(`{"revision_ids":[],"collection_markers":[],"source_devices":[],"next_page_token":null,"has_more":false}`))
	f.Fuzz(func(t *testing.T, payload []byte) {
		for _, newDestination := range []func() any{
			func() any { return &[]string{} },
			func() any { return &vaultEnvelope{} },
			func() any { return &recordRevision{} },
			func() any { return &[]vectorEntry{} },
			func() any { return &collectionMarker{} },
			func() any { return &snapshotPageDescriptor{} },
		} {
			first := newDestination()
			firstErr := json.Unmarshal(payload, first)
			second := newDestination()
			secondErr := json.Unmarshal(payload, second)
			if (firstErr == nil) != (secondErr == nil) {
				t.Fatal("stored JSON-shape acceptance changed across identical input")
			}
			if firstErr != nil {
				continue
			}
			if !reflect.DeepEqual(first, second) {
				t.Fatal("stored JSON-shape output changed across identical input")
			}
			encoded, err := json.Marshal(first)
			if err != nil {
				t.Fatal(err)
			}
			roundTrip := newDestination()
			if err := json.Unmarshal(encoded, roundTrip); err != nil || !reflect.DeepEqual(first, roundTrip) {
				t.Fatalf("stored JSON shape did not round trip: error=%v", err)
			}
		}
	})
}

func FuzzStoreScalarAndStoredParsers(f *testing.F) {
	base64Token := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	marker := []byte(`{"record_id":"00000000-0000-4000-8000-000000000020","witness_revision_id":"00000000-0000-4000-8000-000000000021","frontier":[{"device_id":"00000000-0000-4000-8000-000000000003","counter":"1"}],"collection_witness_authenticator":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","barrier_cursor":"1"}`)
	descriptor := []byte(`{"revision_ids":[],"collection_markers":[],"source_devices":[],"next_page_token":null,"has_more":false}`)
	f.Add("1", base64Token, "Bearer "+base64Token, marker, descriptor)
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

		firstAuthorization, firstAuthorizationErr := parseAuthorization(authorization, "Bearer")
		secondAuthorization, secondAuthorizationErr := parseAuthorization(authorization, "Bearer")
		if (firstAuthorizationErr == nil) != (secondAuthorizationErr == nil) || !bytes.Equal(firstAuthorization, secondAuthorization) {
			t.Fatal("authorization parser changed across identical input")
		}
		clear(firstAuthorization)
		clear(secondAuthorization)

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
