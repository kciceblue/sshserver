package store

import "testing"

func FuzzPathIdentifier(f *testing.F) {
	const identifier = "00000000-0000-4000-8000-000000000003"
	routes := []struct {
		prefix string
		suffix string
	}{
		{prefix: "/v1/devices/", suffix: "/revoke"},
		{prefix: "/v1/snapshot-reads/", suffix: "/pages"},
	}
	f.Add("/v1/devices/" + identifier + "/revoke")
	f.Add("/v1/snapshot-reads/" + identifier + "/pages")
	f.Fuzz(func(t *testing.T, path string) {
		for _, route := range routes {
			first, firstOK := pathIdentifier(path, route.prefix, route.suffix)
			second, secondOK := pathIdentifier(path, route.prefix, route.suffix)
			if firstOK != secondOK || first != second {
				t.Fatalf("route identifier acceptance changed: first=%q/%t second=%q/%t", first, firstOK, second, secondOK)
			}
			if !firstOK {
				continue
			}
			if validateUUID(first) != nil || path != route.prefix+first+route.suffix {
				t.Fatalf("route identifier escaped its production grammar: path=%q identifier=%q", path, first)
			}
			roundTripped, ok := pathIdentifier(route.prefix+first+route.suffix, route.prefix, route.suffix)
			if !ok || roundTripped != first {
				t.Fatalf("route identifier did not round trip: first=%q round_tripped=%q/%t", first, roundTripped, ok)
			}
		}
	})
}

func FuzzOperationReceiptKey(f *testing.F) {
	const targetDeviceID = "00000000-0000-4000-8000-000000000003"
	f.Add("sync", canonicalSyncResponseFuzzSeed)
	f.Add("vault-envelope", canonicalBaseVaultEnvelopeFuzzSeed)
	f.Add("device-revocation/"+targetDeviceID, canonicalRevokedDeviceFuzzSeed)
	f.Fuzz(func(t *testing.T, operation string, body []byte) {
		firstKeyAccepted := validOperationReceiptKey(operation)
		secondKeyAccepted := validOperationReceiptKey(operation)
		if firstKeyAccepted != secondKeyAccepted {
			t.Fatal("operation-receipt key acceptance changed across identical input")
		}

		firstResponseErr := validateStoredOperationResponse(
			operation,
			200,
			body,
			parserFuzzIdentity,
		)
		secondResponseErr := validateStoredOperationResponse(
			operation,
			200,
			body,
			parserFuzzIdentity,
		)
		if (firstResponseErr == nil) != (secondResponseErr == nil) {
			t.Fatalf(
				"stored operation-response acceptance changed: first=%v second=%v",
				firstResponseErr,
				secondResponseErr,
			)
		}
		if firstResponseErr == nil && !firstKeyAccepted {
			t.Fatalf("stored response accepted an invalid operation key %q", operation)
		}
	})
}

func TestFuzzOperationReceiptKeyCanonicalSeeds(t *testing.T) {
	const targetDeviceID = "00000000-0000-4000-8000-000000000003"
	for _, test := range []struct {
		operation string
		body      []byte
	}{
		{operation: "sync", body: canonicalSyncResponseFuzzSeed},
		{operation: "vault-envelope", body: canonicalBaseVaultEnvelopeFuzzSeed},
		{operation: "device-revocation/" + targetDeviceID, body: canonicalRevokedDeviceFuzzSeed},
	} {
		t.Run(test.operation, func(t *testing.T) {
			if !validOperationReceiptKey(test.operation) {
				t.Fatal("canonical operation key was rejected")
			}
			if err := validateStoredOperationResponse(
				test.operation,
				200,
				test.body,
				parserFuzzIdentity,
			); err != nil {
				t.Fatalf("canonical stored response was rejected: %v", err)
			}
		})
	}
}
