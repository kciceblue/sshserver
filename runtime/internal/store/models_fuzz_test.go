package store

import (
	"reflect"
	"testing"
)

func FuzzDecodeStrictJSON(f *testing.F) {
	f.Add([]byte(`{"protocol_version":"1","device_id":"00000000-0000-4000-8000-000000000003","request_id":"00000000-0000-4000-8000-000000000004","after_cursor":"0","ack_cursor":"0","mutations":[]}`))
	f.Add([]byte(`{"request_id":"00000000-0000-4000-8000-000000000004","allow_zero_active":false}`))

	newDestinations := []func() any{
		func() any { return &syncRequest{} },
		func() any { return &recordRevision{} },
		func() any { return &vaultEnvelope{} },
		func() any { return &revokeDeviceRequest{} },
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		for _, newDestination := range newDestinations {
			first := newDestination()
			firstErr := decodeStrict(payload, first)
			second := newDestination()
			secondErr := decodeStrict(payload, second)
			if (firstErr == nil) != (secondErr == nil) {
				t.Fatalf("strict decoder acceptance changed across identical input: first=%v second=%v", firstErr, secondErr)
			}
			if firstErr == nil && !reflect.DeepEqual(first, second) {
				t.Fatalf("strict decoder output changed across identical input: first=%+v second=%+v", first, second)
			}
		}
	})
}
