package config

import (
	"encoding/json"
	"reflect"
	"testing"
)

var configJSONFuzzTargets = []struct {
	name           string
	acceptedSeed   []byte
	newDestination func() any
}{
	{
		name:           "settings",
		acceptedSeed:   []byte(`{"config_version":1,"instance_id":"00000000-0000-4000-8000-000000000001","vault_id":"00000000-0000-4000-8000-000000000002","listeners":["127.0.0.1:37421","[::1]:37421"]}`),
		newDestination: func() any { return &Settings{} },
	},
	{
		name:           "install marker",
		acceptedSeed:   []byte(`{"generation":"1","phase":"ready","state":"complete"}`),
		newDestination: func() any { return &InstallMarker{} },
	},
}

func FuzzDecodeConfigJSON(f *testing.F) {
	for _, target := range configJSONFuzzTargets {
		f.Add(target.acceptedSeed)
	}
	f.Add([]byte("127.0.0.1:37421"))
	f.Fuzz(func(t *testing.T, payload []byte) {
		firstListenerErr := ValidateListener(string(payload))
		secondListenerErr := ValidateListener(string(payload))
		if (firstListenerErr == nil) != (secondListenerErr == nil) {
			t.Fatal("listener acceptance changed across identical input")
		}
		for _, target := range configJSONFuzzTargets {
			first := target.newDestination()
			firstErr := decodeStrictJSON(payload, first)
			second := target.newDestination()
			secondErr := decodeStrictJSON(payload, second)
			if (firstErr == nil) != (secondErr == nil) {
				t.Fatalf("%s acceptance changed across identical input", target.name)
			}
			if firstErr != nil {
				continue
			}
			if !reflect.DeepEqual(first, second) {
				t.Fatalf("%s output changed across identical input", target.name)
			}
			encoded, err := json.Marshal(first)
			if err != nil {
				t.Fatalf("marshal accepted %s: %v", target.name, err)
			}
			roundTrip := target.newDestination()
			if err := decodeStrictJSON(encoded, roundTrip); err != nil {
				t.Fatalf("decode re-encoded %s: %v", target.name, err)
			}
			if !reflect.DeepEqual(first, roundTrip) {
				t.Fatalf("%s changed across JSON round trip", target.name)
			}
		}
	})
}

func TestFuzzDecodeConfigJSONAcceptedSeeds(t *testing.T) {
	for _, target := range configJSONFuzzTargets {
		if err := decodeStrictJSON(target.acceptedSeed, target.newDestination()); err != nil {
			t.Fatalf("%s seed rejected: %v", target.name, err)
		}
	}
}
