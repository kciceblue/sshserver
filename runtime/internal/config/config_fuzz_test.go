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
	validate       func(any) error
}{
	{
		name:           "settings",
		acceptedSeed:   []byte(`{"config_version":1,"instance_id":"00000000-0000-4000-8000-000000000001","vault_id":"00000000-0000-4000-8000-000000000002","listeners":["127.0.0.1:37421","[::1]:37421"]}`),
		newDestination: func() any { return &Settings{} },
		validate: func(value any) error {
			return value.(*Settings).Validate()
		},
	},
	{
		name:           "install marker",
		acceptedSeed:   []byte(`{"generation":"1","phase":"ready","state":"complete"}`),
		newDestination: func() any { return &InstallMarker{} },
		validate: func(value any) error {
			return value.(*InstallMarker).Validate()
		},
	},
}

func FuzzDecodeConfigJSON(f *testing.F) {
	for _, target := range configJSONFuzzTargets {
		f.Add(target.acceptedSeed)
	}
	f.Add([]byte("127.0.0.1:37421"))
	f.Add([]byte("/tmp/jat-state"))
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > maxConfigBytes+1 {
			return
		}
		path := string(payload)
		wantPath := len(payload) > 0 && payload[0] == '/' && !containsZeroByte(payload)
		if got := validAbsolutePath(path); got != wantPath {
			t.Fatalf("absolute-path acceptance=%v want=%v for %q", got, wantPath, path)
		}
		firstListenerErr := ValidateListener(string(payload))
		secondListenerErr := ValidateListener(string(payload))
		if (firstListenerErr == nil) != (secondListenerErr == nil) {
			t.Fatal("listener acceptance changed across identical input")
		}
		for _, target := range configJSONFuzzTargets {
			first := target.newDestination()
			firstErr := decodeStrictJSON(payload, first)
			if firstErr == nil {
				firstErr = target.validate(first)
			}
			second := target.newDestination()
			secondErr := decodeStrictJSON(payload, second)
			if secondErr == nil {
				secondErr = target.validate(second)
			}
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
			if err := target.validate(roundTrip); err != nil {
				t.Fatalf("validate re-encoded %s: %v", target.name, err)
			}
			if !reflect.DeepEqual(first, roundTrip) {
				t.Fatalf("%s changed across JSON round trip", target.name)
			}
		}
	})
}

func containsZeroByte(value []byte) bool {
	for _, item := range value {
		if item == 0 {
			return true
		}
	}
	return false
}

func TestFuzzDecodeConfigJSONAcceptedSeeds(t *testing.T) {
	for _, target := range configJSONFuzzTargets {
		destination := target.newDestination()
		if err := decodeStrictJSON(target.acceptedSeed, destination); err != nil {
			t.Fatalf("%s seed rejected: %v", target.name, err)
		}
		if err := target.validate(destination); err != nil {
			t.Fatalf("%s seed failed production semantics: %v", target.name, err)
		}
	}
}
