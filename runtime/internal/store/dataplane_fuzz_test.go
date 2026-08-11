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
