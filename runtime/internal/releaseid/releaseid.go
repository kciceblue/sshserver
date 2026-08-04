// Package releaseid defines the one immutable release identifier grammar used
// by manifests, build attestations, deployment state, and filesystem layouts.
package releaseid

import "regexp"

const (
	// Pattern is also published by packaging/release-manifest.schema.json.
	// Capturing groups keep the expression compatible with Go's RE2 syntax.
	Pattern  = `^v?[0-9]+\.[0-9]+\.[0-9]+(-[a-z0-9]+([.-][a-z0-9]+)*)?$`
	maxBytes = 64
)

var pattern = regexp.MustCompile(Pattern)

// Valid reports whether value is one exact, bounded release version rather
// than a moving channel name or another path-safe but mutable label.
func Valid(value string) bool {
	return len(value) > 0 && len(value) <= maxBytes && pattern.MatchString(value)
}
