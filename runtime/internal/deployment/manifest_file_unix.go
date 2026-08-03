//go:build darwin || linux

package deployment

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// ReadPinnedManifestFile loads a bounded owner-only local manifest without
// following links and authenticates its exact bytes before returning them.
func ReadPinnedManifestFile(path, expectedSHA256 string) ([]byte, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, '\x00') {
		return nil, errors.New("release manifest path must be canonical and absolute")
	}
	payload, err := readDeploymentFile(path, maxManifestBytes)
	if err != nil {
		return nil, fmt.Errorf("read protected release manifest: %w", err)
	}
	if _, err := ParsePinnedManifest(payload, expectedSHA256); err != nil {
		return nil, err
	}
	return payload, nil
}
