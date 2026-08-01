// Package uuidv4 implements the protocol's exact lowercase UUIDv4 format
// without adding a runtime dependency.
package uuidv4

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

var ErrInvalid = errors.New("invalid canonical UUIDv4")

// New returns a cryptographically random, lowercase, canonical UUIDv4.
func New() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate UUIDv4: %w", err)
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return Format(value), nil
}

// Parse accepts only the exact lowercase UUIDv4 wire representation.
func Parse(value string) ([16]byte, error) {
	var decoded [16]byte
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return decoded, ErrInvalid
	}
	compact := value[:8] + value[9:13] + value[14:18] + value[19:23] + value[24:]
	if _, err := hex.Decode(decoded[:], []byte(compact)); err != nil {
		return [16]byte{}, ErrInvalid
	}
	if Format(decoded) != value || decoded[6]>>4 != 4 || decoded[8]>>6 != 2 {
		return [16]byte{}, ErrInvalid
	}
	return decoded, nil
}

// Format returns the canonical lowercase representation of value.
func Format(value [16]byte) string {
	var encoded [36]byte
	hex.Encode(encoded[0:8], value[0:4])
	encoded[8] = '-'
	hex.Encode(encoded[9:13], value[4:6])
	encoded[13] = '-'
	hex.Encode(encoded[14:18], value[6:8])
	encoded[18] = '-'
	hex.Encode(encoded[19:23], value[8:10])
	encoded[23] = '-'
	hex.Encode(encoded[24:36], value[10:16])
	return string(encoded[:])
}
