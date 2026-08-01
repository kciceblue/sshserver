package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

type vectorEntry struct {
	DeviceID string `json:"device_id"`
	Counter  string `json:"counter"`
}

type recordCase struct {
	RevisionID                         string        `json:"revision_id"`
	AuthorCounter                      string        `json:"author_counter"`
	Tombstone                          bool          `json:"tombstone"`
	VersionVector                      []vectorEntry `json:"version_vector"`
	CollectionWitnessAuthenticatorKind int           `json:"collection_witness_authenticator_kind"`
	CollectionWitnessAuthenticator     *string       `json:"collection_witness_authenticator"`
	RecordNonceHex                     string        `json:"record_nonce_hex"`
}

type vectorFixture struct {
	ProposedSuite string `json:"proposed_suite"`
	Inputs        struct {
		ProtocolMajor             uint16                `json:"protocol_major"`
		CryptoSuiteID             uint16                `json:"crypto_suite_id"`
		InstanceID                string                `json:"instance_id"`
		VaultID                   string                `json:"vault_id"`
		RecordID                  string                `json:"record_id"`
		DeviceID                  string                `json:"device_id"`
		RecordCases               map[string]recordCase `json:"record_cases"`
		InstanceSecretHex         string                `json:"instance_secret_hex"`
		VMKHex                    string                `json:"vmk_hex"`
		HKDFSaltHex               string                `json:"hkdf_salt_hex"`
		Argon2SaltHex             string                `json:"argon2_salt_hex"`
		PassphraseUTF8HexAfterNFC string                `json:"passphrase_utf8_hex_after_nfc"`
		EnvelopeNonceHex          string                `json:"envelope_nonce_hex"`
		RecordPlaintextUTF8Hex    string                `json:"record_plaintext_utf8_hex"`
	} `json:"inputs"`
	ProposedArgon2ID struct {
		Version      uint32 `json:"version"`
		MemoryKiB    uint32 `json:"memory_kib"`
		Iterations   uint32 `json:"iterations"`
		Parallelism  uint8  `json:"parallelism"`
		OutputLength uint32 `json:"output_length"`
	} `json:"proposed_argon2id"`
}

type envelopeReference struct {
	EnvelopeGeneration       string `json:"envelope_generation"`
	InstanceSecretGeneration string `json:"instance_secret_generation"`
	Mode                     string `json:"mode"`
}

type envelopeFixture struct {
	BaseMode struct {
		Envelope envelopeReference `json:"envelope"`
	} `json:"base_mode"`
	PassphraseRewrap struct {
		Envelope envelopeReference `json:"envelope"`
	} `json:"passphrase_rewrap"`
}

type outputs struct {
	BaseWrapKeyHex                                    string `json:"base_wrap_key_hex"`
	BaseEnvelopeADHex                                 string `json:"base_envelope_ad_hex"`
	BaseWrappedVMKHex                                 string `json:"base_wrapped_vmk_hex"`
	PassphraseMaterialHex                             string `json:"passphrase_material_hex"`
	PassphraseWrapKeyHex                              string `json:"passphrase_wrap_key_hex"`
	PassphraseWrappedVMKHex                           string `json:"passphrase_wrapped_vmk_hex"`
	RecordKeyHex                                      string `json:"record_key_hex"`
	CollectionWitnessKeyHex                           string `json:"collection_witness_key_hex"`
	AuthorizedCollectionWitnessAuthenticatorBase64URL string `json:"authorized_collection_witness_authenticator_base64url"`
	InitialLiveRecordADHex                            string `json:"initial_live_record_ad_hex"`
	InitialLiveRecordCiphertextHex                    string `json:"initial_live_record_ciphertext_hex"`
	AuthorizedSupersedingRecordADHex                  string `json:"authorized_superseding_record_ad_hex"`
	AuthorizedSupersedingRecordCiphertextHex          string `json:"authorized_superseding_record_ciphertext_hex"`
	TamperedADResult                                  string `json:"tampered_ad_result"`
	WrongPassphraseResult                             string `json:"wrong_passphrase_result"`
	RewrapPreservesVMK                                bool   `json:"rewrap_preserves_vmk"`
}

func mustHex(value string) []byte {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return decoded
}

func appendU8(target []byte, value byte) []byte {
	return append(target, value)
}

func appendU16(target []byte, value uint16) []byte {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], value)
	return append(target, encoded[:]...)
}

func appendU32(target []byte, value uint32) []byte {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	return append(target, encoded[:]...)
}

func appendU64(target []byte, value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return append(target, encoded[:]...)
}

func appendLP(target []byte, value []byte) []byte {
	target = appendU32(target, uint32(len(value)))
	return append(target, value...)
}

func parseUint64(value string) uint64 {
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		panic(err)
	}
	return parsed
}

func uuidBytes(value string) []byte {
	compact := strings.ReplaceAll(value, "-", "")
	decoded := mustHex(compact)
	if len(decoded) != 16 {
		panic("UUID must decode to 16 bytes")
	}
	return decoded
}

func hkdfExtract(salt, ikm []byte) []byte {
	mac := hmac.New(sha256.New, salt)
	_, _ = mac.Write(ikm)
	return mac.Sum(nil)
}

func hkdfExpand32(prk, info []byte) []byte {
	mac := hmac.New(sha256.New, prk)
	_, _ = mac.Write(info)
	_, _ = mac.Write([]byte{1})
	return mac.Sum(nil)
}

func wrapKey(fixture vectorFixture, mode byte, passphraseMaterial []byte) []byte {
	instanceSecret := mustHex(fixture.Inputs.InstanceSecretHex)
	hkdfSalt := mustHex(fixture.Inputs.HKDFSaltHex)
	ikm := appendLP(nil, instanceSecret)
	ikm = appendLP(ikm, passphraseMaterial)
	prk := hkdfExtract(hkdfSalt, ikm)
	info := appendLP(nil, []byte("JAT vault wrapping key v1"))
	info = append(info, uuidBytes(fixture.Inputs.InstanceID)...)
	info = append(info, uuidBytes(fixture.Inputs.VaultID)...)
	info = appendU8(info, mode)
	return hkdfExpand32(prk, info)
}

func envelopeAD(fixture vectorFixture, reference envelopeReference) []byte {
	mode := byte(0)
	argonSalt := []byte{}
	version := uint32(0)
	memory := uint32(0)
	iterations := uint32(0)
	parallelism := uint32(0)
	if reference.Mode == "passphrase" {
		mode = 1
		argonSalt = mustHex(fixture.Inputs.Argon2SaltHex)
		version = fixture.ProposedArgon2ID.Version
		memory = fixture.ProposedArgon2ID.MemoryKiB
		iterations = fixture.ProposedArgon2ID.Iterations
		parallelism = uint32(fixture.ProposedArgon2ID.Parallelism)
	} else if reference.Mode != "base" {
		panic("unknown envelope mode")
	}

	ad := appendLP(nil, []byte("JAT vault envelope AD v1"))
	ad = appendU16(ad, fixture.Inputs.ProtocolMajor)
	ad = appendU16(ad, fixture.Inputs.CryptoSuiteID)
	ad = append(ad, uuidBytes(fixture.Inputs.InstanceID)...)
	ad = append(ad, uuidBytes(fixture.Inputs.VaultID)...)
	ad = appendU64(ad, parseUint64(reference.EnvelopeGeneration))
	ad = appendU64(ad, parseUint64(reference.InstanceSecretGeneration))
	ad = appendU8(ad, mode)
	ad = appendLP(ad, mustHex(fixture.Inputs.HKDFSaltHex))
	ad = appendLP(ad, argonSalt)
	ad = appendU32(ad, version)
	ad = appendU32(ad, memory)
	ad = appendU32(ad, iterations)
	ad = appendU32(ad, parallelism)
	return ad
}

func recordKey(fixture vectorFixture, label string) []byte {
	vmk := mustHex(fixture.Inputs.VMKHex)
	prk := hkdfExtract(uuidBytes(fixture.Inputs.RecordID), vmk)
	info := appendLP(nil, []byte(label))
	info = appendU16(info, fixture.Inputs.ProtocolMajor)
	info = appendU16(info, fixture.Inputs.CryptoSuiteID)
	info = append(info, uuidBytes(fixture.Inputs.InstanceID)...)
	info = append(info, uuidBytes(fixture.Inputs.VaultID)...)
	info = append(info, uuidBytes(fixture.Inputs.RecordID)...)
	return hkdfExpand32(prk, info)
}

func canonicalVector(entries []vectorEntry) []vectorEntry {
	result := append([]vectorEntry(nil), entries...)
	sort.Slice(result, func(i, j int) bool {
		return bytes.Compare(uuidBytes(result[i].DeviceID), uuidBytes(result[j].DeviceID)) < 0
	})
	return result
}

func witnessAuthenticator(fixture vectorFixture, key []byte, test recordCase) []byte {
	message := appendLP(nil, []byte("JAT collection witness authenticator v1"))
	message = appendU16(message, fixture.Inputs.ProtocolMajor)
	message = appendU16(message, fixture.Inputs.CryptoSuiteID)
	message = append(message, uuidBytes(fixture.Inputs.InstanceID)...)
	message = append(message, uuidBytes(fixture.Inputs.VaultID)...)
	message = append(message, uuidBytes(fixture.Inputs.RecordID)...)
	message = append(message, uuidBytes(test.RevisionID)...)
	vector := canonicalVector(test.VersionVector)
	message = appendU16(message, uint16(len(vector)))
	for _, entry := range vector {
		message = append(message, uuidBytes(entry.DeviceID)...)
		message = appendU64(message, parseUint64(entry.Counter))
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(message)
	return mac.Sum(nil)
}

func recordAD(fixture vectorFixture, test recordCase, authenticator []byte) []byte {
	ad := appendLP(nil, []byte("JAT record revision AD v1"))
	ad = appendU16(ad, fixture.Inputs.ProtocolMajor)
	ad = appendU16(ad, fixture.Inputs.CryptoSuiteID)
	ad = append(ad, uuidBytes(fixture.Inputs.InstanceID)...)
	ad = append(ad, uuidBytes(fixture.Inputs.VaultID)...)
	ad = append(ad, uuidBytes(fixture.Inputs.RecordID)...)
	ad = append(ad, uuidBytes(test.RevisionID)...)
	ad = append(ad, uuidBytes(fixture.Inputs.DeviceID)...)
	ad = appendU64(ad, parseUint64(test.AuthorCounter))
	ad = appendU16(ad, 1)
	if test.Tombstone {
		ad = appendU8(ad, 1)
	} else {
		ad = appendU8(ad, 0)
	}
	vector := canonicalVector(test.VersionVector)
	ad = appendU16(ad, uint16(len(vector)))
	for _, entry := range vector {
		ad = append(ad, uuidBytes(entry.DeviceID)...)
		ad = appendU64(ad, parseUint64(entry.Counter))
	}
	ad = appendU8(ad, byte(test.CollectionWitnessAuthenticatorKind))
	if test.CollectionWitnessAuthenticatorKind == 1 {
		if len(authenticator) != 32 {
			panic("authorized witness must contain 32 bytes")
		}
		ad = append(ad, authenticator...)
	} else if test.CollectionWitnessAuthenticatorKind != 0 {
		panic("unsupported witness kind")
	}
	return ad
}

func xSeal(key, nonce, plaintext, ad []byte) []byte {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		panic(err)
	}
	return aead.Seal(nil, nonce, plaintext, ad)
}

func xOpen(key, nonce, ciphertext, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, ad)
}

func derive(fixture vectorFixture, envelopes envelopeFixture) outputs {
	if fixture.ProposedSuite != "jat-xchacha-hkdf-argon2id-draft2" {
		panic("unexpected suite")
	}
	if fixture.ProposedArgon2ID.Version != argon2.Version {
		panic("unexpected Argon2 version")
	}
	if fixture.ProposedArgon2ID.OutputLength != 32 {
		panic("unexpected Argon2 output length")
	}

	baseKey := wrapKey(fixture, 0, nil)
	passphrase := mustHex(fixture.Inputs.PassphraseUTF8HexAfterNFC)
	argonSalt := mustHex(fixture.Inputs.Argon2SaltHex)
	passphraseMaterial := argon2.IDKey(
		passphrase,
		argonSalt,
		fixture.ProposedArgon2ID.Iterations,
		fixture.ProposedArgon2ID.MemoryKiB,
		fixture.ProposedArgon2ID.Parallelism,
		fixture.ProposedArgon2ID.OutputLength,
	)
	passphraseKey := wrapKey(fixture, 1, passphraseMaterial)
	baseAD := envelopeAD(fixture, envelopes.BaseMode.Envelope)
	passphraseAD := envelopeAD(fixture, envelopes.PassphraseRewrap.Envelope)
	nonce := mustHex(fixture.Inputs.EnvelopeNonceHex)
	vmk := mustHex(fixture.Inputs.VMKHex)
	baseCiphertext := xSeal(baseKey, nonce, vmk, baseAD)
	passphraseCiphertext := xSeal(passphraseKey, nonce, vmk, passphraseAD)

	recordKeyBytes := recordKey(fixture, "JAT record key v1")
	witnessKey := recordKey(fixture, "JAT collection witness key v1")
	authorized := fixture.Inputs.RecordCases["authorized_superseding_live"]
	authenticator := witnessAuthenticator(fixture, witnessKey, authorized)
	initial := fixture.Inputs.RecordCases["initial_live_null_authorization"]
	initialAD := recordAD(fixture, initial, nil)
	authorizedAD := recordAD(fixture, authorized, authenticator)
	plaintext := mustHex(fixture.Inputs.RecordPlaintextUTF8Hex)
	initialCiphertext := xSeal(recordKeyBytes, mustHex(initial.RecordNonceHex), plaintext, initialAD)
	authorizedCiphertext := xSeal(recordKeyBytes, mustHex(authorized.RecordNonceHex), plaintext, authorizedAD)

	tamperedAD := append([]byte(nil), baseAD...)
	tamperedAD[len(tamperedAD)-1] ^= 1
	_, tamperedErr := xOpen(baseKey, nonce, baseCiphertext, tamperedAD)
	if tamperedErr == nil {
		panic("tampered associated data unexpectedly authenticated")
	}

	wrongPassphrase := append(append([]byte(nil), passphrase...), 0)
	wrongMaterial := argon2.IDKey(
		wrongPassphrase,
		argonSalt,
		fixture.ProposedArgon2ID.Iterations,
		fixture.ProposedArgon2ID.MemoryKiB,
		fixture.ProposedArgon2ID.Parallelism,
		fixture.ProposedArgon2ID.OutputLength,
	)
	wrongKey := wrapKey(fixture, 1, wrongMaterial)
	_, wrongErr := xOpen(wrongKey, nonce, passphraseCiphertext, passphraseAD)
	if wrongErr == nil {
		panic("wrong passphrase unexpectedly authenticated")
	}

	basePlaintext, err := xOpen(baseKey, nonce, baseCiphertext, baseAD)
	if err != nil {
		panic(err)
	}
	passphrasePlaintext, err := xOpen(passphraseKey, nonce, passphraseCiphertext, passphraseAD)
	if err != nil {
		panic(err)
	}

	return outputs{
		BaseWrapKeyHex:          hex.EncodeToString(baseKey),
		BaseEnvelopeADHex:       hex.EncodeToString(baseAD),
		BaseWrappedVMKHex:       hex.EncodeToString(baseCiphertext),
		PassphraseMaterialHex:   hex.EncodeToString(passphraseMaterial),
		PassphraseWrapKeyHex:    hex.EncodeToString(passphraseKey),
		PassphraseWrappedVMKHex: hex.EncodeToString(passphraseCiphertext),
		RecordKeyHex:            hex.EncodeToString(recordKeyBytes),
		CollectionWitnessKeyHex: hex.EncodeToString(witnessKey),
		AuthorizedCollectionWitnessAuthenticatorBase64URL: base64.RawURLEncoding.EncodeToString(authenticator),
		InitialLiveRecordADHex:                            hex.EncodeToString(initialAD),
		InitialLiveRecordCiphertextHex:                    hex.EncodeToString(initialCiphertext),
		AuthorizedSupersedingRecordADHex:                  hex.EncodeToString(authorizedAD),
		AuthorizedSupersedingRecordCiphertextHex:          hex.EncodeToString(authorizedCiphertext),
		TamperedADResult:                                  "authentication_failed",
		WrongPassphraseResult:                             "authentication_failed",
		RewrapPreservesVMK:                                bytes.Equal(basePlaintext, vmk) && bytes.Equal(passphrasePlaintext, vmk),
	}
}

func loadJSON(path string, target any) error {
	payload, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: crypto-kat <crypto-review-vectors.json> <vault-envelope.json>")
		os.Exit(2)
	}
	var fixture vectorFixture
	var envelopes envelopeFixture
	if err := loadJSON(os.Args[1], &fixture); err != nil {
		panic(err)
	}
	if err := loadJSON(os.Args[2], &envelopes); err != nil {
		panic(err)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(derive(fixture, envelopes)); err != nil {
		panic(err)
	}
}
