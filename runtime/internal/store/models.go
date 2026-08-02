package store

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kciceblue/sshserver/runtime/internal/auth"
	"github.com/kciceblue/sshserver/runtime/internal/config"
	"github.com/kciceblue/sshserver/runtime/internal/uuidv4"
)

const (
	cryptoSuite = "jat-xchacha-hkdf-argon2id-draft2"

	maxBodyBytes = 4 * 1024 * 1024
	maxMutations = 256
	maxChanges   = 128
)

var requiredSnapshotCapabilities = []string{
	"authenticated-collection-frontiers-v2",
	"snapshot-collection-markers-v1",
	"snapshot-device-registry-v1",
	"snapshot-read-v1",
}

type vectorEntry struct {
	DeviceID string `json:"device_id"`
	Counter  string `json:"counter"`
}

type recordRevision struct {
	RecordID                       string        `json:"record_id"`
	RevisionID                     string        `json:"revision_id"`
	AuthorDeviceID                 string        `json:"author_device_id"`
	AuthorCounter                  string        `json:"author_counter"`
	VersionVector                  []vectorEntry `json:"version_vector"`
	CollectionWitnessAuthenticator *string       `json:"collection_witness_authenticator"`
	PayloadSchema                  string        `json:"payload_schema"`
	CryptoSuite                    string        `json:"crypto_suite"`
	Tombstone                      bool          `json:"tombstone"`
	Nonce                          string        `json:"nonce"`
	Ciphertext                     string        `json:"ciphertext"`
}

type argon2Parameters struct {
	Version      int    `json:"version"`
	Salt         string `json:"salt"`
	MemoryKiB    int    `json:"memory_kib"`
	Iterations   int    `json:"iterations"`
	Parallelism  int    `json:"parallelism"`
	OutputLength int    `json:"output_length"`
}

type vaultEnvelope struct {
	ProtocolVersion          string            `json:"protocol_version"`
	CryptoSuite              string            `json:"crypto_suite"`
	InstanceID               string            `json:"instance_id"`
	VaultID                  string            `json:"vault_id"`
	EnvelopeGeneration       string            `json:"envelope_generation"`
	InstanceSecretGeneration string            `json:"instance_secret_generation"`
	Mode                     string            `json:"mode"`
	HKDFSalt                 string            `json:"hkdf_salt"`
	Argon2                   *argon2Parameters `json:"argon2"`
	Nonce                    string            `json:"nonce"`
	WrappedVMK               string            `json:"wrapped_vmk"`
}

type device struct {
	DeviceID         string   `json:"device_id"`
	Scopes           []string `json:"scopes"`
	Status           string   `json:"status"`
	CreatedAt        string   `json:"created_at"`
	RevokedAt        *string  `json:"revoked_at"`
	LastSyncAt       *string  `json:"last_sync_at"`
	AckCursor        string   `json:"ack_cursor"`
	MaxAuthorCounter string   `json:"max_author_counter"`
}

type collectionMarker struct {
	RecordID                       string        `json:"record_id"`
	WitnessRevisionID              string        `json:"witness_revision_id"`
	Frontier                       []vectorEntry `json:"frontier"`
	CollectionWitnessAuthenticator string        `json:"collection_witness_authenticator"`
	BarrierCursor                  string        `json:"barrier_cursor"`
}

type change struct {
	Cursor           string            `json:"cursor"`
	Kind             string            `json:"kind"`
	ReceivedAt       string            `json:"received_at"`
	RecordRevision   *recordRevision   `json:"record_revision"`
	CollectionMarker *collectionMarker `json:"collection_marker"`
}

type enrollmentRequest struct {
	ProtocolVersion string   `json:"protocol_version"`
	EnrollmentID    string   `json:"enrollment_id"`
	DeviceID        string   `json:"device_id"`
	DeviceToken     string   `json:"device_token"`
	Scopes          []string `json:"scopes"`
}

type enrollmentResponse struct {
	ProtocolVersion         string `json:"protocol_version"`
	InstanceID              string `json:"instance_id"`
	VaultID                 string `json:"vault_id"`
	Device                  device `json:"device"`
	EnvelopeGeneration      string `json:"envelope_generation"`
	BecameFirstActiveDevice bool   `json:"became_first_active_device"`
}

type putEnvelopeRequest struct {
	ExpectedGeneration string        `json:"expected_generation"`
	NewGeneration      string        `json:"new_generation"`
	Envelope           vaultEnvelope `json:"envelope"`
}

type syncRequest struct {
	ProtocolVersion string           `json:"protocol_version"`
	DeviceID        string           `json:"device_id"`
	RequestID       string           `json:"request_id"`
	AfterCursor     string           `json:"after_cursor"`
	AckCursor       string           `json:"ack_cursor"`
	Mutations       []recordRevision `json:"mutations"`
}

type syncResponse struct {
	ProtocolVersion    string   `json:"protocol_version"`
	ServerCursor       string   `json:"server_cursor"`
	NextCursor         string   `json:"next_cursor"`
	HasMore            bool     `json:"has_more"`
	EnvelopeGeneration string   `json:"envelope_generation"`
	Changes            []change `json:"changes"`
}

type snapshotCreateRequest struct {
	ProtocolVersion      string   `json:"protocol_version"`
	DeviceID             string   `json:"device_id"`
	RequestID            string   `json:"request_id"`
	RequiredCapabilities []string `json:"required_capabilities"`
}

type snapshotCreateResponse struct {
	ProtocolVersion    string        `json:"protocol_version"`
	SnapshotID         string        `json:"snapshot_id"`
	CutCursor          string        `json:"cut_cursor"`
	EnvelopeGeneration string        `json:"envelope_generation"`
	Envelope           vaultEnvelope `json:"envelope"`
	ExpiresAt          string        `json:"expires_at"`
	FirstPageToken     string        `json:"first_page_token"`
}

type snapshotPageRequest struct {
	ProtocolVersion string `json:"protocol_version"`
	DeviceID        string `json:"device_id"`
	PageToken       string `json:"page_token"`
}

type sourceDevice struct {
	DeviceID         string `json:"device_id"`
	MaxAuthorCounter string `json:"max_author_counter"`
}

type snapshotPageResponse struct {
	ProtocolVersion    string             `json:"protocol_version"`
	SnapshotID         string             `json:"snapshot_id"`
	CutCursor          string             `json:"cut_cursor"`
	EnvelopeGeneration string             `json:"envelope_generation"`
	Revisions          []recordRevision   `json:"revisions"`
	CollectionMarkers  []collectionMarker `json:"collection_markers"`
	SourceDevices      []sourceDevice     `json:"source_devices"`
	NextPageToken      *string            `json:"next_page_token"`
	HasMore            bool               `json:"has_more"`
}

type revokeDeviceRequest struct {
	RequestID       string `json:"request_id"`
	AllowZeroActive bool   `json:"allow_zero_active"`
}

type tokenRotationRequest struct {
	RotationID     string `json:"rotation_id"`
	DeviceID       string `json:"device_id"`
	NewDeviceToken string `json:"new_device_token"`
}

func decodeStrict(body []byte, destination any) error {
	if len(body) == 0 || !utf8.Valid(body) {
		return errors.New("body must contain valid UTF-8 JSON")
	}
	validator := json.NewDecoder(bytes.NewReader(body))
	validator.UseNumber()
	if err := validateJSONValue(validator, 1); err != nil {
		return err
	}
	if token, err := validator.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("trailing JSON token %v", token)
		}
		return err
	}
	destinationType := reflect.TypeOf(destination)
	if destinationType == nil || destinationType.Kind() != reflect.Pointer || reflect.ValueOf(destination).IsNil() {
		return errors.New("JSON destination must be a non-nil pointer")
	}
	if err := validateRequiredJSON(body, destinationType.Elem()); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

func validateRequiredJSON(raw json.RawMessage, destinationType reflect.Type) error {
	for destinationType.Kind() == reflect.Pointer {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil
		}
		destinationType = destinationType.Elem()
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("required JSON value is null")
	}
	switch destinationType.Kind() {
	case reflect.Struct:
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil {
			return err
		}
		for index := 0; index < destinationType.NumField(); index++ {
			field := destinationType.Field(index)
			tag := field.Tag.Get("json")
			name := strings.Split(tag, ",")[0]
			if name == "" || name == "-" {
				continue
			}
			fieldRaw, exists := object[name]
			if !exists {
				return fmt.Errorf("required JSON field %q is missing", name)
			}
			if err := validateRequiredJSON(fieldRaw, field.Type); err != nil {
				return fmt.Errorf("JSON field %q: %w", name, err)
			}
		}
	case reflect.Slice, reflect.Array:
		var values []json.RawMessage
		if err := json.Unmarshal(raw, &values); err != nil {
			return err
		}
		for _, value := range values {
			if err := validateRequiredJSON(value, destinationType.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("JSON nesting exceeds 32 levels")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return errors.New("duplicate JSON object key")
			}
			seen[key] = struct{}{}
			if err := validateJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
	case '[':
		for decoder.More() {
			if err := validateJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("unterminated JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func parseUint64(value string) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(parsed, 10) != value {
		return 0, errors.New("noncanonical uint64")
	}
	return parsed, nil
}

func decodeBase64(value string, exactBytes, minimumBytes, maximumBytes int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("noncanonical base64url")
	}
	if exactBytes >= 0 && len(decoded) != exactBytes {
		return nil, errors.New("base64url value has invalid length")
	}
	if exactBytes < 0 && (len(decoded) < minimumBytes || len(decoded) > maximumBytes) {
		return nil, errors.New("base64url value is outside its length bounds")
	}
	return decoded, nil
}

func validateUUID(value string) error {
	_, err := uuidv4.Parse(value)
	return err
}

func validateVector(vector []vectorEntry) (map[string]uint64, error) {
	if len(vector) == 0 || len(vector) > 64 {
		return nil, errors.New("vector size is invalid")
	}
	values := make(map[string]uint64, len(vector))
	var previous [16]byte
	for index, entry := range vector {
		identifier, err := uuidv4.Parse(entry.DeviceID)
		if err != nil {
			return nil, err
		}
		if index != 0 && bytes.Compare(previous[:], identifier[:]) >= 0 {
			return nil, errors.New("vector is not strictly ordered")
		}
		counter, err := parseUint64(entry.Counter)
		if err != nil || counter == 0 {
			return nil, errors.New("vector counter is invalid")
		}
		values[entry.DeviceID] = counter
		previous = identifier
	}
	return values, nil
}

func validateRevision(revision recordRevision) (uint64, map[string]uint64, error) {
	for _, identifier := range []string{revision.RecordID, revision.RevisionID, revision.AuthorDeviceID} {
		if err := validateUUID(identifier); err != nil {
			return 0, nil, err
		}
	}
	authorCounter, err := parseUint64(revision.AuthorCounter)
	if err != nil || authorCounter == 0 {
		return 0, nil, errors.New("author counter is invalid")
	}
	vector, err := validateVector(revision.VersionVector)
	if err != nil || vector[revision.AuthorDeviceID] != authorCounter {
		return 0, nil, errors.New("author entry does not match author counter")
	}
	if revision.CollectionWitnessAuthenticator != nil {
		if _, err := decodeBase64(*revision.CollectionWitnessAuthenticator, 32, 0, 0); err != nil {
			return 0, nil, err
		}
	}
	if revision.PayloadSchema != config.ProtocolMajor || revision.CryptoSuite != cryptoSuite {
		return 0, nil, errors.New("record profile is unsupported")
	}
	if _, err := decodeBase64(revision.Nonce, 24, 0, 0); err != nil {
		return 0, nil, err
	}
	if _, err := decodeBase64(revision.Ciphertext, -1, 16, 512*1024); err != nil {
		return 0, nil, err
	}
	return authorCounter, vector, nil
}

func validateEnvelope(envelope vaultEnvelope, identity Identity) (uint64, uint64, error) {
	if envelope.ProtocolVersion != config.ProtocolMajor || envelope.CryptoSuite != cryptoSuite {
		return 0, 0, errors.New("envelope profile is unsupported")
	}
	if envelope.InstanceID != identity.InstanceID || envelope.VaultID != identity.VaultID {
		return 0, 0, errors.New("envelope identity mismatch")
	}
	generation, err := parseUint64(envelope.EnvelopeGeneration)
	if err != nil {
		return 0, 0, err
	}
	secretGeneration, err := parseUint64(envelope.InstanceSecretGeneration)
	if err != nil {
		return 0, 0, err
	}
	if _, err := decodeBase64(envelope.HKDFSalt, 32, 0, 0); err != nil {
		return 0, 0, err
	}
	if _, err := decodeBase64(envelope.Nonce, 24, 0, 0); err != nil {
		return 0, 0, err
	}
	if _, err := decodeBase64(envelope.WrappedVMK, 48, 0, 0); err != nil {
		return 0, 0, err
	}
	switch envelope.Mode {
	case "base":
		if envelope.Argon2 != nil {
			return 0, 0, errors.New("base envelope carries Argon2 parameters")
		}
	case "passphrase":
		if envelope.Argon2 == nil || envelope.Argon2.Version != 19 ||
			envelope.Argon2.MemoryKiB != 65536 || envelope.Argon2.Iterations != 3 ||
			envelope.Argon2.Parallelism != 1 || envelope.Argon2.OutputLength != 32 {
			return 0, 0, errors.New("passphrase envelope Argon2 profile is invalid")
		}
		if _, err := decodeBase64(envelope.Argon2.Salt, 16, 0, 0); err != nil {
			return 0, 0, err
		}
	default:
		return 0, 0, errors.New("envelope mode is invalid")
	}
	return generation, secretGeneration, nil
}

func validateCollectionMarker(marker collectionMarker) (map[string]uint64, uint64, []byte, error) {
	if err := validateUUID(marker.RecordID); err != nil {
		return nil, 0, nil, err
	}
	if err := validateUUID(marker.WitnessRevisionID); err != nil {
		return nil, 0, nil, err
	}
	frontier, err := validateVector(marker.Frontier)
	if err != nil {
		return nil, 0, nil, err
	}
	authenticator, err := decodeBase64(marker.CollectionWitnessAuthenticator, 32, 0, 0)
	if err != nil {
		return nil, 0, nil, err
	}
	barrier, err := parseUint64(marker.BarrierCursor)
	if err != nil {
		return nil, 0, nil, err
	}
	return frontier, barrier, authenticator, nil
}

func decodeStoredCollectionMarker(body []byte) (collectionMarker, error) {
	var marker collectionMarker
	if json.Unmarshal(body, &marker) != nil {
		return marker, errors.New("stored collection marker is invalid JSON")
	}
	if _, _, _, err := validateCollectionMarker(marker); err != nil {
		return marker, err
	}
	canonical, err := marshalJSON(marker)
	if err != nil || !bytes.Equal(canonical, body) {
		return marker, errors.New("stored collection marker is noncanonical")
	}
	return marker, nil
}

func validateEnrollmentRequest(request enrollmentRequest) ([]byte, error) {
	if request.ProtocolVersion != config.ProtocolMajor {
		return nil, errors.New("protocol version is invalid")
	}
	if err := validateUUID(request.EnrollmentID); err != nil {
		return nil, err
	}
	if err := validateUUID(request.DeviceID); err != nil {
		return nil, err
	}
	if err := auth.ValidateScopes(request.Scopes); err != nil {
		return nil, err
	}
	return decodeBase64(request.DeviceToken, 32, 0, 0)
}

func formatTimestamp(milliseconds int64) string {
	return time.UnixMilli(milliseconds).UTC().Format("2006-01-02T15:04:05.000Z")
}

func marshalJSON(value any) ([]byte, error) {
	return json.Marshal(value)
}

func decodeStoredCanonical(body []byte, destination any) error {
	if len(body) == 0 || len(body) > maxBodyBytes {
		return errors.New("stored response body is outside V1 bounds")
	}
	if err := decodeStrict(body, destination); err != nil {
		return err
	}
	canonical, err := marshalJSON(destination)
	if err != nil || !bytes.Equal(canonical, body) {
		return errors.New("stored response body is noncanonical")
	}
	return nil
}

func validateTimestamp(value string) error {
	parsed, err := time.Parse("2006-01-02T15:04:05.000Z", value)
	if err != nil || parsed.Format("2006-01-02T15:04:05.000Z") != value {
		return errors.New("timestamp is noncanonical")
	}
	return nil
}

func validateDevice(value device) error {
	if validateUUID(value.DeviceID) != nil || auth.ValidateScopes(value.Scopes) != nil || validateTimestamp(value.CreatedAt) != nil {
		return errors.New("device profile is invalid")
	}
	if _, err := parseUint64(value.AckCursor); err != nil {
		return err
	}
	if _, err := parseUint64(value.MaxAuthorCounter); err != nil {
		return err
	}
	if value.LastSyncAt != nil && validateTimestamp(*value.LastSyncAt) != nil {
		return errors.New("last-sync timestamp is invalid")
	}
	switch value.Status {
	case "active":
		if value.RevokedAt != nil {
			return errors.New("active device has a revocation time")
		}
	case "revoked":
		if value.RevokedAt == nil || validateTimestamp(*value.RevokedAt) != nil {
			return errors.New("revoked device has an invalid revocation time")
		}
	default:
		return errors.New("device status is invalid")
	}
	return nil
}

func validateStoredOperationResponse(operation string, status int, body []byte, identity Identity) error {
	if status != 200 {
		return errors.New("stored operation response status is invalid")
	}
	switch {
	case operation == "vault-envelope":
		var envelope vaultEnvelope
		if err := decodeStoredCanonical(body, &envelope); err != nil {
			return err
		}
		_, _, err := validateEnvelope(envelope, identity)
		return err
	case operation == "sync":
		var response syncResponse
		if err := decodeStoredCanonical(body, &response); err != nil {
			return err
		}
		return validateSyncResponse(response)
	case strings.HasPrefix(operation, "device-revocation/"):
		target := strings.TrimPrefix(operation, "device-revocation/")
		if validateUUID(target) != nil {
			return errors.New("stored revocation target is invalid")
		}
		var response device
		if err := decodeStoredCanonical(body, &response); err != nil {
			return err
		}
		if response.DeviceID != target {
			return errors.New("stored revocation response target is invalid")
		}
		return validateDevice(response)
	default:
		return errors.New("stored operation is invalid")
	}
}

func validateStoredEnrollmentResponse(body []byte, identity Identity, deviceID string) error {
	var response enrollmentResponse
	if err := decodeStoredCanonical(body, &response); err != nil {
		return err
	}
	if response.ProtocolVersion != config.ProtocolMajor || response.InstanceID != identity.InstanceID ||
		response.VaultID != identity.VaultID || response.Device.DeviceID != deviceID {
		return errors.New("stored enrollment response identity is invalid")
	}
	if err := validateDevice(response.Device); err != nil {
		return err
	}
	_, err := parseUint64(response.EnvelopeGeneration)
	return err
}

func validateStoredSnapshotCreateResponse(body []byte, identity Identity, snapshotID, ownerDeviceID string, cutCursor, envelopeGeneration uint64, expiresAtMS int64) error {
	var response snapshotCreateResponse
	if err := decodeStoredCanonical(body, &response); err != nil {
		return err
	}
	if response.ProtocolVersion != config.ProtocolMajor || response.SnapshotID != snapshotID ||
		response.CutCursor != encodeUint64Text(cutCursor) || response.EnvelopeGeneration != encodeUint64Text(envelopeGeneration) ||
		response.ExpiresAt != formatTimestamp(expiresAtMS) || validateUUID(ownerDeviceID) != nil {
		return errors.New("stored snapshot response identity is invalid")
	}
	if _, err := decodeBase64(response.FirstPageToken, 32, 0, 0); err != nil {
		return err
	}
	validatedGeneration, _, err := validateEnvelope(response.Envelope, identity)
	if err != nil || validatedGeneration != envelopeGeneration {
		return errors.New("stored snapshot envelope is invalid")
	}
	return nil
}

func validateSyncResponse(response syncResponse) error {
	if response.ProtocolVersion != config.ProtocolMajor || len(response.Changes) > maxChanges {
		return errors.New("stored sync response profile is invalid")
	}
	serverCursor, err := parseUint64(response.ServerCursor)
	if err != nil {
		return err
	}
	nextCursor, err := parseUint64(response.NextCursor)
	if err != nil || nextCursor > serverCursor {
		return errors.New("stored sync response cursor is invalid")
	}
	if _, err := parseUint64(response.EnvelopeGeneration); err != nil {
		return err
	}
	previous := uint64(0)
	for index, item := range response.Changes {
		cursor, err := parseUint64(item.Cursor)
		if err != nil || cursor > serverCursor || index != 0 && cursor <= previous || validateTimestamp(item.ReceivedAt) != nil {
			return errors.New("stored sync change is invalid")
		}
		switch item.Kind {
		case "record_revision":
			if item.RecordRevision == nil || item.CollectionMarker != nil {
				return errors.New("stored revision change shape is invalid")
			}
			if _, _, err := validateRevision(*item.RecordRevision); err != nil {
				return err
			}
		case "collection_marker":
			if item.RecordRevision != nil || item.CollectionMarker == nil {
				return errors.New("stored marker change shape is invalid")
			}
			if _, _, _, err := validateCollectionMarker(*item.CollectionMarker); err != nil {
				return err
			}
		case "envelope_changed", "device_changed":
			if item.RecordRevision != nil || item.CollectionMarker != nil {
				return errors.New("stored metadata change shape is invalid")
			}
		default:
			return errors.New("stored change kind is invalid")
		}
		previous = cursor
	}
	if len(response.Changes) != 0 && nextCursor != previous {
		return errors.New("stored sync next cursor is invalid")
	}
	return nil
}

func vectorDominates(left, right map[string]uint64) bool {
	strict := false
	for deviceID, rightCounter := range right {
		leftCounter := left[deviceID]
		if leftCounter < rightCounter {
			return false
		}
		if leftCounter > rightCounter {
			strict = true
		}
	}
	if !strict {
		for deviceID, leftCounter := range left {
			if _, exists := right[deviceID]; !exists && leftCounter > 0 {
				strict = true
				break
			}
		}
	}
	return strict
}
