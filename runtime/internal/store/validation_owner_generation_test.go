package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/api"
)

type validationOwnerEnvelopeState struct {
	serverCursor, runtimeGeneration, envelopeGeneration, envelopeBody string
	origins, changes, receipts                                        int
}

func readValidationOwnerEnvelopeState(t *testing.T, database *sql.DB) validationOwnerEnvelopeState {
	t.Helper()
	var state validationOwnerEnvelopeState
	if err := database.QueryRow(`
		SELECT hex(r.server_cursor), hex(r.envelope_generation),
		       hex(v.generation), hex(v.envelope_json),
		       (SELECT count(*) FROM change_origins),
		       (SELECT count(*) FROM changes),
		       (SELECT count(*) FROM operation_receipts)
		FROM runtime_state r JOIN vault_envelope v ON v.singleton = r.singleton
		WHERE r.singleton = 1`,
	).Scan(
		&state.serverCursor, &state.runtimeGeneration,
		&state.envelopeGeneration, &state.envelopeBody,
		&state.origins, &state.changes, &state.receipts,
	); err != nil {
		t.Fatal(err)
	}
	return state
}

func validationOwnerEnvelopeCall(t *testing.T, token []byte, requestID string) api.Request {
	t.Helper()
	var fixture struct {
		PassphraseRewrap putEnvelopeRequest `json:"passphrase_rewrap"`
	}
	loadFixture(t, "vault-envelope.json", &fixture)
	body, err := marshalJSON(fixture.PassphraseRewrap)
	if err != nil {
		t.Fatal(err)
	}
	return api.Request{
		Method: "PUT", Path: "/v1/vault-envelope", RequestID: requestID,
		Authorization: authorization(token), Body: body, Now: protocolFixtureTime.Add(4 * time.Second),
	}
}

func mutateValidationOwnerText(t *testing.T, database *sql.DB, statement string, arguments ...any) {
	t.Helper()
	if _, err := database.Exec("PRAGMA foreign_keys = OFF"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(statement, arguments...); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("PRAGMA foreign_keys = ON"); err != nil {
		t.Fatal(err)
	}
}

func mutateValidationOwnerWrongType(t *testing.T, database *sql.DB, table, statement string, arguments ...any) {
	t.Helper()
	if _, err := database.Exec("PRAGMA foreign_keys = OFF"); err != nil {
		t.Fatal(err)
	}
	var originalSchema string
	if err := database.QueryRow("SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?", table).Scan(&originalSchema); err != nil {
		t.Fatal(err)
	}
	nonstrictSchema := strings.TrimSuffix(originalSchema, " STRICT")
	if nonstrictSchema == originalSchema {
		t.Fatalf("%s schema is not STRICT", table)
	}
	var schemaVersion int
	if err := database.QueryRow("PRAGMA schema_version").Scan(&schemaVersion); err != nil {
		t.Fatal(err)
	}
	rewrite := func(schema string, version int) {
		if _, err := database.Exec("PRAGMA writable_schema = ON"); err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec("UPDATE sqlite_schema SET sql = ? WHERE type = 'table' AND name = ?", schema, table); err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec(fmt.Sprintf("PRAGMA schema_version = %d", version)); err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec("PRAGMA writable_schema = OFF"); err != nil {
			t.Fatal(err)
		}
	}
	rewrite(nonstrictSchema, schemaVersion+1)
	if _, err := database.Exec(statement, arguments...); err != nil {
		t.Fatal(err)
	}
	rewrite(originalSchema, schemaVersion+2)
	if _, err := database.Exec("PRAGMA foreign_keys = ON"); err != nil {
		t.Fatal(err)
	}
}

func TestPermanentOwnerPreflightAcceptsCanonicalOwners(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{marker: true})
	defer seed.opened.Close()
	serverCursor, envelopeGeneration, _, _, err := validatePersistentRuntime(context.Background(), seed.opened.db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validatePersistentChangeOrigins(context.Background(), seed.opened.db, serverCursor, envelopeGeneration, nil); err != nil {
		t.Fatalf("canonical permanent owners rejected: %v", err)
	}
	response, protocolErr := seed.opened.HandleAPI(context.Background(), validationOwnerEnvelopeCall(
		t, seed.token, "e8350000-0000-4000-8000-000000000001",
	))
	if protocolErr != nil || response.Status != http.StatusOK {
		t.Fatalf("canonical owner envelope PUT: response=%+v error=%v", response, protocolErr)
	}
}

func TestEnvelopePutRejectsMalformedPermanentOwnerIDsWithoutMutation(t *testing.T) {
	oversizedSuffix := "\x00" + strings.Repeat("x", 64*1024)
	invalidUUID := strings.Repeat("x", maxUUIDBytes)
	tests := []struct {
		name    string
		options boundedSeedOptions
		mutate  func(*testing.T, boundedPersistenceSeed)
	}{
		{
			name: "NUL-suffixed collection marker record ID", options: boundedSeedOptions{marker: true},
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutateValidationOwnerText(t, seed.opened.db, "UPDATE collection_markers SET record_id = ?", seed.recordID+oversizedSuffix)
			},
		},
		{
			name: "exact-length invalid collection marker record ID", options: boundedSeedOptions{marker: true},
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutateValidationOwnerText(t, seed.opened.db, "UPDATE collection_markers SET record_id = ?", invalidUUID)
			},
		},
		{
			name: "BLOB collection marker record ID", options: boundedSeedOptions{marker: true},
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutateValidationOwnerWrongType(t, seed.opened.db, "collection_markers", "UPDATE collection_markers SET record_id = ?", []byte(seed.recordID))
			},
		},
		{
			name: "NUL-suffixed device origin ID",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutateValidationOwnerText(t, seed.opened.db, "UPDATE device_origins SET device_id = ? WHERE created_cursor IS NOT NULL", seed.deviceID+oversizedSuffix)
			},
		},
		{
			name: "exact-length invalid device origin ID",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutateValidationOwnerText(t, seed.opened.db, "UPDATE device_origins SET device_id = ? WHERE created_cursor IS NOT NULL", invalidUUID)
			},
		},
		{
			name: "BLOB device origin ID",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutateValidationOwnerWrongType(t, seed.opened.db, "device_origins", "UPDATE device_origins SET device_id = ? WHERE created_cursor IS NOT NULL", []byte(seed.deviceID))
			},
		},
		{
			name: "NUL-suffixed enrollment device ID",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutateValidationOwnerText(t, seed.opened.db, "UPDATE enrollments SET device_id = ?", seed.deviceID+oversizedSuffix)
			},
		},
		{
			name: "exact-length invalid enrollment device ID",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutateValidationOwnerText(t, seed.opened.db, "UPDATE enrollments SET device_id = ?", invalidUUID)
			},
		},
		{
			name: "BLOB enrollment device ID",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutateValidationOwnerWrongType(t, seed.opened.db, "enrollments", "UPDATE enrollments SET device_id = ?", []byte(seed.deviceID))
			},
		},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seed := seedBoundedPersistence(t, test.options)
			defer seed.opened.Close()
			test.mutate(t, seed)
			serverCursor, envelopeGeneration, _, _, err := validatePersistentRuntime(context.Background(), seed.opened.db)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := validatePersistentChangeOrigins(context.Background(), seed.opened.db, serverCursor, envelopeGeneration, nil); !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "change origin") {
				t.Fatalf("malformed permanent owner error=%v", err)
			}
			before := readValidationOwnerEnvelopeState(t, seed.opened.db)
			requestID := fmt.Sprintf("e8360000-0000-4000-8000-%012x", index+1)
			expectInternalError(t, seed.opened, validationOwnerEnvelopeCall(t, seed.token, requestID))
			after := readValidationOwnerEnvelopeState(t, seed.opened.db)
			if before != after {
				t.Fatalf("malformed-owner envelope PUT mutated state: before=%+v after=%+v", before, after)
			}
		})
	}
}

func TestPermanentOwnerCorruptionPreservesEnvelopeErrorOrdering(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{marker: true})
	defer seed.opened.Close()
	mutateValidationOwnerText(t, seed.opened.db, "UPDATE collection_markers SET record_id = ?", seed.recordID+"\x00corrupt")
	before := readValidationOwnerEnvelopeState(t, seed.opened.db)
	invalidBody := validationOwnerEnvelopeCall(t, seed.token, "e8370000-0000-4000-8000-000000000001")
	invalidBody.Body = []byte("{")
	if _, protocolErr := seed.opened.HandleAPI(context.Background(), invalidBody); protocolErr == nil || protocolErr.Code != "invalid_request" {
		t.Fatalf("invalid body error ordering=%v", protocolErr)
	}
	unauthorized := validationOwnerEnvelopeCall(t, seed.token, "e8370000-0000-4000-8000-000000000002")
	unauthorized.Authorization = "Bearer invalid"
	if _, protocolErr := seed.opened.HandleAPI(context.Background(), unauthorized); protocolErr == nil || protocolErr.Code != "unauthorized" {
		t.Fatalf("unauthorized error ordering=%v", protocolErr)
	}
	after := readValidationOwnerEnvelopeState(t, seed.opened.db)
	if before != after {
		t.Fatalf("error-ordering probes mutated state: before=%+v after=%+v", before, after)
	}
}

func openValidationGenerationFixture(t *testing.T) *sql.DB {
	t.Helper()
	database, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "collection-generations.db"))
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = database.Close() })
	if _, err := database.Exec("CREATE TABLE record_revisions (revision_id TEXT, collected_generation BLOB)"); err != nil {
		t.Fatal(err)
	}
	return database
}

func insertValidationGenerations(t *testing.T, database *sql.DB, generations ...uint64) {
	t.Helper()
	for index, generation := range generations {
		encoded := EncodeUint64(generation)
		if _, err := database.Exec("INSERT INTO record_revisions (revision_id, collected_generation) VALUES (?, ?)", fmt.Sprintf("revision-%d", index), encoded[:]); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPersistentCollectionGenerationSequenceStreamsContiguously(t *testing.T) {
	for _, test := range []struct {
		name       string
		rows       []uint64
		runtime    uint64
		wantErr    bool
		transition []uint64
	}{
		{name: "empty generation zero", runtime: 0},
		{name: "canonical repeated generations", rows: []uint64{2, 1, 2, 1}, runtime: 2},
		{name: "missing first generation", rows: []uint64{2}, runtime: 2, wantErr: true},
		{name: "gap", rows: []uint64{1, 3}, runtime: 3, wantErr: true},
		{name: "missing final generation", rows: []uint64{1}, runtime: 2, wantErr: true},
		{name: "transition reappearance", transition: []uint64{1, 2, 1}, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.transition != nil {
				previous := uint64(0)
				valid := true
				for _, generation := range test.transition {
					previous, valid = advancePersistentCollectionGeneration(previous, generation)
					if !valid {
						break
					}
				}
				if valid == test.wantErr {
					t.Fatalf("transition validity=%t want error=%t", valid, test.wantErr)
				}
				return
			}
			database := openValidationGenerationFixture(t)
			insertValidationGenerations(t, database, test.rows...)
			err := validatePersistentCollectionGenerationSequence(context.Background(), database, test.runtime)
			if test.wantErr {
				if !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "collection generation does not match accepted history") {
					t.Fatalf("generation sequence error=%v", err)
				}
			} else if err != nil {
				t.Fatalf("canonical generation sequence error=%v", err)
			}
		})
	}
}
