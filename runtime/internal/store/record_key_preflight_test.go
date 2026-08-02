package store

import (
	"context"
	"strings"
	"testing"

	"github.com/kciceblue/sshserver/runtime/internal/api"
)

var recordKeyOwnerTables = []string{
	"record_revisions",
	"record_vector_index",
	"record_heads",
	"collection_candidates",
	"collection_records",
	"collection_markers",
}

var recordKeyIndexedAliasTables = []string{
	"record_revisions",
	"record_vector_index",
	"record_heads",
	"collection_candidates",
	"collection_records",
}

func corruptRecordKey(t *testing.T, fixture revisionKeyFixture, form string) {
	t.Helper()
	corruptID := fixture.seed.recordID + "\x00suffix"
	switch form {
	case "NUL-suffixed TEXT":
		for _, table := range recordKeyOwnerTables {
			if _, err := fixture.seed.opened.db.Exec(
				"UPDATE "+table+" SET record_id = ? WHERE record_id = ?",
				corruptID, fixture.seed.recordID,
			); err != nil {
				t.Fatal(err)
			}
		}
		assertNULSuffixPassedSQLiteLengthCheck(t, fixture.seed.opened.db, `
			SELECT length(record_id), octet_length(record_id), typeof(record_id)
			FROM record_vector_index LIMIT 1`)
	case "BLOB-equivalent", "NUL-suffixed BLOB":
		value := fixture.seed.recordID
		if form == "NUL-suffixed BLOB" {
			value = corruptID
			if _, err := fixture.seed.opened.db.Exec("PRAGMA ignore_check_constraints = ON"); err != nil {
				t.Fatal(err)
			}
		}
		for _, table := range recordKeyOwnerTables {
			writeLiveWrongTypeText(t, fixture.seed.opened.db, table,
				"UPDATE "+table+" SET record_id = CAST(? AS BLOB) WHERE record_id = ?",
				value, fixture.seed.recordID)
		}
		if form == "NUL-suffixed BLOB" {
			if _, err := fixture.seed.opened.db.Exec("PRAGMA ignore_check_constraints = OFF"); err != nil {
				t.Fatal(err)
			}
		}
	default:
		t.Fatalf("unknown record key form %q", form)
	}
}

func corruptSingleRecordKeyOwner(t *testing.T, fixture revisionKeyFixture, table, form string) {
	t.Helper()
	corruptID := fixture.seed.recordID + "\x00suffix"
	switch form {
	case "NUL-suffixed TEXT":
		if _, err := fixture.seed.opened.db.Exec(
			"UPDATE "+table+" SET record_id = ? WHERE record_id = ?",
			corruptID, fixture.seed.recordID,
		); err != nil {
			t.Fatal(err)
		}
	case "BLOB-equivalent", "NUL-suffixed BLOB":
		value := fixture.seed.recordID
		if form == "NUL-suffixed BLOB" {
			value = corruptID
			if _, err := fixture.seed.opened.db.Exec("PRAGMA ignore_check_constraints = ON"); err != nil {
				t.Fatal(err)
			}
		}
		writeLiveWrongTypeText(t, fixture.seed.opened.db, table,
			"UPDATE "+table+" SET record_id = CAST(? AS BLOB) WHERE record_id = ?",
			value, fixture.seed.recordID)
		if form == "NUL-suffixed BLOB" {
			if _, err := fixture.seed.opened.db.Exec("PRAGMA ignore_check_constraints = OFF"); err != nil {
				t.Fatal(err)
			}
		}
	default:
		t.Fatalf("unknown record key form %q", form)
	}
}

func recordKeySyncCall(t *testing.T, fixture revisionKeyFixture, requestID, revisionID string) api.Request {
	t.Helper()
	mutation := revisionKeyMutation(
		fixture.seed.deviceID, fixture.seed.recordID, revisionID, fixture.nextCounter,
	)
	body, err := marshalJSON(syncRequest{
		ProtocolVersion: "1", DeviceID: fixture.seed.deviceID, RequestID: requestID,
		AfterCursor: fixture.afterCursor, AckCursor: "0", Mutations: []recordRevision{mutation},
	})
	if err != nil {
		t.Fatal(err)
	}
	return api.Request{
		Method: "POST", Path: "/v1/sync", RequestID: requestID,
		Authorization: authorization(fixture.seed.token), Body: body, Now: protocolFixtureTime,
	}
}

func TestRecordKeyPreflightRejectsPermanentAndCollectionAliasesWithoutMutation(t *testing.T) {
	for _, history := range []string{"retained head", "dominated retained", "collected permanent"} {
		for _, form := range []string{"NUL-suffixed TEXT", "BLOB-equivalent", "NUL-suffixed BLOB"} {
			t.Run(history+"/"+form, func(t *testing.T) {
				fixture := seedRevisionKeyFixture(t, history)
				defer fixture.seed.opened.Close()
				corruptRecordKey(t, fixture, form)
				before := markerKeyDurableDigest(t, fixture.seed.opened.db)
				newRevisionID := "f7550000-0000-4000-8000-000000000001"
				call := recordKeySyncCall(t, fixture,
					"f7550000-0000-4000-8000-000000000002", newRevisionID)
				if _, protocolErr := fixture.seed.opened.HandleAPI(context.Background(), call); protocolErr == nil || protocolErr.Code != "internal_error" {
					t.Fatalf("record alias error=%v", protocolErr)
				}
				if after := markerKeyDurableDigest(t, fixture.seed.opened.db); before != after {
					t.Fatalf("record alias changed durable state: before=%x after=%x", before, after)
				}
				var inserted int
				if err := fixture.seed.opened.db.QueryRow(
					"SELECT count(*) FROM record_revisions WHERE revision_id = ?", newRevisionID,
				).Scan(&inserted); err != nil {
					t.Fatal(err)
				}
				if inserted != 0 {
					t.Fatalf("canonical record alias revision inserted: count=%d", inserted)
				}
			})
		}
	}
}

func TestRecordKeyPreflightCoversEachIndexedOwner(t *testing.T) {
	for _, table := range recordKeyIndexedAliasTables {
		for _, form := range []string{"NUL-suffixed TEXT", "BLOB-equivalent", "NUL-suffixed BLOB"} {
			t.Run(table+"/"+form, func(t *testing.T) {
				fixture := seedRevisionKeyFixture(t, "retained head")
				defer fixture.seed.opened.Close()
				corruptSingleRecordKeyOwner(t, fixture, table, form)
				before := markerKeyDurableDigest(t, fixture.seed.opened.db)
				newRevisionID := "f7550000-0000-4000-8000-000000000003"
				call := recordKeySyncCall(t, fixture,
					"f7550000-0000-4000-8000-000000000004", newRevisionID)
				if _, protocolErr := fixture.seed.opened.HandleAPI(context.Background(), call); protocolErr == nil || protocolErr.Code != "internal_error" {
					t.Fatalf("%s record alias error=%v", table, protocolErr)
				}
				if after := markerKeyDurableDigest(t, fixture.seed.opened.db); before != after {
					t.Fatalf("%s record alias changed durable state: before=%x after=%x", table, before, after)
				}
			})
		}
	}
}

func TestRecordKeyPreflightAllowsCanonicalPermanentHistory(t *testing.T) {
	for _, history := range []string{"retained head", "dominated retained", "collected permanent"} {
		t.Run(history, func(t *testing.T) {
			fixture := seedRevisionKeyFixture(t, history)
			defer fixture.seed.opened.Close()
			newRevisionID := "f7560000-0000-4000-8000-000000000001"
			call := recordKeySyncCall(t, fixture,
				"f7560000-0000-4000-8000-000000000002", newRevisionID)
			response, protocolErr := fixture.seed.opened.HandleAPI(context.Background(), call)
			if protocolErr != nil || response.Status != 200 {
				t.Fatalf("canonical record history: response=%+v error=%v", response, protocolErr)
			}
			var inserted int
			if err := fixture.seed.opened.db.QueryRow(
				"SELECT count(*) FROM record_revisions WHERE revision_id = ? AND record_id = ?",
				newRevisionID, fixture.seed.recordID,
			).Scan(&inserted); err != nil {
				t.Fatal(err)
			}
			if inserted != 1 {
				t.Fatalf("canonical record history insertion count=%d", inserted)
			}
		})
	}
}

func TestRecordKeyAliasProbeUsesPermanentPrimaryKeyRanges(t *testing.T) {
	opened, _ := openDataPlane(t)
	defer opened.Close()
	recordID := "f7570000-0000-4000-8000-000000000001"
	lowerBytes := []byte(recordID)
	upperBytes := append([]byte(nil), lowerBytes...)
	upperBytes[len(upperBytes)-1]++
	rows, err := opened.db.Query("EXPLAIN QUERY PLAN "+recordKeyAliasProbeSQL,
		recordID, string(upperBytes), lowerBytes, upperBytes,
		recordID, string(upperBytes), lowerBytes, upperBytes,
		recordID, string(upperBytes), lowerBytes, upperBytes,
		recordID, string(upperBytes), lowerBytes, upperBytes,
		recordID, string(upperBytes), lowerBytes, upperBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	searches := 0
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		for _, table := range recordKeyIndexedAliasTables {
			if strings.Contains(detail, "SCAN "+table) {
				rows.Close()
				t.Fatalf("record-key alias probe scans %s: %s", table, detail)
			}
		}
		for _, table := range recordKeyIndexedAliasTables {
			if strings.Contains(detail, "SEARCH "+table) &&
				strings.Contains(detail, "record_id>?") && strings.Contains(detail, "record_id<?") {
				searches++
			}
		}
	}
	iterationErr := rows.Err()
	closeErr := rows.Close()
	if iterationErr != nil || closeErr != nil {
		t.Fatalf("explain record-key alias probe: iteration=%v close=%v", iterationErr, closeErr)
	}
	wantSearches := 2 * len(recordKeyIndexedAliasTables)
	if searches != wantSearches {
		t.Fatalf("record-key indexed range searches=%d, want=%d", searches, wantSearches)
	}
}
