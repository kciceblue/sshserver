package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestPersistentChangesStreamsLargeMarkerRegistry(t *testing.T) {
	opened, _ := openDataPlane(t)
	defer opened.Close()

	const markerCount = 2049
	frontier := []vectorEntry{{
		DeviceID: "e8430000-0000-4000-8000-000000000001",
		Counter:  "1",
	}}
	frontierBody, err := json.Marshal(frontier)
	if err != nil {
		t.Fatal(err)
	}
	authenticator := make([]byte, 32)
	encodedAuthenticator := base64.RawURLEncoding.EncodeToString(authenticator)
	barrier := EncodeUint64(0)

	transaction, err := opened.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	originStatement, err := transaction.Prepare(`
		INSERT INTO change_origins (cursor, kind)
		VALUES (?, 'collection_marker')`)
	if err != nil {
		t.Fatal(err)
	}
	defer originStatement.Close()
	changeStatement, err := transaction.Prepare(`
		INSERT INTO changes (cursor, kind, received_at_ms, collection_marker_record_id, collection_marker_json)
		VALUES (?, 'collection_marker', ?, ?, ?)`)
	if err != nil {
		t.Fatal(err)
	}
	defer changeStatement.Close()
	markerStatement, err := transaction.Prepare(`
		INSERT INTO collection_markers (
			record_id, witness_revision_id, frontier_json,
			collection_witness_authenticator, barrier_cursor, marker_json,
			change_cursor, received_at_ms
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		t.Fatal(err)
	}
	defer markerStatement.Close()

	for index := 1; index <= markerCount; index++ {
		recordID := fmt.Sprintf("e8410000-0000-4000-8000-%012x", index)
		marker := collectionMarker{
			RecordID:                       recordID,
			WitnessRevisionID:              "e8420000-0000-4000-8000-000000000001",
			Frontier:                       frontier,
			CollectionWitnessAuthenticator: encodedAuthenticator,
			BarrierCursor:                  "0",
		}
		markerBody, err := marshalJSON(marker)
		if err != nil {
			t.Fatal(err)
		}
		cursor := EncodeUint64(uint64(index))
		if _, err := originStatement.Exec(cursor[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := changeStatement.Exec(cursor[:], protocolFixtureTime.UnixMilli(), recordID, markerBody); err != nil {
			t.Fatal(err)
		}
		if _, err := markerStatement.Exec(
			recordID, marker.WitnessRevisionID, frontierBody, authenticator, barrier[:], markerBody,
			cursor[:], protocolFixtureTime.UnixMilli(),
		); err != nil {
			t.Fatal(err)
		}
	}
	serverCursor := EncodeUint64(markerCount)
	if _, err := transaction.Exec("UPDATE runtime_state SET server_cursor = ? WHERE singleton = 1", serverCursor[:]); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}

	if err := validatePersistentChanges(context.Background(), opened.db, nil, markerCount); err != nil {
		t.Fatalf("large marker registry validation: %v", err)
	}
}

func TestPersistentChangesRequiresCurrentLatestMarker(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, twoMarkerAdvanceFixture)
	}{
		{
			name: "missing current marker",
			mutate: func(t *testing.T, fixture twoMarkerAdvanceFixture) {
				if _, err := fixture.opened.db.Exec("DELETE FROM collection_markers WHERE record_id = ?", fixture.recordID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "stale current marker",
			mutate: func(t *testing.T, fixture twoMarkerAdvanceFixture) {
				firstCursor := EncodeUint64(fixture.firstCursor)
				if _, err := fixture.opened.db.Exec(
					"UPDATE collection_markers SET change_cursor = ? WHERE record_id = ?",
					firstCursor[:], fixture.recordID,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := seedTwoMarkerAdvanceLifecycle(t)
			defer fixture.opened.Close()
			serverCursor, _, _, _, err := validatePersistentRuntime(context.Background(), fixture.opened.db)
			if err != nil {
				t.Fatal(err)
			}
			devices, err := validatePersistentDevices(context.Background(), fixture.opened.db, serverCursor)
			if err != nil {
				t.Fatal(err)
			}
			if err := validatePersistentChanges(context.Background(), fixture.opened.db, devices, serverCursor); err != nil {
				t.Fatalf("current latest marker control: %v", err)
			}

			test.mutate(t, fixture)
			err = validatePersistentChanges(context.Background(), fixture.opened.db, devices, serverCursor)
			if !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "invalid marker change") {
				t.Fatalf("current latest marker error=%v", err)
			}
		})
	}
}

func TestPersistentChangesUsesBoundedMarkerPrimaryKeyLookup(t *testing.T) {
	opened, _ := openDataPlane(t)
	defer opened.Close()

	rows, err := opened.db.Query(
		"EXPLAIN QUERY PLAN "+persistentChangesValidationQuery,
		maxUUIDBytes, maxUUIDBytes, maxBodyBytes, maxUUIDBytes, maxBodyBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var details []string
	foundMarkerLookup := false
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		details = append(details, detail)
		if strings.Contains(detail, "SEARCH m USING") && strings.Contains(detail, "record_id=?") {
			foundMarkerLookup = true
		}
		if strings.Contains(detail, "USE TEMP B-TREE") {
			t.Fatalf("marker validation materializes ordered changes: %v", details)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !foundMarkerLookup {
		t.Fatalf("marker validation lacks bounded record primary-key lookup: %v", details)
	}
}
