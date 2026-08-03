package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/api"
	"github.com/kciceblue/sshserver/runtime/internal/auth"
)

func enrollmentDeviceCollisionCall(t *testing.T, opened *Store, deviceID string) (api.Request, EnrollmentGrant) {
	t.Helper()
	grant := createGrant(t, opened, protocolFixtureTime.Add(time.Second))
	body, err := marshalJSON(enrollmentRequest{
		ProtocolVersion: "1",
		EnrollmentID:    "f7520000-0000-4000-8000-000000000001",
		DeviceID:        deviceID,
		DeviceToken:     base64.RawURLEncoding.EncodeToString(tokenWithByte(0x52)),
		Scopes:          auth.FixedScopes(),
	})
	if err != nil {
		clear(grant.Grant)
		t.Fatal(err)
	}
	return api.Request{
		Method: "POST", Path: "/v1/enrollments",
		RequestID:     "f7520000-0000-4000-8000-000000000002",
		Authorization: "JAT-Enrollment " + base64.RawURLEncoding.EncodeToString(grant.Grant),
		Body:          body,
		Now:           protocolFixtureTime.Add(time.Second),
	}, grant
}

func insertEnrollmentDeviceCollision(t *testing.T, opened *Store, table, deviceID string, blob bool) {
	t.Helper()
	wantScopes, err := json.Marshal(auth.FixedScopes())
	if err != nil {
		t.Fatal(err)
	}
	zero := EncodeUint64(0)
	switch table {
	case "devices":
		statement := `
			INSERT INTO devices (
				device_id, token_hash, scopes_json, created_at_ms,
				last_ack_cursor, max_author_counter
			) VALUES (?, ?, ?, ?, ?, ?)`
		arguments := []any{deviceID, tokenWithByte(0x53), string(wantScopes), protocolFixtureTime.UnixMilli(), zero[:], zero[:]}
		if blob {
			statement = strings.Replace(statement, "VALUES (?,", "VALUES (CAST(? AS BLOB),", 1)
			writeLiveWrongTypeText(t, opened.db, "devices", statement, arguments...)
			return
		}
		if _, err := opened.db.Exec(statement, arguments...); err != nil {
			t.Fatal(err)
		}
	case "enrollments":
		setLiveDeviceIDForeignKeys(t, opened.db, false)
		defer setLiveDeviceIDForeignKeys(t, opened.db, true)
		createdCursor := EncodeUint64(99)
		statement := `
			INSERT INTO enrollments (
				enrollment_id, device_id, created_cursor, token_hash, scopes_json,
				request_fingerprint, response_json, created_status
			) VALUES (?, ?, ?, ?, ?, ?, ?, 201)`
		arguments := []any{
			"f7520000-0000-4000-8000-000000000003", deviceID, createdCursor[:],
			tokenWithByte(0x54), string(wantScopes), tokenWithByte(0x55), []byte("{}"),
		}
		if blob {
			statement = strings.Replace(statement, "VALUES (?, ?,", "VALUES (?, CAST(? AS BLOB),", 1)
			writeLiveWrongTypeText(t, opened.db, "enrollments", statement, arguments...)
			return
		}
		if _, err := opened.db.Exec(statement, arguments...); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown collision table %q", table)
	}
}

func TestEnrollmentDeviceCollisionPreflightBlocksCanonicalReenrollmentWithoutMutation(t *testing.T) {
	canonicalDeviceID := "f7520000-0000-4000-8000-000000000004"
	for _, test := range []struct {
		name, table string
		blob        bool
	}{
		{name: "NUL-suffixed device registry key", table: "devices"},
		{name: "BLOB device registry key", table: "devices", blob: true},
		{name: "NUL-suffixed enrollment witness key", table: "enrollments"},
		{name: "BLOB enrollment witness key", table: "enrollments", blob: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			opened, _ := openDataPlane(t)
			defer opened.Close()
			storedDeviceID := canonicalDeviceID
			if !test.blob {
				storedDeviceID = oversizedNULSuffixedText(canonicalDeviceID)
			}
			insertEnrollmentDeviceCollision(t, opened, test.table, storedDeviceID, test.blob)
			call, grant := enrollmentDeviceCollisionCall(t, opened, canonicalDeviceID)
			defer clear(grant.Grant)
			grantHash, err := auth.EnrollmentGrantHash(testIdentity.InstanceID, testIdentity.VaultID, grant.Grant)
			if err != nil {
				t.Fatal(err)
			}
			before := readLiveDeviceIDDurableState(t, opened.db)

			invalidGrant := call
			invalidGrant.Authorization = "JAT-Enrollment invalid"
			if _, protocolErr := opened.HandleAPI(context.Background(), invalidGrant); protocolErr == nil || protocolErr.Code != "unauthorized" {
				t.Fatalf("invalid grant ordering error=%v", protocolErr)
			}
			if _, protocolErr := opened.HandleAPI(context.Background(), call); protocolErr == nil || protocolErr.Code != "internal_error" {
				t.Fatalf("canonical re-enrollment collision error=%v", protocolErr)
			}

			after := readLiveDeviceIDDurableState(t, opened.db)
			assertLiveDeviceIDStateUnchanged(t, before, after)
			var canonicalDevices, canonicalEnrollments, unconsumedGrant int
			if err := opened.db.QueryRow(`
				SELECT (SELECT count(*) FROM devices WHERE device_id = ?),
				       (SELECT count(*) FROM enrollments WHERE device_id = ?),
				       (SELECT count(*) FROM enrollment_grants
				        WHERE grant_hash = ? AND consumed_enrollment_id IS NULL)`,
				canonicalDeviceID, canonicalDeviceID, grantHash[:],
			).Scan(&canonicalDevices, &canonicalEnrollments, &unconsumedGrant); err != nil {
				t.Fatal(err)
			}
			if canonicalDevices != 0 || canonicalEnrollments != 0 || unconsumedGrant != 1 {
				t.Fatalf("re-enrollment mutation: devices=%d enrollments=%d unconsumed_grant=%d",
					canonicalDevices, canonicalEnrollments, unconsumedGrant)
			}
		})
	}
}

func TestEnrollmentDeviceCollisionProbeUsesUniqueKeyRanges(t *testing.T) {
	opened, _ := openDataPlane(t)
	defer opened.Close()
	deviceID := "f7530000-0000-4000-8000-000000000001"
	lowerBytes := []byte(deviceID)
	upperBytes := append([]byte(nil), lowerBytes...)
	upperBytes[len(upperBytes)-1]++
	rows, err := opened.db.Query("EXPLAIN QUERY PLAN "+enrollmentDeviceCollisionProbeSQL,
		maxUUIDBytes, deviceID, string(upperBytes),
		maxUUIDBytes, lowerBytes, upperBytes,
		maxUUIDBytes, deviceID, string(upperBytes),
		maxUUIDBytes, lowerBytes, upperBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	searches := map[string]int{"enrollments": 0, "devices": 0}
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		for table := range searches {
			if strings.Contains(detail, "SCAN "+table) {
				rows.Close()
				t.Fatalf("enrollment device-key probe scans %s: %s", table, detail)
			}
			if strings.Contains(detail, "SEARCH "+table) &&
				strings.Contains(detail, "device_id>?") && strings.Contains(detail, "device_id<?") {
				searches[table]++
			}
		}
	}
	iterationErr := rows.Err()
	closeErr := rows.Close()
	if iterationErr != nil || closeErr != nil {
		t.Fatalf("explain enrollment device-key probe: iteration=%v close=%v", iterationErr, closeErr)
	}
	if searches["enrollments"] != 2 || searches["devices"] != 2 {
		t.Fatalf("enrollment device-key indexed searches=%v, want two per table", searches)
	}
}
