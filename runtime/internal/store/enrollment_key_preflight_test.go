package store

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/api"
	"github.com/kciceblue/sshserver/runtime/internal/auth"
)

type enrollmentKeyFixture struct {
	opened       *Store
	enrollmentID string
	deviceID     string
}

func seedEnrollmentKeyFixture(t *testing.T) enrollmentKeyFixture {
	t.Helper()
	opened, _ := openDataPlane(t)
	fixture := enrollmentKeyFixture{
		opened:       opened,
		enrollmentID: "f7400000-0000-4000-8000-000000000001",
		deviceID:     "f7400000-0000-4000-8000-000000000002",
	}
	response := enrollDevice(t, opened, protocolFixtureTime,
		fixture.enrollmentID, fixture.deviceID,
		"f7400000-0000-4000-8000-000000000003", tokenWithByte(0x74))
	if response.Status != http.StatusCreated {
		opened.Close()
		t.Fatalf("seed enrollment status=%d", response.Status)
	}
	return fixture
}

func replacementEnrollmentCall(t *testing.T, fixture enrollmentKeyFixture, grant EnrollmentGrant) (api.Request, string) {
	t.Helper()
	deviceID := "f7400000-0000-4000-8000-000000000004"
	body, err := marshalJSON(enrollmentRequest{
		ProtocolVersion: "1",
		EnrollmentID:    fixture.enrollmentID,
		DeviceID:        deviceID,
		DeviceToken:     base64.RawURLEncoding.EncodeToString(tokenWithByte(0x75)),
		Scopes:          auth.FixedScopes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return api.Request{
		Method:        "POST",
		Path:          "/v1/enrollments",
		RequestID:     "f7400000-0000-4000-8000-000000000005",
		Authorization: "JAT-Enrollment " + base64.RawURLEncoding.EncodeToString(grant.Grant),
		Body:          body,
		Now:           protocolFixtureTime.Add(time.Second),
	}, deviceID
}

func TestEnrollmentKeyPreflightRejectsMalformedCollisionBeforeReplacementGrantMutation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, enrollmentKeyFixture)
	}{
		{
			name: "NUL-suffixed TEXT key",
			mutate: func(t *testing.T, fixture enrollmentKeyFixture) {
				if _, err := fixture.opened.db.Exec(
					"UPDATE enrollments SET enrollment_id = ? WHERE device_id = ?",
					oversizedNULSuffixedText(fixture.enrollmentID), fixture.deviceID,
				); err != nil {
					t.Fatal(err)
				}
				assertNULSuffixPassedSQLiteLengthCheck(t, fixture.opened.db, `
					SELECT length(enrollment_id), octet_length(enrollment_id), typeof(enrollment_id)
					FROM enrollments WHERE device_id = ?`, fixture.deviceID)
			},
		},
		{
			name: "BLOB-equivalent key",
			mutate: func(t *testing.T, fixture enrollmentKeyFixture) {
				writeLiveWrongTypeText(t, fixture.opened.db, "enrollments",
					"UPDATE enrollments SET enrollment_id = CAST(? AS BLOB) WHERE device_id = ?",
					fixture.enrollmentID, fixture.deviceID)
			},
		},
		{
			name: "NUL-suffixed BLOB key",
			mutate: func(t *testing.T, fixture enrollmentKeyFixture) {
				if _, err := fixture.opened.db.Exec("PRAGMA ignore_check_constraints = ON"); err != nil {
					t.Fatal(err)
				}
				writeLiveWrongTypeText(t, fixture.opened.db, "enrollments",
					"UPDATE enrollments SET enrollment_id = CAST(? AS BLOB) WHERE device_id = ?",
					fixture.enrollmentID+"\x00suffix", fixture.deviceID)
				if _, err := fixture.opened.db.Exec("PRAGMA ignore_check_constraints = OFF"); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := seedEnrollmentKeyFixture(t)
			defer fixture.opened.Close()
			test.mutate(t, fixture)

			grant := createGrant(t, fixture.opened, protocolFixtureTime.Add(time.Second))
			defer clear(grant.Grant)
			call, replacementDeviceID := replacementEnrollmentCall(t, fixture, grant)
			before := readLiveDeviceIDDurableState(t, fixture.opened.db)
			if _, protocolErr := fixture.opened.HandleAPI(context.Background(), call); protocolErr == nil || protocolErr.Code != "internal_error" {
				t.Fatalf("malformed enrollment key error=%v", protocolErr)
			}
			after := readLiveDeviceIDDurableState(t, fixture.opened.db)
			assertLiveDeviceIDStateUnchanged(t, before, after)

			var canonicalEnrollments, replacementDevices, unconsumedGrants int
			if err := fixture.opened.db.QueryRow(`
				SELECT (SELECT count(*) FROM enrollments WHERE enrollment_id = ?),
				       (SELECT count(*) FROM devices WHERE device_id = ?),
				       (SELECT count(*) FROM enrollment_grants WHERE consumed_enrollment_id IS NULL)`,
				fixture.enrollmentID, replacementDeviceID,
			).Scan(&canonicalEnrollments, &replacementDevices, &unconsumedGrants); err != nil {
				t.Fatal(err)
			}
			if canonicalEnrollments != 0 || replacementDevices != 0 || unconsumedGrants != 1 {
				t.Fatalf("replacement mutated state: canonical_enrollments=%d replacement_devices=%d unconsumed_grants=%d",
					canonicalEnrollments, replacementDevices, unconsumedGrants)
			}
		})
	}
}

func TestEnrollmentKeyProbeUsesPrimaryKeyRanges(t *testing.T) {
	opened, _ := openDataPlane(t)
	defer opened.Close()
	enrollmentID := "f7410000-0000-4000-8000-000000000001"
	lowerBytes := []byte(enrollmentID)
	upperBytes := append([]byte(nil), lowerBytes...)
	upperBytes[len(upperBytes)-1]++
	rows, err := opened.db.Query("EXPLAIN QUERY PLAN "+enrollmentKeyProbeSQL,
		maxUUIDBytes, enrollmentID, string(upperBytes),
		maxUUIDBytes, lowerBytes, upperBytes,
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
		if strings.Contains(detail, "SCAN enrollments") {
			rows.Close()
			t.Fatalf("enrollment-key probe scans full table: %s", detail)
		}
		if strings.Contains(detail, "SEARCH enrollments") &&
			strings.Contains(detail, "enrollment_id>?") && strings.Contains(detail, "enrollment_id<?") {
			searches++
		}
	}
	iterationErr := rows.Err()
	closeErr := rows.Close()
	if iterationErr != nil || closeErr != nil {
		t.Fatalf("explain enrollment-key probe: iteration=%v close=%v", iterationErr, closeErr)
	}
	if searches != 2 {
		t.Fatalf("enrollment-key indexed range searches=%d, want=2", searches)
	}
}
