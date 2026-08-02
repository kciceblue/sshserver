package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"hash"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/api"
)

type markerKeyFixture struct {
	opened       *Store
	writerID     string
	writerToken  []byte
	staleID      string
	staleToken   []byte
	recordID     string
	witnessID    string
	afterCursor  string
	ackCursor    string
	replayCall   api.Request
	replayResult api.Response
}

func seedCollectedMarkerKeyFixture(t *testing.T) markerKeyFixture {
	t.Helper()
	opened, _ := openDataPlane(t)
	fixture := markerKeyFixture{
		opened:      opened,
		writerID:    "f4000000-0000-4000-8000-000000000001",
		writerToken: tokenWithByte(0xf4),
		staleID:     "f4000000-0000-4000-8000-000000000009",
		staleToken:  tokenWithByte(0xf5),
		recordID:    "f4000000-0000-4000-8000-000000000004",
		witnessID:   "f4000000-0000-4000-8000-000000000005",
	}
	enrollDevice(t, opened, protocolFixtureTime,
		"f4000000-0000-4000-8000-000000000002", fixture.writerID,
		"f4000000-0000-4000-8000-000000000003", fixture.writerToken,
	)
	var envelopeFixture struct {
		BaseMode putEnvelopeRequest `json:"base_mode"`
	}
	loadFixture(t, "vault-envelope.json", &envelopeFixture)
	envelopeBody, err := marshalJSON(envelopeFixture.BaseMode)
	if err != nil {
		opened.Close()
		t.Fatal(err)
	}
	if response, protocolErr := opened.HandleAPI(context.Background(), api.Request{
		Method: "PUT", Path: "/v1/vault-envelope", RequestID: "f4000000-0000-4000-8000-000000000014",
		Authorization: authorization(fixture.writerToken), Body: envelopeBody, Now: protocolFixtureTime,
	}); protocolErr != nil || response.Status != http.StatusOK {
		opened.Close()
		t.Fatalf("seed envelope: response=%+v error=%v", response, protocolErr)
	}
	tombstone := markerKeyRevision(fixture.writerID, fixture.recordID, fixture.witnessID, 1, true, true)
	fixture.replayCall = markerKeySyncCall(t, fixture.writerID, fixture.writerToken,
		"f4000000-0000-4000-8000-000000000006", "0", "0", []recordRevision{tombstone}, protocolFixtureTime)
	response, protocolErr := opened.HandleAPI(context.Background(), fixture.replayCall)
	if protocolErr != nil || response.Status != http.StatusOK {
		opened.Close()
		t.Fatalf("seed tombstone: response=%+v error=%v", response, protocolErr)
	}
	fixture.replayResult = response
	var seeded syncResponse
	if json.Unmarshal(response.Body, &seeded) != nil {
		opened.Close()
		t.Fatal("decode tombstone sync response")
	}

	retention := EncodeUint64(uint64(minimumRetentionUptime / time.Millisecond))
	if _, err := opened.db.Exec("UPDATE runtime_state SET accumulated_uptime_ms = ? WHERE singleton = 1", retention[:]); err != nil {
		opened.Close()
		t.Fatal(err)
	}
	collectCall := markerKeySyncCall(t, fixture.writerID, fixture.writerToken,
		"f4000000-0000-4000-8000-000000000007", seeded.ServerCursor, seeded.ServerCursor, []recordRevision{}, protocolFixtureTime)
	if response, protocolErr := opened.HandleAPI(context.Background(), collectCall); protocolErr != nil || response.Status != http.StatusOK {
		opened.Close()
		t.Fatalf("collect tombstone: response=%+v error=%v", response, protocolErr)
	}
	var retained, markerCount int
	if err := opened.db.QueryRow("SELECT retained FROM record_revisions WHERE revision_id = ?", fixture.witnessID).Scan(&retained); err != nil {
		opened.Close()
		t.Fatal(err)
	}
	if err := opened.db.QueryRow("SELECT count(*) FROM collection_markers WHERE record_id = ?", fixture.recordID).Scan(&markerCount); err != nil {
		opened.Close()
		t.Fatal(err)
	}
	if retained != 0 || markerCount != 1 {
		opened.Close()
		t.Fatalf("collected tombstone state: retained=%d marker_count=%d", retained, markerCount)
	}

	enrollDevice(t, opened, protocolFixtureTime.Add(time.Second),
		"f4000000-0000-4000-8000-000000000008", fixture.staleID,
		"f4000000-0000-4000-8000-00000000000a", fixture.staleToken,
	)
	bootstrap := createBoundedSnapshot(t, opened, fixture.staleID, fixture.staleToken,
		"f4000000-0000-4000-8000-000000000013", protocolFixtureTime.Add(time.Second))
	var floorBytes, ackBytes, maxReturnedBytes []byte
	if err := opened.db.QueryRow(`
		SELECT r.cursor_floor, d.last_ack_cursor, s.max_returned_cursor
		FROM runtime_state r, devices d JOIN device_sync_state s USING (device_id)
		WHERE r.singleton = 1 AND d.device_id = ?`, fixture.staleID,
	).Scan(&floorBytes, &ackBytes, &maxReturnedBytes); err != nil {
		opened.Close()
		t.Fatal(err)
	}
	floor, floorErr := DecodeUint64(floorBytes)
	ack, ackErr := DecodeUint64(ackBytes)
	maxReturned, maxReturnedErr := DecodeUint64(maxReturnedBytes)
	if floorErr != nil || ackErr != nil || maxReturnedErr != nil || floor > maxReturned || ack > maxReturned {
		opened.Close()
		t.Fatalf("stale-device cursors: floor=%d ack=%d max=%d errors=%v/%v/%v", floor, ack, maxReturned, floorErr, ackErr, maxReturnedErr)
	}
	cut, cutErr := parseUint64(bootstrap.CutCursor)
	if cutErr != nil || cut < floor || cut > maxReturned {
		opened.Close()
		t.Fatalf("bootstrap cut=%d floor=%d max=%d error=%v", cut, floor, maxReturned, cutErr)
	}
	fixture.afterCursor = bootstrap.CutCursor
	fixture.ackCursor = bootstrap.CutCursor
	return fixture
}

func markerKeyRevision(deviceID, recordID, revisionID string, counter uint64, tombstone, witness bool) recordRevision {
	revision := recordRevision{
		RecordID: recordID, RevisionID: revisionID, AuthorDeviceID: deviceID,
		AuthorCounter: encodeUint64Text(counter),
		VersionVector: []vectorEntry{{DeviceID: deviceID, Counter: encodeUint64Text(counter)}},
		PayloadSchema: "1", CryptoSuite: cryptoSuite, Tombstone: tombstone,
		Nonce:      base64.RawURLEncoding.EncodeToString(make([]byte, 24)),
		Ciphertext: base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
	}
	if witness {
		authenticator := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		revision.CollectionWitnessAuthenticator = &authenticator
	}
	return revision
}

func markerKeySyncCall(t *testing.T, deviceID string, token []byte, requestID, after, ack string, mutations []recordRevision, now time.Time) api.Request {
	t.Helper()
	body, err := marshalJSON(syncRequest{
		ProtocolVersion: "1", DeviceID: deviceID, RequestID: requestID,
		AfterCursor: after, AckCursor: ack, Mutations: mutations,
	})
	if err != nil {
		t.Fatal(err)
	}
	return api.Request{
		Method: "POST", Path: "/v1/sync", RequestID: requestID,
		Authorization: authorization(token), Body: body, Now: now,
	}
}

func markerKeyStaleCall(t *testing.T, fixture markerKeyFixture, requestID string, counter uint64) api.Request {
	t.Helper()
	revision := markerKeyRevision(fixture.staleID, fixture.recordID,
		"f4000000-0000-4000-8000-00000000000c", counter, false, false)
	return markerKeySyncCall(t, fixture.staleID, fixture.staleToken, requestID,
		fixture.afterCursor, fixture.ackCursor, []recordRevision{revision}, protocolFixtureTime.Add(2*time.Second))
}

func TestSyncMarkerKeyPreflightRejectsMalformedCollectedKeysBeforeMutation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, markerKeyFixture)
	}{
		{
			name: "NUL suffix",
			mutate: func(t *testing.T, fixture markerKeyFixture) {
				if _, err := fixture.opened.db.Exec("UPDATE collection_markers SET record_id = ? WHERE witness_revision_id = ?",
					oversizedNULSuffixedText(fixture.recordID), fixture.witnessID); err != nil {
					t.Fatal(err)
				}
				assertNULSuffixPassedSQLiteLengthCheck(t, fixture.opened.db, `
					SELECT length(record_id), octet_length(record_id), typeof(record_id)
					FROM collection_markers WHERE witness_revision_id = ?`, fixture.witnessID)
			},
		},
		{
			name: "BLOB-equivalent key",
			mutate: func(t *testing.T, fixture markerKeyFixture) {
				writeLiveWrongTypeText(t, fixture.opened.db, "collection_markers",
					"UPDATE collection_markers SET record_id = CAST(? AS BLOB) WHERE witness_revision_id = ?",
					fixture.recordID, fixture.witnessID)
				var length int
				var storageClass string
				if err := fixture.opened.db.QueryRow(`
					SELECT octet_length(record_id), typeof(record_id)
					FROM collection_markers WHERE witness_revision_id = ?`, fixture.witnessID).Scan(&length, &storageClass); err != nil {
					t.Fatal(err)
				}
				if length != maxUUIDBytes || storageClass != "blob" {
					t.Fatalf("wrong-type marker key shape: length=%d type=%q", length, storageClass)
				}
			},
		},
		{
			name: "BLOB-equivalent NUL suffix",
			mutate: func(t *testing.T, fixture markerKeyFixture) {
				if _, err := fixture.opened.db.Exec("PRAGMA ignore_check_constraints = ON"); err != nil {
					t.Fatal(err)
				}
				writeLiveWrongTypeText(t, fixture.opened.db, "collection_markers",
					"UPDATE collection_markers SET record_id = CAST(? AS BLOB) WHERE witness_revision_id = ?",
					fixture.recordID+"\x00suffix", fixture.witnessID)
				if _, err := fixture.opened.db.Exec("PRAGMA ignore_check_constraints = OFF"); err != nil {
					t.Fatal(err)
				}
				var length int
				var storageClass string
				if err := fixture.opened.db.QueryRow(`
					SELECT octet_length(record_id), typeof(record_id)
					FROM collection_markers WHERE witness_revision_id = ?`, fixture.witnessID).Scan(&length, &storageClass); err != nil {
					t.Fatal(err)
				}
				if length <= maxUUIDBytes || storageClass != "blob" {
					t.Fatalf("wrong-type suffixed marker key shape: length=%d type=%q", length, storageClass)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := seedCollectedMarkerKeyFixture(t)
			defer fixture.opened.Close()
			test.mutate(t, fixture)

			before := markerKeyDurableDigest(t, fixture.opened.db)
			call := markerKeyStaleCall(t, fixture, "f4000000-0000-4000-8000-00000000000b", 1)
			if _, protocolErr := fixture.opened.HandleAPI(context.Background(), call); protocolErr == nil || protocolErr.Code != "internal_error" {
				t.Fatalf("malformed marker key error=%v", protocolErr)
			}
			after := markerKeyDurableDigest(t, fixture.opened.db)
			if before != after {
				t.Fatalf("malformed marker key changed durable state: before=%x after=%x", before, after)
			}
			var revisionCount int
			if err := fixture.opened.db.QueryRow("SELECT count(*) FROM record_revisions WHERE revision_id = ?", "f4000000-0000-4000-8000-00000000000c").Scan(&revisionCount); err != nil {
				t.Fatal(err)
			}
			if revisionCount != 0 {
				t.Fatalf("hosted stale revision committed: count=%d", revisionCount)
			}
		})
	}
}

func TestSyncMarkerKeyPreflightIgnoresUnrelatedMarkerOnEmptySync(t *testing.T) {
	fixture := seedCollectedMarkerKeyFixture(t)
	defer fixture.opened.Close()
	corruptID := oversizedNULSuffixedText(fixture.recordID)
	if _, err := fixture.opened.db.Exec("UPDATE collection_markers SET record_id = ? WHERE witness_revision_id = ?", corruptID, fixture.witnessID); err != nil {
		t.Fatal(err)
	}
	call := markerKeySyncCall(t, fixture.staleID, fixture.staleToken,
		"f4000000-0000-4000-8000-00000000000d", fixture.afterCursor, fixture.ackCursor, []recordRevision{}, protocolFixtureTime.Add(2*time.Second))
	response, protocolErr := fixture.opened.HandleAPI(context.Background(), call)
	if protocolErr != nil || response.Status != http.StatusOK {
		t.Fatalf("unrelated malformed marker empty sync: response=%+v error=%v", response, protocolErr)
	}
	var receiptCount int
	if err := fixture.opened.db.QueryRow(`
		SELECT count(*) FROM operation_receipts
		WHERE device_id = ? AND operation = 'sync' AND request_id = ?`, fixture.staleID, call.RequestID).Scan(&receiptCount); err != nil {
		t.Fatal(err)
	}
	if receiptCount != 1 {
		t.Fatalf("empty sync receipt count=%d", receiptCount)
	}
}

func TestSyncMarkerKeyPreflightCoversBoundedCollectionLookup(t *testing.T) {
	fixture := seedCollectedMarkerKeyFixture(t)
	defer fixture.opened.Close()
	corruptID := oversizedNULSuffixedText(fixture.recordID)
	if _, err := fixture.opened.db.Exec("UPDATE collection_markers SET record_id = ? WHERE witness_revision_id = ?", corruptID, fixture.witnessID); err != nil {
		t.Fatal(err)
	}
	one := EncodeUint64(1)
	if _, err := fixture.opened.db.Exec(`
		INSERT INTO collection_records (record_id, barrier_cursor)
		VALUES (?, ?)`, fixture.recordID, one[:]); err != nil {
		t.Fatal(err)
	}
	before := markerKeyDurableDigest(t, fixture.opened.db)
	call := markerKeySyncCall(t, fixture.staleID, fixture.staleToken,
		"f4000000-0000-4000-8000-00000000000d", fixture.afterCursor, fixture.ackCursor, []recordRevision{}, protocolFixtureTime.Add(2*time.Second))
	if _, protocolErr := fixture.opened.HandleAPI(context.Background(), call); protocolErr == nil || protocolErr.Code != "internal_error" {
		t.Fatalf("bounded collection marker lookup error=%v", protocolErr)
	}
	after := markerKeyDurableDigest(t, fixture.opened.db)
	if before != after {
		t.Fatalf("bounded collection lookup changed durable state: before=%x after=%x", before, after)
	}
}

func TestSyncMarkerKeyPreflightPreservesCanonicalStaleAndAbsenceControls(t *testing.T) {
	t.Run("collected tombstone remains stale", func(t *testing.T) {
		fixture := seedCollectedMarkerKeyFixture(t)
		defer fixture.opened.Close()
		before := markerKeyDurableDigest(t, fixture.opened.db)
		call := markerKeyStaleCall(t, fixture, "f4000000-0000-4000-8000-00000000000b", 1)
		if _, protocolErr := fixture.opened.HandleAPI(context.Background(), call); protocolErr == nil || protocolErr.Code != "stale_after_collection" {
			t.Fatalf("canonical collected marker error=%v", protocolErr)
		}
		after := markerKeyDurableDigest(t, fixture.opened.db)
		if before != after {
			t.Fatalf("stale upload changed durable state: before=%x after=%x", before, after)
		}
	})

	t.Run("canonical marker absence accepts mutation", func(t *testing.T) {
		fixture := seedCollectedMarkerKeyFixture(t)
		defer fixture.opened.Close()
		invalidUnrelatedKey := strings.Repeat("x", maxUUIDBytes)
		if _, err := fixture.opened.db.Exec("UPDATE collection_markers SET record_id = ? WHERE witness_revision_id = ?",
			invalidUnrelatedKey, fixture.witnessID); err != nil {
			t.Fatal(err)
		}
		recordID := "f4000000-0000-4000-8000-00000000000d"
		revisionID := "f4000000-0000-4000-8000-00000000000e"
		revision := markerKeyRevision(fixture.staleID, recordID, revisionID, 1, false, false)
		call := markerKeySyncCall(t, fixture.staleID, fixture.staleToken,
			"f4000000-0000-4000-8000-00000000000f", fixture.afterCursor, fixture.ackCursor, []recordRevision{revision}, protocolFixtureTime.Add(2*time.Second))
		response, protocolErr := fixture.opened.HandleAPI(context.Background(), call)
		if protocolErr != nil || response.Status != http.StatusOK {
			t.Fatalf("canonical marker absence: response=%+v error=%v", response, protocolErr)
		}
		var count int
		if err := fixture.opened.db.QueryRow("SELECT count(*) FROM record_revisions WHERE revision_id = ? AND record_id = ?", revisionID, recordID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("canonical absence revision count=%d", count)
		}
	})
}

func TestSyncMarkerKeyPreflightPreservesEarlierErrorOrdering(t *testing.T) {
	fixture := seedCollectedMarkerKeyFixture(t)
	defer fixture.opened.Close()
	if _, err := fixture.opened.db.Exec("UPDATE collection_markers SET record_id = ? WHERE witness_revision_id = ?",
		oversizedNULSuffixedText(fixture.recordID), fixture.witnessID); err != nil {
		t.Fatal(err)
	}
	before := markerKeyDurableDigest(t, fixture.opened.db)

	replayed, protocolErr := fixture.opened.HandleAPI(context.Background(), fixture.replayCall)
	if protocolErr != nil || replayed.Status != fixture.replayResult.Status || !bytes.Equal(replayed.Body, fixture.replayResult.Body) {
		t.Fatalf("exact replay ordering: response=%+v error=%v", replayed, protocolErr)
	}
	unauthorized := markerKeySyncCall(t, fixture.staleID, fixture.staleToken,
		"f4000000-0000-4000-8000-000000000010", fixture.afterCursor, fixture.ackCursor, []recordRevision{}, protocolFixtureTime.Add(2*time.Second))
	unauthorized.Authorization = "Bearer invalid"
	if _, protocolErr := fixture.opened.HandleAPI(context.Background(), unauthorized); protocolErr == nil || protocolErr.Code != "unauthorized" {
		t.Fatalf("authorization ordering error=%v", protocolErr)
	}
	invalidAck := markerKeySyncCall(t, fixture.staleID, fixture.staleToken,
		"f4000000-0000-4000-8000-000000000011", fixture.afterCursor, encodeUint64Text(math.MaxUint64), []recordRevision{}, protocolFixtureTime.Add(2*time.Second))
	if _, protocolErr := fixture.opened.HandleAPI(context.Background(), invalidAck); protocolErr == nil || protocolErr.Code != "invalid_request" {
		t.Fatalf("ack ordering error=%v", protocolErr)
	}
	counterConflict := markerKeyStaleCall(t, fixture, "f4000000-0000-4000-8000-000000000012", 2)
	if _, protocolErr := fixture.opened.HandleAPI(context.Background(), counterConflict); protocolErr == nil || protocolErr.Code != "counter_conflict" {
		t.Fatalf("counter ordering error=%v", protocolErr)
	}

	after := markerKeyDurableDigest(t, fixture.opened.db)
	if before != after {
		t.Fatalf("earlier errors changed durable state: before=%x after=%x", before, after)
	}
}

func TestCollectionMarkerKeyProbeUsesPrimaryKeyRanges(t *testing.T) {
	opened, _ := openDataPlane(t)
	defer opened.Close()
	recordID := "f4000000-0000-4000-8000-000000000020"
	lowerBytes := []byte(recordID)
	upperBytes := append([]byte(nil), lowerBytes...)
	upperBytes[len(upperBytes)-1]++
	rows, err := opened.db.Query("EXPLAIN QUERY PLAN "+collectionMarkerKeyProbeSQL,
		maxUUIDBytes, recordID, string(upperBytes),
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
		if strings.Contains(detail, "SCAN collection_markers") {
			rows.Close()
			t.Fatalf("marker-key probe scans full table: %s", detail)
		}
		if strings.Contains(detail, "SEARCH collection_markers") &&
			strings.Contains(detail, "record_id>?") && strings.Contains(detail, "record_id<?") {
			searches++
		}
	}
	iterationErr := rows.Err()
	closeErr := rows.Close()
	if iterationErr != nil || closeErr != nil {
		t.Fatalf("explain marker-key probe: iteration=%v close=%v", iterationErr, closeErr)
	}
	if searches != 2 {
		t.Fatalf("marker-key indexed range searches=%d, want=2", searches)
	}
}

type markerKeyTableShape struct {
	name    string
	columns []string
}

func markerKeyDurableDigest(t *testing.T, database *sql.DB) [sha256.Size]byte {
	t.Helper()
	tableRows, err := database.Query(`
		SELECT name FROM sqlite_schema
		WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
		ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []markerKeyTableShape
	for tableRows.Next() {
		var table markerKeyTableShape
		if err := tableRows.Scan(&table.name); err != nil {
			tableRows.Close()
			t.Fatal(err)
		}
		tables = append(tables, table)
	}
	tableIterationErr := tableRows.Err()
	tableCloseErr := tableRows.Close()
	if tableIterationErr != nil || tableCloseErr != nil {
		t.Fatalf("read durable table list: iteration=%v close=%v", tableIterationErr, tableCloseErr)
	}
	for index := range tables {
		columnRows, err := database.Query("PRAGMA table_info(" + markerKeyQuoteIdentifier(tables[index].name) + ")")
		if err != nil {
			t.Fatal(err)
		}
		for columnRows.Next() {
			var cid, notNull, primaryKey int
			var name, declaredType string
			var defaultValue any
			if err := columnRows.Scan(&cid, &name, &declaredType, &notNull, &defaultValue, &primaryKey); err != nil {
				columnRows.Close()
				t.Fatal(err)
			}
			tables[index].columns = append(tables[index].columns, name)
		}
		columnIterationErr := columnRows.Err()
		columnCloseErr := columnRows.Close()
		if columnIterationErr != nil || columnCloseErr != nil {
			t.Fatalf("read %s columns: iteration=%v close=%v", tables[index].name, columnIterationErr, columnCloseErr)
		}
	}

	digest := sha256.New()
	for _, table := range tables {
		markerKeyDigestField(digest, 't', []byte(table.name))
		quotedColumns := make([]string, len(table.columns))
		order := make([]string, len(table.columns))
		for index, column := range table.columns {
			markerKeyDigestField(digest, 'c', []byte(column))
			quotedColumns[index] = markerKeyQuoteIdentifier(column)
			order[index] = encodeUint64Text(uint64(index + 1))
		}
		query := "SELECT " + strings.Join(quotedColumns, ", ") + " FROM " + markerKeyQuoteIdentifier(table.name) +
			" ORDER BY " + strings.Join(order, ", ")
		rows, err := database.Query(query)
		if err != nil {
			t.Fatalf("read durable table %s: %v", table.name, err)
		}
		for rows.Next() {
			values := make([]any, len(table.columns))
			destinations := make([]any, len(values))
			for index := range values {
				destinations[index] = &values[index]
			}
			if err := rows.Scan(destinations...); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			markerKeyDigestField(digest, 'r', nil)
			for _, value := range values {
				markerKeyDigestValue(t, digest, value)
			}
		}
		iterationErr := rows.Err()
		closeErr := rows.Close()
		if iterationErr != nil || closeErr != nil {
			t.Fatalf("read durable table %s: iteration=%v close=%v", table.name, iterationErr, closeErr)
		}
	}
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func markerKeyQuoteIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

func markerKeyDigestField(digest hash.Hash, tag byte, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	digest.Write([]byte{tag})
	digest.Write(length[:])
	digest.Write(value)
}

func markerKeyDigestValue(t *testing.T, digest hash.Hash, value any) {
	t.Helper()
	switch value := value.(type) {
	case nil:
		markerKeyDigestField(digest, 'n', nil)
	case int64:
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], uint64(value))
		markerKeyDigestField(digest, 'i', encoded[:])
	case float64:
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], math.Float64bits(value))
		markerKeyDigestField(digest, 'f', encoded[:])
	case bool:
		if value {
			markerKeyDigestField(digest, 'b', []byte{1})
		} else {
			markerKeyDigestField(digest, 'b', []byte{0})
		}
	case string:
		markerKeyDigestField(digest, 's', []byte(value))
	case []byte:
		markerKeyDigestField(digest, 'x', value)
	case time.Time:
		markerKeyDigestField(digest, 'd', []byte(value.UTC().Format(time.RFC3339Nano)))
	default:
		t.Fatalf("unsupported durable value type %T", value)
	}
}
