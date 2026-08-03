package store

import "database/sql"

const (
	maxUUIDBytes      = 36
	maxOperationBytes = len("device-revocation/") + maxUUIDBytes
	maxVectorEntries  = 64
	// A canonical maximum vector is '[' + 64 UUID/max-uint64 entries +
	// 63 commas + ']'. UUIDs and counters cannot require JSON escaping.
	maxVectorBytes = 2 + maxVectorEntries*len(`{"device_id":"00000000-0000-4000-8000-000000000000","counter":"18446744073709551615"}`) + maxVectorEntries - 1
)

func boundedRequiredBytes(length int64, value []byte, maximum int) bool {
	return length > 0 && length <= int64(maximum) && int64(len(value)) == length
}

func boundedOptionalBytes(length sql.NullInt64, value []byte, maximum int) bool {
	if !length.Valid {
		return value == nil
	}
	return boundedRequiredBytes(length.Int64, value, maximum)
}

func boundedRequiredText(length int64, value sql.NullString, maximum int) bool {
	return value.Valid && length > 0 && length <= int64(maximum) && int64(len(value.String)) == length
}

func boundedOptionalText(length sql.NullInt64, value sql.NullString, maximum int) bool {
	if !length.Valid {
		return !value.Valid
	}
	return value.Valid && length.Int64 > 0 && length.Int64 <= int64(maximum) && int64(len(value.String)) == length.Int64
}
