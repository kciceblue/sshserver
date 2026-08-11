package cli

import "testing"

func FuzzDecodeCLIResponses(f *testing.F) {
	f.Add([]byte(`{"protocol_version":"1","instance_id":"00000000-0000-4000-8000-000000000001","vault_id":"00000000-0000-4000-8000-000000000002","instance_secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","enrollment_grant":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","expires_at":"2030-01-01T00:00:00.000Z","loopback_port":37421}`))
	f.Add([]byte(`{"status":"ok","protocol_version":"1"}`))
	f.Fuzz(func(t *testing.T, payload []byte) {
		firstEnrollment, firstEnrollmentErr := decodeEnrollmentCreateResponse(payload)
		secondEnrollment, secondEnrollmentErr := decodeEnrollmentCreateResponse(payload)
		if (firstEnrollmentErr == nil) != (secondEnrollmentErr == nil) || firstEnrollment != secondEnrollment {
			t.Fatal("enrollment-response parser changed across identical input")
		}
		firstHealthErr := decodeHealthResponse(payload)
		secondHealthErr := decodeHealthResponse(payload)
		if (firstHealthErr == nil) != (secondHealthErr == nil) {
			t.Fatal("health-response parser changed across identical input")
		}
	})
}
