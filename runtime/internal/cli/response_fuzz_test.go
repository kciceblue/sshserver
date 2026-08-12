package cli

import "testing"

func FuzzDecodeCLIResponses(f *testing.F) {
	f.Add([]byte(`{"protocol_version":"1","instance_id":"00000000-0000-4000-8000-000000000001","vault_id":"00000000-0000-4000-8000-000000000002","instance_secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","enrollment_grant":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","expires_at":"2030-01-01T00:00:00.000Z","loopback_port":37421}`))
	f.Add([]byte(`{"status":"ok","protocol_version":"1"}`))
	f.Add([]byte("37421"))
	f.Add([]byte("+1"))
	f.Add([]byte("0001"))
	f.Add([]byte("65536"))
	f.Add([]byte("-1"))
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 4096 {
			return
		}
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

		portText := string(payload)
		listeners := []string{"127.0.0.1:" + portText, "[::1]:" + portText}
		firstPort, firstPortErr := discoverableIPv4LoopbackPort(listeners)
		secondPort, secondPortErr := discoverableIPv4LoopbackPort(listeners)
		wantPort, wantPortOK := exactEndpointPort(portText)
		if (firstPortErr == nil) != wantPortOK || (secondPortErr == nil) != wantPortOK {
			t.Fatalf("endpoint-port acceptance first=%v second=%v want=%v", firstPortErr == nil, secondPortErr == nil, wantPortOK)
		}
		if wantPortOK && (firstPort != wantPort || secondPort != wantPort) {
			t.Fatalf("endpoint port first=%d second=%d want=%d", firstPort, secondPort, wantPort)
		}

		firstPath, firstPathErr := filepathAbs(string(payload))
		secondPath, secondPathErr := filepathAbs(string(payload))
		wantPathOK := len(payload) > 0 && payload[0] == '/'
		if (firstPathErr == nil) != wantPathOK || (secondPathErr == nil) != wantPathOK {
			t.Fatalf("absolute executable path acceptance first=%v second=%v want=%v", firstPathErr == nil, secondPathErr == nil, wantPathOK)
		}
		if wantPathOK && (firstPath != string(payload) || secondPath != string(payload)) {
			t.Fatal("absolute executable path changed across validation")
		}
	})
}

func exactEndpointPort(value string) (int, bool) {
	if value == "" {
		return 0, false
	}
	index := 0
	if value[0] == '+' {
		index++
	} else if value[0] == '-' {
		return 0, false
	}
	if index == len(value) {
		return 0, false
	}
	port := 0
	for ; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return 0, false
		}
		port = port*10 + int(value[index]-'0')
		if port > 65535 {
			return 0, false
		}
	}
	return port, port >= 1
}
