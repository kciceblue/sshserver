package httpapi

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kciceblue/sshserver/runtime/internal/api"
)

func FuzzHeaderContainsToken(f *testing.F) {
	f.Add("keep-alive, Upgrade", "upgrade")
	f.Add("keep-alive\nclose, UpGrAdE", "UPGRADE")
	f.Add("keep-alive, xupgrade", "upgrade")
	f.Fuzz(func(t *testing.T, joinedValues, token string) {
		if len(joinedValues) > 64*1024 || len(token) > 1024 {
			return
		}
		values := strings.Split(joinedValues, "\n")
		want := headerTokenReference(values, token)
		first := headerContainsToken(values, token)
		second := headerContainsToken(values, token)
		if first != want || second != want {
			t.Fatalf("header token result changed: first=%v second=%v want=%v", first, second, want)
		}

		request := validRequest("/v1/healthz")
		request.Header["Connection"] = append([]string(nil), values...)
		transportRejected := validateTransport(request) != nil
		wantUpgradeRejection := headerTokenReference(values, "upgrade")
		if transportRejected != wantUpgradeRejection {
			t.Fatalf("transport/header parser drift: rejected=%v want=%v", transportRejected, wantUpgradeRejection)
		}
	})
}

func FuzzValidateTransportRequest(f *testing.F) {
	f.Add([]byte{0, 0, 0})
	for byteIndex, bitCount := range []int{8, 8, 2} {
		for bit := 0; bit < bitCount; bit++ {
			seed := []byte{0, 0, 0}
			seed[byteIndex] = 1 << bit
			f.Add(seed)
		}
	}
	f.Fuzz(func(t *testing.T, mutation []byte) {
		if len(mutation) > 64*1024 {
			return
		}
		first, wantRejected := transportRequestMutation(mutation)
		second, secondWantRejected := transportRequestMutation(mutation)
		firstRejected := validateTransport(first) != nil
		secondRejected := validateTransport(second) != nil
		if wantRejected != secondWantRejected || firstRejected != secondRejected {
			t.Fatal("transport request validation changed across identical input")
		}
		if firstRejected != wantRejected {
			t.Fatalf("transport request rejection=%v want=%v", firstRejected, wantRejected)
		}
	})
}

func FuzzHTTPBodyFraming(f *testing.F) {
	const contentType = "application/json; charset=utf-8"
	f.Add("POST", contentType, []byte(`{}`), int64(2), uint8(0))
	f.Add("PUT", contentType, []byte("x"), int64(1), uint8(3))
	f.Add("GET", contentType, []byte(`{}`), int64(2), uint8(0))
	f.Add("POST", "application/json", []byte(`{}`), int64(2), uint8(0))
	f.Add("POST", contentType+"\n"+contentType, []byte(`{}`), int64(2), uint8(0))
	f.Add("POST", contentType, []byte{}, int64(1), uint8(0))
	f.Add("POST", contentType, []byte(`{}`), int64(0), uint8(0))
	f.Add("POST", contentType, []byte(`{}trailing`), int64(2), uint8(0))
	f.Add("POST", contentType, []byte(`{}`), int64(3), uint8(0))
	f.Add("POST", contentType, []byte("x"), int64(MaxBodyBytes+1), uint8(5))
	f.Add("GET", "", []byte{}, int64(0), uint8(4))
	f.Add("GET", "", []byte("x"), int64(0), uint8(0))

	f.Fuzz(func(t *testing.T, method, joinedContentTypes string, input []byte, declaredLength int64, mode uint8) {
		if len(method) > 1024 || len(joinedContentTypes) > 64*1024 || len(input) > 64*1024 {
			return
		}
		contentTypes := httpBodyFuzzContentTypes(joinedContentTypes, mode)
		body := httpBodyFuzzPayload(input, mode)
		wantBody, wantCode := exactJSONBodyFraming(method, contentTypes, declaredLength, body)

		firstRequest, _ := httpBodyFuzzRequest(method, contentTypes, declaredLength, body, mode, false)
		secondRequest, _ := httpBodyFuzzRequest(method, contentTypes, declaredLength, body, mode, false)
		firstBody, firstErr := readJSONBody(httptest.NewRecorder(), firstRequest)
		secondBody, secondErr := readJSONBody(httptest.NewRecorder(), secondRequest)
		firstCode := httpBodyFuzzErrorCode(firstErr)
		secondCode := httpBodyFuzzErrorCode(secondErr)
		if firstCode != wantCode || secondCode != wantCode {
			t.Fatalf("JSON body framing code first=%q second=%q want=%q", firstCode, secondCode, wantCode)
		}
		if !bytes.Equal(firstBody, wantBody) || !bytes.Equal(secondBody, wantBody) {
			t.Fatalf("JSON body framing payload lengths first=%d second=%d want=%d", len(firstBody), len(secondBody), len(wantBody))
		}

		firstEmptyRequest, firstPresent := httpBodyFuzzRequest(method, contentTypes, declaredLength, body, mode, true)
		secondEmptyRequest, secondPresent := httpBodyFuzzRequest(method, contentTypes, declaredLength, body, mode, true)
		firstEmptyErr := requireEmptyBody(httptest.NewRecorder(), firstEmptyRequest)
		secondEmptyErr := requireEmptyBody(httptest.NewRecorder(), secondEmptyRequest)
		wantEmpty := exactEmptyBodyFraming(declaredLength)
		if firstPresent != secondPresent || (firstEmptyErr == nil) != wantEmpty || (secondEmptyErr == nil) != wantEmpty {
			t.Fatalf("empty body framing first=%v second=%v want=%v", firstEmptyErr == nil, secondEmptyErr == nil, wantEmpty)
		}
	})
}

type httpBodyFuzzReadCloser struct {
	body   []byte
	offset int
	chunk  int
	short  bool
}

func (reader *httpBodyFuzzReadCloser) Read(destination []byte) (int, error) {
	if reader.offset == len(reader.body) {
		if reader.short {
			reader.short = false
			return 0, io.ErrUnexpectedEOF
		}
		return 0, io.EOF
	}
	count := len(reader.body) - reader.offset
	if count > reader.chunk {
		count = reader.chunk
	}
	if count > len(destination) {
		count = len(destination)
	}
	copy(destination, reader.body[reader.offset:reader.offset+count])
	reader.offset += count
	return count, nil
}

func (*httpBodyFuzzReadCloser) Close() error { return nil }

func httpBodyFuzzRequest(method string, contentTypes []string, declaredLength int64, body []byte, mode uint8, allowNil bool) (*http.Request, bool) {
	request := &http.Request{
		Method:        method,
		Header:        make(http.Header),
		ContentLength: declaredLength,
	}
	bodyPresent := !allowNil || mode%8 != 4
	if bodyPresent {
		framedBody := append([]byte(nil), body...)
		short := false
		if declaredLength >= 0 {
			if declaredLength <= int64(len(framedBody)) {
				framedBody = framedBody[:int(declaredLength)]
			} else {
				short = true
			}
		}
		request.Body = &httpBodyFuzzReadCloser{
			body:  framedBody,
			chunk: 1 + int(mode%32),
			short: short,
		}
	}
	if contentTypes != nil {
		request.Header["Content-Type"] = append([]string(nil), contentTypes...)
	}
	return request, bodyPresent
}

func httpBodyFuzzContentTypes(joined string, mode uint8) []string {
	if mode%8 == 1 {
		return nil
	}
	values := strings.Split(joined, "\n")
	if mode%8 == 2 {
		values = append(values, values...)
	}
	return values
}

func httpBodyFuzzPayload(input []byte, mode uint8) []byte {
	if mode%8 != 5 {
		return append([]byte(nil), input...)
	}
	payload := make([]byte, MaxBodyBytes+1)
	if len(input) == 0 {
		input = []byte{'x'}
	}
	for offset := 0; offset < len(payload); offset += len(input) {
		copy(payload[offset:], input)
	}
	return payload
}

func httpBodyFuzzErrorCode(err *api.Error) string {
	if err == nil {
		return ""
	}
	return err.Code
}

func exactJSONBodyFraming(method string, contentTypes []string, declaredLength int64, body []byte) ([]byte, string) {
	if (method != "POST" && method != "PUT") || len(contentTypes) != 1 || contentTypes[0] != "application/json; charset=utf-8" || declaredLength <= 0 {
		return nil, "invalid_request"
	}
	visibleLength := declaredLength
	short := false
	if declaredLength > int64(len(body)) {
		visibleLength = int64(len(body))
		short = true
	}
	if visibleLength > MaxBodyBytes {
		return nil, "limit_exceeded"
	}
	if short || visibleLength == 0 {
		return nil, "invalid_request"
	}
	return append([]byte(nil), body[:int(visibleLength)]...), ""
}

func exactEmptyBodyFraming(declaredLength int64) bool {
	return declaredLength == 0
}

func transportRequestMutation(mutation []byte) (*http.Request, bool) {
	var flags [3]byte
	copy(flags[:], mutation)
	request := validRequest("/v1/healthz")
	if flags[0]&(1<<0) != 0 {
		request.ProtoMajor = 2
	}
	if flags[0]&(1<<1) != 0 {
		request.ProtoMinor = 0
	}
	if flags[0]&(1<<2) != 0 {
		request.URL.Scheme = "https"
		request.URL.Host = "loopback.invalid"
	}
	if flags[0]&(1<<3) != 0 {
		request.RequestURI = "http://loopback.invalid/v1/healthz"
	}
	if flags[0]&(1<<4) != 0 {
		request.URL.RawQuery = "unsafe=1"
	}
	if flags[0]&(1<<5) != 0 {
		request.URL.ForceQuery = true
	}
	if flags[0]&(1<<6) != 0 {
		request.URL.Fragment = "unsafe"
	}
	if flags[0]&(1<<7) != 0 {
		request.URL.RawPath = "/v1/%68ealthz"
	}
	if flags[1]&(1<<0) != 0 {
		request.Method = http.MethodConnect
	}
	if flags[1]&(1<<1) != 0 {
		request.Header.Set("Origin", "https://loopback.invalid")
	}
	if flags[1]&(1<<2) != 0 {
		request.Header.Set("Upgrade", "websocket")
	}
	if flags[1]&(1<<3) != 0 {
		request.Header.Set("Connection", "keep-alive, Upgrade")
	}
	if flags[1]&(1<<4) != 0 {
		request.Header.Set("Proxy-Connection", "keep-alive")
	}
	if flags[1]&(1<<5) != 0 {
		request.TransferEncoding = []string{"chunked"}
	}
	if flags[1]&(1<<6) != 0 {
		request.Trailer = http.Header{"X-Trailer": []string{"unsafe"}}
	}
	if flags[1]&(1<<7) != 0 {
		request.Header.Set("Expect", "100-continue")
	}
	if flags[2]&(1<<0) != 0 {
		request.Header.Set("TE", "trailers")
	}
	if flags[2]&(1<<1) != 0 {
		request.ContentLength = -1
	}
	wantRejected := flags[0] != 0 || flags[1] != 0 || flags[2]&0x03 != 0
	return request, wantRejected
}

func headerTokenReference(values []string, token string) bool {
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(item), token) {
				return true
			}
		}
	}
	return false
}
