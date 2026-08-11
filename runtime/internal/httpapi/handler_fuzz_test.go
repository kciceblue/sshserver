package httpapi

import (
	"strings"
	"testing"
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
