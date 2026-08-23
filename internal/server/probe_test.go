package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// postProbeTLS drives handleProbeTLS with a raw JSON body and returns the recorder.
func postProbeTLS(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	s := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/api/probe/tls", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.handleProbeTLS(rr, req)
	return rr
}

func TestHandleProbeTLS_BadJSON(t *testing.T) {
	rr := postProbeTLS(t, "{not json")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad JSON: want 400, got %d (%s)", rr.Code, rr.Body.String())
	}
}

func TestHandleProbeTLS_EmptyHost(t *testing.T) {
	rr := postProbeTLS(t, `{"host":"  "}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("empty host: want 400, got %d (%s)", rr.Code, rr.Body.String())
	}
}

func TestHandleProbeTLS_InvalidHost(t *testing.T) {
	// A leading hyphen / shell-meta input fails ValidTarget → 400 before any dial.
	for _, h := range []string{"-flag", "bad;rm -rf", "a b c", "http://x/y"} {
		rr := postProbeTLS(t, `{"host":"`+h+`"}`)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("invalid host %q: want 400, got %d (%s)", h, rr.Code, rr.Body.String())
		}
	}
}

func TestHandleProbeTLS_SSRFRefused(t *testing.T) {
	// Hosts that resolve to internal addresses must be refused (403) and never reach
	// ProbeTLS. localhost / 127.0.0.1 / a private literal cover loopback + RFC1918.
	for _, h := range []string{"localhost", "127.0.0.1", "10.0.0.1", "169.254.169.254", "192.168.50.1", "100.64.0.1"} {
		rr := postProbeTLS(t, `{"host":"`+h+`"}`)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("internal host %q: want 403, got %d (%s)", h, rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "internal") {
			t.Fatalf("internal host %q: want an 'internal' error, got %s", h, rr.Body.String())
		}
	}
}
