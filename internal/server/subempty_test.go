package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A 200 whose body yields no connections used to return (0, nil), and the panel rendered
// "Last refreshed 2m ago (+0 new)" — exactly what an up-to-date subscription looks like. A captive
// portal, an HTML error page, or a provider outage serving an empty payload all read as success.
func TestSubrefresh_BodyWithNothingUsableIsAFailure(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"captive portal", "<html><body>Sign in to continue</body></html>"},
		{"provider error page", "<!DOCTYPE html><h1>502 Bad Gateway</h1>"},
		{"empty body", ""},
		{"whitespace only", "   \n\n\t "},
		{"plain prose", "your subscription has expired, please renew"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(c.body))
			}))
			defer ts.Close()
			s := subrefresh_server(t, ts.URL)

			added, err := s.refreshSubscriptionOnce(context.Background())
			if err == nil {
				t.Fatalf("a body with no connections reported success (+%d new) — indistinguishable from being up to date", added)
			}
			if added != 0 {
				t.Errorf("nothing was added, got %d", added)
			}
			if !strings.Contains(err.Error(), "subscription") {
				t.Errorf("the error should say the subscription is the problem, got %q", err)
			}
		})
	}
}

// A body that DOES carry connections but none that are new is the genuine "you are up to date"
// case, and must stay a success — otherwise every steady-state refresh would report a failure.
func TestSubrefresh_NothingNewIsStillSuccess(t *testing.T) {
	body := subrefresh_sub(subrefresh_link1, subrefresh_link2)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer ts.Close()
	s := subrefresh_server(t, ts.URL)

	if _, err := s.refreshSubscriptionOnce(context.Background()); err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	added, err := s.refreshSubscriptionOnce(context.Background())
	if err != nil {
		t.Fatalf("a refresh that finds nothing new is not a failure: %v", err)
	}
	if added != 0 {
		t.Errorf("the same body twice should add nothing the second time, got %d", added)
	}
}
