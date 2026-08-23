package clash

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newClient(t *testing.T, ts *httptest.Server) *Client {
	t.Helper()
	c, err := New(strings.TrimPrefix(ts.URL, "http://"), "")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestProxiesParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/proxies" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"proxies":{"main":{"name":"main","type":"URLTest","now":"proxy-a","all":["proxy-a","proxy-b"],"history":[{"time":"t","delay":42}]},"direct":{"name":"direct","type":"Direct"}}}`))
	}))
	defer ts.Close()

	px, err := newClient(t, ts).Proxies(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	m := px["main"]
	if m.Type != "URLTest" || m.Now != "proxy-a" || len(m.All) != 2 || len(m.History) != 1 || m.History[0].Delay != 42 {
		t.Fatalf("bad parse: %+v", m)
	}
}

func TestDelayAlive(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/proxies/") || !strings.HasSuffix(r.URL.Path, "/delay") {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("url") == "" || r.URL.Query().Get("timeout") == "" {
			http.Error(w, "missing query", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"delay":123}`))
	}))
	defer ts.Close()

	d, err := newClient(t, ts).Delay(context.Background(), "proxy-a", "http://x/generate_204", 5000)
	if err != nil {
		t.Fatal(err)
	}
	if d != 123 {
		t.Fatalf("delay=%d, want 123", d)
	}
}

func TestDelayProxyDown(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusRequestTimeout)
		_, _ = w.Write([]byte(`{"message":"An error occurred in the delay test"}`))
	}))
	defer ts.Close()

	_, err := newClient(t, ts).Delay(context.Background(), "proxy-b", "http://x", 2000)
	if !errors.Is(err, ErrProxyDown) {
		t.Fatalf("want ErrProxyDown, got %v", err)
	}
}

func TestDelayUnreachable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	addr := strings.TrimPrefix(ts.URL, "http://")
	ts.Close() // server is now down -> Clash API unreachable

	c, _ := New(addr, "")
	_, err := c.Delay(context.Background(), "x", "http://y", 1000)
	if err == nil {
		t.Fatal("expected an error")
	}
	if errors.Is(err, ErrProxyDown) {
		t.Fatal("unreachable must NOT be classified as ErrProxyDown")
	}
}
