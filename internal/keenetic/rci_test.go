package keenetic

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeKeenetic mimics the KeeneticOS x-ndw2-interactive auth + RCI, exactly as probed on the
// live reference router: GET /auth → 401 + X-NDM-Realm/Challenge + session cookie; POST /auth with
// SHA256(challenge + MD5(user:realm:pass)) → 200; /rci/* requires the authed session cookie.
func fakeKeenetic(t *testing.T, user, pass string) (*httptest.Server, *[]string) {
	t.Helper()
	const realm, challenge = "Keenetic Test", "CHALLENGE123"
	authed := map[string]bool{}
	var recorded []string // every /rci/parse command, in order
	mux := http.NewServeMux()
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		ck, _ := r.Cookie("sess")
		if ck == nil {
			http.SetCookie(w, &http.Cookie{Name: "sess", Value: "S1", Path: "/"})
		}
		switch r.Method {
		case http.MethodGet:
			if ck != nil && authed[ck.Value] {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.Header().Set("X-NDM-Realm", realm)
			w.Header().Set("X-NDM-Challenge", challenge)
			w.WriteHeader(http.StatusUnauthorized)
		case http.MethodPost:
			var body struct{ Login, Password string }
			_ = json.NewDecoder(r.Body).Decode(&body)
			md := md5.Sum([]byte(user + ":" + realm + ":" + pass))
			want := sha256.Sum256([]byte(challenge + hex.EncodeToString(md[:])))
			if body.Login == user && body.Password == hex.EncodeToString(want[:]) && ck != nil {
				authed[ck.Value] = true
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		}
	})
	authedGuard := func(r *http.Request) bool {
		ck, _ := r.Cookie("sess")
		return ck != nil && authed[ck.Value]
	}
	mux.HandleFunc("/rci/show/", func(w http.ResponseWriter, r *http.Request) {
		if !authedGuard(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"path":"`+strings.TrimPrefix(r.URL.Path, "/rci/show/")+`"}`)
	})
	mux.HandleFunc("/rci/parse", func(w http.ResponseWriter, r *http.Request) {
		if !authedGuard(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		// Batch form: [{"parse":"…"}, …] → record all, return an array of results. A command
		// containing "FAILCMD" returns the real NDM error shape so ParseBatch's error path is
		// exercised end-to-end.
		var arr []struct{ Parse string }
		if err := json.Unmarshal(raw, &arr); err == nil && len(arr) > 0 {
			for _, it := range arr {
				recorded = append(recorded, it.Parse)
			}
			for _, it := range arr {
				if strings.Contains(it.Parse, "FAILCMD") {
					io.WriteString(w, `[{"status":[{"status":"error","message":"mock rejected FAILCMD"}]}]`)
					return
				}
			}
			io.WriteString(w, "[]")
			return
		}
		// Single form: {"parse":"…"} → record + echo (for the show-version test).
		var body struct{ Parse string }
		_ = json.Unmarshal(raw, &body)
		recorded = append(recorded, body.Parse)
		if strings.Contains(body.Parse, "FAILCMD") {
			io.WriteString(w, `{"status":[{"status":"error","message":"mock rejected FAILCMD"}]}`)
			return
		}
		io.WriteString(w, `{"parse":"`+body.Parse+`"}`)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts, &recorded
}

func TestRCIClient_AuthShowParse(t *testing.T) {
	ts, _ := fakeKeenetic(t, "admin", "secret")
	c, err := NewRCIClient(ts.URL, "admin", "secret")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Show auto-authenticates on the first 401, then succeeds.
	b, err := c.Show(ctx, "ip/route")
	if err != nil {
		t.Fatalf("Show: %v", err)
	}
	if !strings.Contains(string(b), `"path":"ip/route"`) {
		t.Errorf("Show body = %s", b)
	}

	// Parse executes an NDM command (session reused — no re-auth).
	b, err = c.Parse(ctx, "show version")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !strings.Contains(string(b), `"parse":"show version"`) {
		t.Errorf("Parse body = %s", b)
	}
}

func TestRCIClient_BadPassword(t *testing.T) {
	ts, _ := fakeKeenetic(t, "admin", "secret")
	c, _ := NewRCIClient(ts.URL, "admin", "wrong")
	if err := c.Auth(context.Background()); err == nil {
		t.Error("Auth with wrong password should fail")
	}
	if _, err := c.Show(context.Background(), "version"); err == nil {
		t.Error("Show with wrong password should fail")
	}
}
