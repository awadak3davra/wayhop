package updater

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"wayhop/internal/localtz"
)

// QA-131. When GitHub's allowance lifts is written in the router's zone and names it. Go's time.Local
// is UTC on Keenetic and OpenWrt, so a reset at 23:05 router time in UTC+3 read "until 20:05", with
// no zone to tell. The zone here is five hours off this host's own, so a time formatted in
// time.Local cannot pass.
func TestExhaustedAllowanceNamesTheRoutersTime(t *testing.T) {
	_, off := time.Now().Zone()
	router := time.FixedZone("", off+5*3600)
	reset := time.Now().Add(37 * time.Minute).In(router)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", fmt.Sprint(reset.Unix()))
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	u := New(t.TempDir(), "arm64", nil)
	u.zone = func() *time.Location { return router }
	directAt(t, u, srv)

	var rel Release
	err := u.apiGetDirect(context.Background(), "/p", &rel)
	if err == nil {
		t.Fatal("no error")
	}
	if want := "until " + reset.Format("15:04") + " (" + localtz.Label(reset) + ")"; !strings.Contains(err.Error(), want) {
		t.Errorf("message %q, want it to say %q", err.Error(), want)
	}
}
