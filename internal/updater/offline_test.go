package updater

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// TestOfflineReleaseLookupsMakeNoRequest: in demo the panel must answer version questions without
// reaching GitHub.
//
// The verification suite drives the demo, and twice in three full runs on 2026-08-19 it failed on
// `502 /api/updater/sing-box/fit` — once on diagnostics, once on Components — because api.github.com
// did not answer in time. Nothing in the panel was wrong. The transport below fails every request,
// so a lookup that still tries the network cannot pass this test by being lucky.
func TestOfflineReleaseLookupsMakeNoRequest(t *testing.T) {
	u := New(t.TempDir(), "arm64", nil)
	u.Offline = true
	u.hc = &http.Client{Transport: refuseTransport{t}, Timeout: time.Second}
	e := Engine{ID: "sing-box", Repo: "SagerNet/sing-box"}
	ctx := context.Background()

	rels, err := u.List(ctx, e, 15)
	if err != nil || len(rels) == 0 {
		t.Fatalf("List offline: %v (%d releases)", err, len(rels))
	}
	if tag := LatestStable(rels); tag == "" {
		t.Error("the catalogue must contain a stable release, or every engine reads as having none")
	}
	latest, err := u.Latest(ctx, e)
	if err != nil || latest.Tag == "" {
		t.Fatalf("Latest offline: %v (%q)", err, latest.Tag)
	}

	// Fit is the call the failing runs made: it must produce the same arithmetic offline, against an
	// asset picked for the arch by the ordinary code path.
	fit, err := u.Fit(ctx, e, rels[0].Tag)
	if err != nil {
		t.Fatalf("Fit offline: %v", err)
	}
	if fit.Asset == "" || fit.Download <= 0 || fit.Need <= uint64(fit.Download) {
		t.Errorf("Fit must pick an arch asset and compute peak disk above the download: %+v", fit)
	}
	if want := "arm64"; !contains(fit.Asset, want) {
		t.Errorf("asset %q was not selected for arch %q", fit.Asset, want)
	}

	// An unknown tag stays a miss: the demo must not invent a version that does not exist.
	if _, err := u.Fit(ctx, e, "v0.0.1-nope"); err == nil {
		t.Error("an unknown tag must fail rather than synthesize a release")
	}
}

// TestOfflineIsOptIn: the real daemon must keep using the network. A default-on offline mode would
// silently stop routers from ever seeing a new release.
func TestOfflineIsOptIn(t *testing.T) {
	if New(t.TempDir(), "arm64", nil).Offline {
		t.Error("Offline must default to false")
	}
}

type refuseTransport struct{ t *testing.T }

func (r refuseTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.t.Errorf("offline lookup reached the network: %s", req.URL.String())
	return nil, errRefused
}

var errRefused = &refusedErr{}

type refusedErr struct{}

func (*refusedErr) Error() string { return "network refused by test" }

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestOfflineNeverInventsASelfUpdate: the demo may stand in for the world, but not for a newer
// version of itself.
//
// The first cut handed the engine version line to every repository, so a demo daemon at 0.5.6 was
// told a WayHop v1.13.19 existed — offered by the control that replaces the running binary, and
// rendered as an "update → v1.13.19" badge that the contrast gate then caught at 3.22:1.
func TestOfflineNeverInventsASelfUpdate(t *testing.T) {
	u := New(t.TempDir(), "arm64", nil)
	u.Offline = true
	u.hc = &http.Client{Transport: refuseTransport{t}, Timeout: time.Second}
	self := Engine{ID: "wayhop", Repo: DefaultSelfRepo}
	ctx := context.Background()

	rels, err := u.List(ctx, self, 15)
	if err != nil || len(rels) != 0 {
		t.Errorf("the self repo must list no releases offline: %d, %v", len(rels), err)
	}
	if r, err := u.Latest(ctx, self); err == nil {
		t.Errorf("Latest must not name a self release, got %q", r.Tag)
	}
	if _, err := u.Fit(ctx, self, offlineTags[0]); err == nil {
		t.Error("Fit must not measure an install of a self release that does not exist")
	}
	// Engines are unaffected: this is a rule about one repository, not a second offline switch.
	if rs, err := u.List(ctx, Engine{ID: "sing-box", Repo: "SagerNet/sing-box"}, 15); err != nil || len(rs) == 0 {
		t.Errorf("engine lookups must still answer: %d, %v", len(rs), err)
	}
}
