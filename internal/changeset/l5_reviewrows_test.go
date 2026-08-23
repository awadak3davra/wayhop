package changeset

import (
	"strings"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/model"
)

// TestNewlyReviewableFieldsReadTruthfully (L5): the thirteen fields that moved the revision without
// producing a review row now produce one, and the row says something an operator can act on.
//
// The property test in internal/server proves only that a row EXISTS. That is the safety net, not
// the goal: a row reading "Field changed: true -> false" satisfies the property and still tells the
// operator nothing. These are the ones with real consequences, so their text is pinned here.
func TestNewlyReviewableFieldsReadTruthfully(t *testing.T) {
	cfg := config.Config{}
	rowFor := func(base, desired model.Profile, field string) Change {
		t.Helper()
		for _, c := range Diff("base-rev", "desired-rev", base, desired, cfg, cfg).Changes {
			if c.Field == field {
				return c
			}
		}
		t.Fatalf("no review row for %q", field)
		return Change{}
	}

	// Kill switch: the difference between "traffic stops" and "traffic silently leaves through the
	// provider" when every member is down. Worth a sentence, not a bare boolean.
	base := model.Profile{Groups: []model.Group{{ID: "g", Name: "RU", Type: "fallback", Members: []string{"e"}}}}
	on := model.Profile{Groups: []model.Group{{ID: "g", Name: "RU", Type: "fallback", Members: []string{"e"}, KillSwitch: true}}}
	if c := rowFor(base, on, "Kill switch"); c.Before != "Off" || c.After != "On" ||
		!strings.Contains(c.Impact, "leaking to the provider") {
		t.Errorf("kill switch row must name the consequence: %+v", c)
	}

	// DNS cache is stored as DisableCache, and reporting the raw flag makes the operator decode a
	// double negative. Turning caching OFF must read as the cache going Off, not as a flag going On.
	dnsBase := model.Profile{DNS: &model.DNSSettings{Enabled: true}}
	dnsOff := model.Profile{DNS: &model.DNSSettings{Enabled: true, DisableCache: true}}
	if c := rowFor(dnsBase, dnsOff, "DNS cache"); c.Before != "On" || c.After != "Off" {
		t.Errorf("the cache row must resolve the double negative, got %q -> %q", c.Before, c.After)
	}

	// Intercept rewrites where every LAN query goes, so it must be flagged as interrupting.
	if c := rowFor(dnsBase, model.Profile{DNS: &model.DNSSettings{Enabled: true, Intercept: true}},
		"Intercept DNS"); !c.MayInterrupt {
		t.Errorf("intercepting DNS must be marked as possibly interrupting: %+v", c)
	}

	// A probe is what decides failover. Nil means the built-in default and must not render empty:
	// "" -> "" is the shape that made these invisible in the first place.
	epBase := model.Profile{Endpoints: []model.Endpoint{{ID: "e", Name: "NL", Server: "198.51.100.4", Port: 443}}}
	epProbe := model.Profile{Endpoints: []model.Endpoint{{ID: "e", Name: "NL", Server: "198.51.100.4", Port: 443,
		Health: &model.Health{URL: "https://probe.example/204", Interval: 30, Tolerance: 250}}}}
	c := rowFor(epBase, epProbe, "Health test")
	if c.Before != "default" {
		t.Errorf("an unset probe must read as the default, got %q", c.Before)
	}
	if !strings.Contains(c.After, "probe.example") || !strings.Contains(c.After, "every 30s") ||
		!strings.Contains(c.After, "250ms") {
		t.Errorf("the probe row must name what is fetched, how often and the tolerance, got %q", c.After)
	}

	// Keepalive is the field that keeps a WireGuard peer reachable behind NAT; a silent change here
	// looks like a tunnel that dies on its own.
	kaBase := model.Profile{Endpoints: []model.Endpoint{{ID: "w", Name: "AWG", Server: "198.51.100.9", Port: 51820}}}
	kaSet := model.Profile{Endpoints: []model.Endpoint{{ID: "w", Name: "AWG", Server: "198.51.100.9", Port: 51820,
		PersistentKeepalive: 25}}}
	if c := rowFor(kaBase, kaSet, "Keepalive"); c.After != "25" {
		t.Errorf("keepalive must show the interval, got %q -> %q", c.Before, c.After)
	}
}
