package model

import (
	"strings"
	"testing"
)

// The strategy is ciadpi's own flags, checked against the documented list: the daemon owns the
// listener, and nothing may point ciadpi at a file on the router.
func TestByeDPIStrategy(t *testing.T) {
	for _, ok := range []string{
		"",
		DefaultByeDPIStrategy,
		"--fake -1 --ttl 8",
		"-d1 -s1+s -r1+s",
		"--fake -1 --ttl 10 --auto=ssl_err --fake -1 --ttl 5",
		"--proto=http,tls --disorder 3 --auto=none",
		"--hosts=:example.com --disorder 3 --auto=none",
		"--fake-data=:GET --md5sig --drop-sack",
	} {
		if _, err := ByeDPIStrategy(map[string]any{"strategy": ok}); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for bad, want := range map[string]string{
		"--port 1080":              "not allowed",
		"-p1080":                   "not allowed",
		"--ip 0.0.0.0":             "not allowed",
		"-D":                       "not allowed",
		"--daemon":                 "not allowed",
		"--transparent":            "not allowed",
		"--cache-dump /tmp/x":      "not allowed",
		"--hosts list.txt":         "inline data only",
		"-H/etc/passwd":            "inline data only",
		"--fake-data=/tmp/payload": "inline data only",
		"--disorder":               "needs a value",
		"--md5sig=1":               "takes no value",
		"--frobnicate 3":           "not a ciadpi flag",
		"disorder 1":               "not a ciadpi flag",
		"--split 1 ; reboot":       "not a ciadpi flag",
		"--fake-sni=exämple.com":   "character",
	} {
		_, err := ByeDPIStrategy(map[string]any{"strategy": bad})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want it to say %q", bad, err, want)
		}
	}
	got, _ := ByeDPIStrategy(nil)
	if strings.Join(got, " ") != DefaultByeDPIStrategy {
		t.Errorf("an empty strategy must be the default, got %q", got)
	}
}

// A ByeDPI connection needs no server, port or protocol; its strategy is what validation checks.
func TestValidateByeDPIEndpoint(t *testing.T) {
	p := Profile{Endpoints: []Endpoint{{ID: "bye", Name: "ByeDPI", Engine: EngineByeDPI, Enabled: true}}}
	if err := p.Validate(); err != nil {
		t.Fatalf("a ByeDPI connection with the default strategy: %v", err)
	}
	p.Endpoints[0].Params = map[string]any{"strategy": "--port 1080"}
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "byedpi") {
		t.Errorf("a strategy taking over the listener must fail validation: %v", err)
	}
}

// The save paths (upsert, bulk import, subscription refresh) ask EndpointParamProblem, not Validate;
// a bad strategy must be refused there too, or it is stored enabled and fails the next Apply.
func TestByeDPIParamProblem(t *testing.T) {
	e := Endpoint{ID: "bye", Engine: EngineByeDPI, Protocol: ProtoSOCKS, Enabled: true, Params: map[string]any{"strategy": "--port 1080"}}
	if p := EndpointParamProblem(&e); !strings.Contains(p, "not allowed") {
		t.Errorf("problem = %q", p)
	}
	e.Params["strategy"] = "--fake -1 --ttl 8"
	if p := EndpointParamProblem(&e); p != "" {
		t.Errorf("a good strategy reported %q", p)
	}
}
