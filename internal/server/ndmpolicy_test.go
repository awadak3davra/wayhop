package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/model"
	"wayhop/internal/platform"
)

// showIPPolicyFixture is the measured `show ip policy` shape (route listings elided).
const showIPPolicyFixture = "\x1b[K\n" +
	"           policy, name = Policy0, description = Bypass: \n" +
	"                 mark: ffffaaa\n" +
	"               table4: 4096\n" +
	"           policy, name = Policy1, description = VPN: \n" +
	"                 mark: ffffaab\n" +
	"               table4: 4098\n"

func TestReadKeeneticPoliciesRunsTheExactBoundedNDMC(t *testing.T) {
	var gotName string
	var gotArgs []string
	out, err := readKeeneticPoliciesWith(context.Background(),
		func(_ context.Context, timeout time.Duration, limit int, _ time.Duration, name string, args ...string) (string, error) {
			if timeout != keeneticPolicyTimeout || limit != keeneticPolicyLimit {
				t.Fatalf("bounds = %v/%d", timeout, limit)
			}
			gotName, gotArgs = name, args
			return showIPPolicyFixture, nil
		})
	if err != nil || out != showIPPolicyFixture {
		t.Fatalf("out=%q err=%v", out, err)
	}
	if gotName != exactKeeneticNDMCPath || !reflect.DeepEqual(gotArgs, []string{"-c", "show ip policy"}) {
		t.Fatalf("ran %s %q", gotName, gotArgs)
	}
	if _, err := readKeeneticPoliciesWith(context.Background(),
		func(context.Context, time.Duration, int, time.Duration, string, ...string) (string, error) {
			return "", errors.New("ndmc: no answer")
		}); !errors.Is(err, errExecutionCaptureUnavailable) {
		t.Fatalf("a failed read = %v", err)
	}
}

func ndmPolicyListProfile(enabled bool, outbound string) model.Profile {
	return model.Profile{RoutingLists: []model.RoutingList{{
		ID: "rl", Name: "Telegram", Enabled: enabled, Outbound: outbound, Manual: []string{"198.51.100.0/24"},
	}}}
}

func TestNDMPolicyFindings(t *testing.T) {
	present := map[string]uint32{"Policy1": 0x0ffffaab}
	for name, tc := range map[string]struct {
		profile model.Profile
		facts   ndmPolicyFacts
		want    string // finding ID, "" = none
	}{
		"present":       {ndmPolicyListProfile(true, "ndm-policy:Policy1"), ndmPolicyFacts{keenetic: true, marks: present}, ""},
		"deleted":       {ndmPolicyListProfile(true, "ndm-policy:Policy7"), ndmPolicyFacts{keenetic: true, marks: present}, "list.ndm_policy_missing"},
		"not keenetic":  {ndmPolicyListProfile(true, "ndm-policy:Policy1"), ndmPolicyFacts{}, "list.ndm_policy_unsupported"},
		"unreadable":    {ndmPolicyListProfile(true, "ndm-policy:Policy1"), ndmPolicyFacts{keenetic: true, readErr: errors.New("x")}, "list.ndm_policy_unread"},
		"disabled list": {ndmPolicyListProfile(false, "ndm-policy:Policy7"), ndmPolicyFacts{keenetic: true, marks: present}, ""},
		"no policy":     {ndmPolicyListProfile(true, "direct"), ndmPolicyFacts{}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			tc.facts.inUse = model.NDMPoliciesInUse(&tc.profile)
			got := ndmPolicyFindings(&tc.profile, tc.facts)
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("findings = %+v", got)
				}
				return
			}
			if len(got) != 1 || got[0].ID != tc.want || got[0].Blocks != platform.BlocksApply ||
				got[0].Item != "Telegram" || got[0].Detail == "" || got[0].Remedy == "" {
				t.Fatalf("findings = %+v", got)
			}
			if code, title, _, _ := findingTemplate(got[0]); !strings.HasPrefix(code, "NDM_POLICY_") || title == "" {
				t.Fatalf("template = %s %q", code, title)
			}
		})
	}
}

func TestReviewNDMPoliciesReadsOnlyWhenAListUsesOne(t *testing.T) {
	reads := 0
	s := &Server{cfg: &config.Config{}, platformOf: func() platform.Platform { return platform.Keenetic },
		keeneticPolicyReader: func(context.Context) (string, error) { reads++; return showIPPolicyFixture, nil }}

	none := ndmPolicyListProfile(true, "direct")
	if facts := s.reviewNDMPolicies(context.Background(), config.Config{}, &none); reads != 0 || facts.inUse != nil {
		t.Fatalf("a profile without policies read NDM %d time(s): %+v", reads, facts)
	}
	used := ndmPolicyListProfile(true, "ndm-policy:Policy1")
	facts := s.reviewNDMPolicies(context.Background(), config.Config{}, &used)
	if reads != 1 || !facts.keenetic || facts.readErr != nil || facts.marks["Policy1"] != 0x0ffffaab {
		t.Fatalf("reads=%d facts=%+v", reads, facts)
	}
	// The demo never runs a host command, and has policies to pick from.
	demo := s.reviewNDMPolicies(context.Background(), config.Config{Demo: true}, &used)
	if reads != 1 || !demo.keenetic || demo.marks["Policy1"] == 0 {
		t.Fatalf("demo: reads=%d facts=%+v", reads, demo)
	}
	s.platformOf = func() platform.Platform { return platform.OpenWrt }
	if off := s.reviewNDMPolicies(context.Background(), config.Config{}, &used); reads != 1 || off.keenetic {
		t.Fatalf("OpenWrt: reads=%d facts=%+v", reads, off)
	}
}

// The review's kernel compile is given the router's policies, so a list sent to one that exists is
// not reported as traffic the kernel will not carry; one that does not exist is.
func TestKernelPlaneFindingsKnowTheRoutersPolicies(t *testing.T) {
	s := &Server{cfg: &config.Config{}}
	cfg := &config.Config{RoutingMode: "fast"}
	prof := ndmPolicyListProfile(true, "ndm-policy:Policy1")
	if got := s.kernelPlaneFindings(cfg, &prof, map[string]uint32{"Policy1": 0x0ffffaab}); len(got) != 0 {
		t.Fatalf("a present policy was reported: %+v", got)
	}
	if got := s.kernelPlaneFindings(cfg, &prof, nil); len(got) != 1 || got[0].Item != "rl" {
		t.Fatalf("an unknown policy must be reported: %+v", got)
	}
}

func ndmPolicyCaptureTuple(t *testing.T, outbound string) (DesiredSnapshot, ExecutionHostFactsV1) {
	t.Helper()
	cfg := *config.Default()
	cfg.RoutingMode = "fast"
	desired, err := newDesiredSnapshot(cfg, ndmPolicyListProfile(true, outbound), 4)
	if err != nil {
		t.Fatal(err)
	}
	probe := hostTestProbe(desired)
	probe.Platform = string(platform.Keenetic)
	probe.RawCapabilities.Platform = string(platform.Keenetic)
	host, err := newHostSnapshot(desired, probe, nil)
	if err != nil {
		t.Fatal(err)
	}
	return desired, ExecutionHostFactsV1{Host: host, ExternalBindings: []ExecutionExternalBindingV1{}}
}

// The Apply capture reads the policies in the same host pass, only for a profile that uses one, and
// carries the marks into what the planes are compiled from.
func TestCaptureExecutionNativeCarriesThePolicyMarks(t *testing.T) {
	reads := 0
	s := &Server{cfg: &config.Config{},
		keeneticConfigReader: func(context.Context) (string, error) { return "interface Wireguard0\n!\n", nil },
		keeneticPolicyReader: func(context.Context) (string, error) { reads++; return showIPPolicyFixture, nil }}

	desired, host := ndmPolicyCaptureTuple(t, "direct")
	capture, err := s.captureExecutionNative(context.Background(), desired, host)
	if err != nil || reads != 0 || capture.NDMPolicies != nil {
		t.Fatalf("no policy in use: reads=%d policies=%v err=%v", reads, capture.NDMPolicies, err)
	}

	desired, host = ndmPolicyCaptureTuple(t, "ndm-policy:Policy1")
	capture, err = s.captureExecutionNative(context.Background(), desired, host)
	if err != nil || reads != 1 {
		t.Fatalf("reads=%d err=%v", reads, err)
	}
	want := map[string]uint32{"Policy0": 0x0ffffaaa, "Policy1": 0x0ffffaab}
	if !reflect.DeepEqual(capture.NDMPolicies, want) {
		t.Fatalf("captured policies = %#v", capture.NDMPolicies)
	}
	if got := applyNDMPolicies(desired.Config, &capture); !reflect.DeepEqual(got, want) ||
		len(missingNDMPolicies(&desired.Profile, got)) != 0 {
		t.Fatalf("apply marks = %#v", got)
	}
	if missing := missingNDMPolicies(&desired.Profile, nil); !reflect.DeepEqual(missing, []string{"Policy1"}) {
		t.Fatalf("missing = %q", missing)
	}

	s.keeneticPolicyReader = func(context.Context) (string, error) { return "", errExecutionCaptureUnavailable }
	if _, err := s.captureExecutionNative(context.Background(), desired, host); !errors.Is(err, errExecutionCaptureUnavailable) {
		t.Fatalf("an unreadable listing must fail the capture: %v", err)
	}
}

func TestHandleKeeneticPolicies(t *testing.T) {
	get := func(s *Server) (*httptest.ResponseRecorder, []ndmPolicyAnswer) {
		rec := httptest.NewRecorder()
		s.handleKeeneticPolicies(rec, httptest.NewRequest(http.MethodGet, "/api/keenetic/policies", nil))
		var out []ndmPolicyAnswer
		if rec.Code == http.StatusOK {
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
		}
		return rec, out
	}
	keenetic := func() platform.Platform { return platform.Keenetic }

	rec, out := get(&Server{cfg: &config.Config{}, platformOf: keenetic,
		keeneticPolicyReader: func(context.Context) (string, error) { return showIPPolicyFixture, nil }})
	want := []ndmPolicyAnswer{{"Policy0", "Bypass", 0x0ffffaaa}, {"Policy1", "VPN", 0x0ffffaab}}
	if rec.Code != http.StatusOK || !reflect.DeepEqual(out, want) {
		t.Fatalf("keenetic: %d %s", rec.Code, rec.Body)
	}
	if rec, _ := get(&Server{cfg: &config.Config{}, platformOf: func() platform.Platform { return platform.OpenWrt }}); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("off KeeneticOS: %d", rec.Code)
	}
	if rec, _ := get(&Server{cfg: &config.Config{}, platformOf: keenetic,
		keeneticPolicyReader: func(context.Context) (string, error) { return "", errExecutionCaptureUnavailable }}); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unreadable: %d", rec.Code)
	}
	// The demo runs no host command, and the reader would fail the test if it did.
	rec, out = get(&Server{cfg: &config.Config{Demo: true}, platformOf: func() platform.Platform { return platform.OpenWrt },
		keeneticPolicyReader: func(context.Context) (string, error) { t.Fatal("demo read NDM"); return "", nil }})
	if rec.Code != http.StatusOK || len(out) != len(demoNDMPolicies) {
		t.Fatalf("demo: %d %s", rec.Code, rec.Body)
	}
	// Answer for an empty router is a list, not null.
	rec, _ = get(&Server{cfg: &config.Config{}, platformOf: keenetic,
		keeneticPolicyReader: func(context.Context) (string, error) { return "", nil }})
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("empty router: %d %q", rec.Code, rec.Body)
	}
}

func seedNDMPolicyList(t *testing.T, s *Server) {
	t.Helper()
	if err := s.store.UpsertRoutingList(model.RoutingList{ID: "rl-policy", Name: "Telegram", Enabled: true,
		Outbound: "ndm-policy:Policy1", Manual: []string{"198.51.100.0/24"}}); err != nil {
		t.Fatalf("seed list: %v", err)
	}
}

// Off KeeneticOS the review refuses the Apply and names the list; in the demo, whose router has
// policies, the Apply goes through and the core's outbound for the list carries the policy's mark.
func TestRunApply_PolicyListEndToEnd(t *testing.T) {
	s, _ := applytest_server(t)
	apply_seedVLESS(t, s)
	seedNDMPolicyList(t, s)
	_, aerr := s.runApply(context.Background(), applyRequest{Save: true})
	if aerr == nil || aerr.Code != applyCodeBlocked {
		t.Fatalf("apply off KeeneticOS = %v", aerr)
	}
	refused := false
	for _, f := range aerr.Findings {
		refused = refused || (f.ID == "list.ndm_policy_unsupported" && reflect.DeepEqual(f.Items, []string{"Telegram"}))
	}
	if !refused {
		t.Fatalf("findings = %+v", aerr.Findings)
	}

	demo, _ := applytest_server(t)
	demo.cfg.Demo = true
	apply_seedVLESS(t, demo)
	seedNDMPolicyList(t, demo)
	if _, aerr := demo.runApply(context.Background(), applyRequest{}); aerr != nil {
		t.Fatalf("demo apply: %v", aerr.body())
	}
	live := demo.liveRevision()
	if live == nil {
		t.Fatal("no live revision")
	}
	var cfg struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(live.Materialization.Core.Config, &cfg); err != nil {
		t.Fatal(err)
	}
	marked := false
	for _, ob := range cfg.Outbounds {
		marked = marked || (ob["tag"] == "ndm-policy:Policy1" && ob["routing_mark"] == float64(0x0ffffaab))
	}
	if !marked {
		t.Fatalf("outbounds = %#v", cfg.Outbounds)
	}
}
