package core

import (
	"regexp"
	"sort"
	"strings"
)

// StartFailure is a classified reason a sing-box start/reload aborted, with a remedy the UI can show.
// sing-box exits non-zero AFTER a successful fork for a handful of recurring, very fixable reasons —
// but the raw FATAL line is a wall of nested errors. Classifying it turns "the core keeps dying" into
// an actionable message. Zero value (Kind=="") means "not a recognized failure".
type StartFailure struct {
	Kind    string   `json:"kind"`               // stable slug, e.g. "rule-set"
	Detail  string   `json:"detail"`             // human summary
	Items   []string `json:"items,omitempty"`    // the specific offenders (e.g. failing rule-set tags)
	Remedy  string   `json:"remedy,omitempty"`   // what the user can do about it
	RawLine string   `json:"raw_line,omitempty"` // the log line it was classified from
}

var (
	// "initialize rule-set[3]: initial rule-set: rs-ai_openai: invalid sing-box rule-set file"
	reRuleSetTag = regexp.MustCompile(`initial rule-set:\s*([A-Za-z0-9_.\-]+):`)
	// A listen/bind collision: another process already holds the port or TUN device.
	reAddrInUse = regexp.MustCompile(`(?i)address already in use|bind: address|listen .*: .*in use`)
	reTUNBusy   = regexp.MustCompile(`(?i)(create tun|tun device|device or resource busy|operation not permitted).*`)
)

// ClassifyStartFailure inspects the tail of a core log and reports WHY the process aborted.
// Pure (no I/O) so it is unit-tested against captured device output. Returns a zero StartFailure when
// nothing recognizable is present — callers should then fall back to showing the raw tail.
func ClassifyStartFailure(lines []string) StartFailure {
	for i := len(lines) - 1; i >= 0; i-- { // newest first: the fatal line is at the end
		ln := lines[i]
		if !strings.Contains(ln, "FATAL") && !strings.Contains(strings.ToLower(ln), "fatal") {
			continue
		}
		switch {
		case strings.Contains(ln, "rule-set"):
			// Collect every failing rule-set tag; sing-box concatenates them with " | ".
			seen := map[string]bool{}
			var items []string
			for _, m := range reRuleSetTag.FindAllStringSubmatch(ln, -1) {
				if tag := m[1]; !seen[tag] {
					seen[tag] = true
					items = append(items, tag)
				}
			}
			sort.Strings(items)
			f := StartFailure{
				Kind:    "rule-set",
				Detail:  "the core aborted while initializing routing rule-sets — a cached rule-set is corrupt or could not be downloaded",
				Items:   items,
				Remedy:  "clear the sing-box cache file (cache_file) to force a clean re-download of these rule-sets, and verify the router can reach their source URLs",
				RawLine: ln,
			}
			// `sing-box check` does NOT validate remote rule-sets (they load only at runtime), which is
			// why a config that validated cleanly still dies here — worth saying out loud.
			if strings.Contains(ln, "invalid sing-box rule-set file") {
				f.Detail += " (a cached rule-set file is invalid; note that `sing-box check` cannot catch this — remote rule-sets load only at runtime)"
			}
			return f
		case reAddrInUse.MatchString(ln):
			return StartFailure{
				Kind:    "port-in-use",
				Detail:  "the core could not bind a listen address — another process (possibly a second sing-box) already holds it",
				Remedy:  "stop the conflicting listener or change the inbound port",
				RawLine: ln,
			}
		case reTUNBusy.MatchString(ln):
			return StartFailure{
				Kind:    "tun",
				Detail:  "the core could not create/attach its TUN device — the name may already be taken by another core, or permissions are insufficient",
				Remedy:  "ensure no other sing-box owns the same interface_name, and that the daemon runs with the required privileges",
				RawLine: ln,
			}
		}
	}
	return StartFailure{}
}

// Summary renders the failure as one actionable line (empty when unclassified).
func (f StartFailure) Summary() string {
	if f.Kind == "" {
		return ""
	}
	s := f.Detail
	if len(f.Items) > 0 {
		s += ": " + strings.Join(f.Items, ", ")
	}
	if f.Remedy != "" {
		s += " — " + f.Remedy
	}
	return s
}
