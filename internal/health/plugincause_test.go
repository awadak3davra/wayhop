package health

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

// A down ByeDPI exit is explained by its process, never by the tunnel advice that sends the operator
// to trace a server it does not have (QA-041); every other engine is left to the existing causes.
func TestLocalProxyCause(t *testing.T) {
	for _, tc := range []struct {
		name                string
		st                  PluginState
		known, core, coreOK bool
		id, says            string
	}{
		{"core missing", PluginState{}, true, true, false, causeEngineMissing, "not installed"},
		{"never started", PluginState{}, false, true, true, causePluginNotRunning, "has not been started"},
		{"binary missing", PluginState{NeedsBinary: true}, true, true, true, causePluginMissing, "ByeDPI is not installed"},
		{"crashed with a reason", PluginState{Reason: "start ciadpi: permission denied"}, true, true, true, causePluginNotRunning, "permission denied"},
		{"running, no answer", PluginState{Running: true}, true, true, true, causePluginNoAnswer, "nothing answered"},
	} {
		id, title, fix, ok := localProxyCause(model.EngineByeDPI, tc.st, tc.known, tc.core, tc.coreOK)
		if !ok || id != tc.id || !strings.Contains(title, tc.says) {
			t.Errorf("%s: %q %q (ok %v), want id %s saying %q", tc.name, id, title, ok, tc.id, tc.says)
		}
		if strings.Contains(fix, "Reality") || strings.Contains(fix, "traceroute") {
			t.Errorf("%s: tunnel advice for a local proxy: %q", tc.name, fix)
		}
	}
	if _, _, _, ok := localProxyCause(model.EngineSingBox, PluginState{}, true, true, true); ok {
		t.Error("a sing-box exit keeps the existing causes")
	}
}
