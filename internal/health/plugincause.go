package health

import (
	"sync"

	"wayhop/internal/model"
)

// PluginState is what the plugin manager knows about the process behind one exit.
type PluginState struct {
	Running     bool
	NeedsBinary bool
	Reason      string // why it is not running, when it is not
}

// pluginStates resolves an exit to its plugin's state; set by the daemon (SetPluginStateResolver).
type pluginStates struct {
	mu      sync.RWMutex
	resolve func(id string) (PluginState, bool)
}

// SetPluginStateResolver tells the monitor where to read a plugin-run exit's process state, so a down
// ByeDPI exit is explained by its process instead of by a network it does not have (QA-041).
func (m *Monitor) SetPluginStateResolver(resolve func(id string) (PluginState, bool)) {
	if m == nil {
		return
	}
	m.plugins.mu.Lock()
	m.plugins.resolve = resolve
	m.plugins.mu.Unlock()
}

func (m *Monitor) pluginState(id string) (PluginState, bool) {
	m.plugins.mu.RLock()
	r := m.plugins.resolve
	m.plugins.mu.RUnlock()
	if r == nil {
		return PluginState{}, false
	}
	return r(id)
}

// Causes for an exit a local process carries (ByeDPI's ciadpi).
const (
	causePluginMissing    = "plugin-missing"
	causePluginNotRunning = "plugin-not-running"
	causePluginNoAnswer   = "plugin-no-answer"
)

// localProxyCause explains a down exit that a process on the router carries. The generic cause asks
// the operator to trace the route to "the server" and change transports; a ByeDPI exit has neither,
// and its process state already says what is wrong. ok is false for every other engine, and for a
// ByeDPI exit whose state is not known (not started by this daemon yet), which then says so.
func localProxyCause(engine model.Engine, st PluginState, known, coreKnown, coreAvailable bool) (id, title, fix string, ok bool) {
	if engine != model.EngineByeDPI {
		return "", "", "", false
	}
	switch {
	case coreKnown && !coreAvailable:
		return causeEngineMissing, "The engine this exit needs is not installed",
			"Install sing-box on the Components page: it is what sends a routing list to ByeDPI.", true
	case !known:
		return causePluginNotRunning, "ByeDPI has not been started",
			"Apply to start it.", true
	case st.NeedsBinary:
		return causePluginMissing, "ByeDPI is not installed",
			"Install the ByeDPI component on the Components page.", true
	case !st.Running:
		title := "ByeDPI is not running"
		if st.Reason != "" {
			title += ": " + st.Reason
		}
		return causePluginNotRunning, title,
			"Check the connection's strategy, then Apply again; the reason above is what stopped it.", true
	default:
		return causePluginNoAnswer, "ByeDPI runs, but nothing answered through it",
			"This strategy may not get past the DPI on this network: try another preset on the connection.", true
	}
}
