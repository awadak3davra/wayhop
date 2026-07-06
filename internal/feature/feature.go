// Package feature is the WayHop plugin system: a compiled-in registry of optional feature MODULES
// (the "Plugins" section in the UI). A module is pulled in by a blank import in cmd/wayhop
// (`_ "wayhop/internal/feature/iptv"`) — the standard Go driver idiom (image/jpeg, database/sql) —
// and "installing" it is nothing more than flipping config.Features[id].Enabled: no dynamic loading,
// no .so, no restart. The server mounts every registered module's routes UNCONDITIONALLY and each
// handler gates on the enabled flag, so a toggle is a pure config flip.
package feature

import (
	"context"
	"net/http"

	"wayhop/internal/config"
	"wayhop/internal/featurestore"
)

// Descriptor is a module's identity for the Plugins UI + the left-menu nav item.
type Descriptor struct {
	ID   string // stable key used in config.Features + the module's routes (/api/<id>/…)
	Name string // display name in the Plugins list + nav
	Icon string // nav icon (emoji or a small inline marker)
	Tip  string // one-line tooltip / description
}

// Deps are the shared services a module receives, so modules never reach into the server directly.
// Cfg/Fetch/QR are funcs so a module always sees LIVE values and inherits the server's SSRF-guarded
// fetch client. The struct grows additively as slices land (the featurestore Store is added next).
type Deps struct {
	Cfg       func() config.Config                        // live daemon config (read Features[id].Settings)
	Fetch     func() *http.Client                         // SSRF-guarded HTTP client for outbound fetches
	QR        func(text string, size int) ([]byte, error) // render a QR PNG (share/install URLs)
	Store     *featurestore.Store                         // atomic per-module state (opaque blob keyed by module id)
	DataDir   string                                      // runtime dir for module files (e.g. generated .m3u)
	Endpoints func() []EndpointMeta                       // read-only view of the user's enabled proxy exits (nil-safe)
}

// EndpointMeta is a read-only snapshot of one proxy endpoint, exposed to modules that want to relate
// a feature to the user's exits (e.g. IPTV matching a playlist's country to an exit country) without
// coupling to the full model.Endpoint / store.
type EndpointMeta struct {
	ID     string
	Name   string
	Server string
}

// Module is one optional feature. Register it from an init() so a blank import installs it.
type Module interface {
	Descriptor() Descriptor
	Routes(mux *http.ServeMux, d *Deps) // mounted UNCONDITIONALLY; the handler gates on Enabled(cfg)
	Start(ctx context.Context, d *Deps) // background loop; must no-op while disabled (re-check per tick)
	Stop()
}

// registry is the compiled-in module set, appended to from module init()s.
var registry []Module

// Register adds a module to the compiled-in registry. Call it from a module package's init().
func Register(m Module) { registry = append(registry, m) }

// All returns every registered (compiled-in) module, in registration order.
func All() []Module { return registry }

// Enabled returns the registered modules the user has installed (config.Features[id].Enabled).
func Enabled(cfg config.Config) []Module {
	var out []Module
	for _, m := range registry {
		if fc, ok := cfg.Features[m.Descriptor().ID]; ok && fc.Enabled {
			out = append(out, m)
		}
	}
	return out
}
