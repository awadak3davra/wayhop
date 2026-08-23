package server

import (
	"wayhop/internal/model"
	"wayhop/internal/pbr"
)

// updaterbind.go points component downloads at an interface the operator chose.
//
// The question it answers is the one that makes the section usable at all where it matters most: if
// the router's ordinary path to a release is blocked, nothing can be installed — including the engine
// that would have carried the traffic around the block. Nobody can download their way out of that by
// trying harder, so the download has to be able to leave through a tunnel that still works.
//
// Deliberately NOT a routing change: no mark, no table, no rule. The socket is bound to the chosen
// interface for the duration of the fetch, so the release metadata and the asset bytes take that path
// and nothing else on the router notices.

// updaterDownloadIface resolves the saved outbound tag to a kernel interface. The updater calls it
// once per connection (see Updater.BindVia), so it always answers for the profile and health that
// hold right now rather than for whatever was true when the choice was saved.
//
// An unset tag, "direct", or a tag this router cannot route through resolves to "" — the ordinary
// path. Falling back rather than refusing is deliberate: a saved choice that no longer matches the
// profile (the tunnel was deleted, renamed, disabled) must not make the section unable to fetch
// anything at all. The page states which path it will use, so a fallback is visible rather than
// silent.
func (s *Server) updaterDownloadIface() string {
	if s == nil || s.cfg == nil || s.store == nil {
		return ""
	}
	tag := s.config().Updater.DownloadVia
	if tag == "" || tag == model.OutboundDirect {
		return ""
	}
	// One read of the profile answers both halves below. Two reads could straddle a publication and
	// resolve the group from one generation and its members from the next.
	profile := s.store.Profile()
	if e := profile.EndpointByID(tag); e != nil {
		if !e.Enabled {
			return ""
		}
		return pbr.KernelIface(e)
	}
	// A group takes the member the rest of the kernel plane routes through: the operator's order,
	// first HEALTHY member that has an interface to bind to — the same election, over the same map,
	// that repoints a routing list's table. Binding to a dead member would be the exact failure this
	// setting exists to avoid, and a group whose members are all down resolves to the ordinary path
	// rather than to a link that cannot carry anything.
	if g := profile.GroupByID(tag); g != nil {
		if iface, ok := s.electHealthyMember(*g, kernelIfaceByEndpoint(&profile)); ok {
			return iface
		}
	}
	return ""
}
