package server

import (
	"errors"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/netvpn"
)

func extEndpoint(id, iface, key string, enabled bool) model.Endpoint {
	return model.Endpoint{
		ID: id, Name: id, Engine: model.EngineExternal, Enabled: enabled,
		Params: map[string]any{"interface": iface, "public_key": key},
	}
}

// Spec §9: "externally removed tunnel becomes unavailable without deleting unrelated rules."
// The router can delete a native tunnel at any time; WayHop must notice rather than keep rendering
// a healthy-looking egress that carries nothing.
func TestMissingAdoptedTunnels_RemovedTunnelIsReported(t *testing.T) {
	eps := []model.Endpoint{extEndpoint("external-awg0", "awg0", "KEY-A", true)}

	got := missingAdoptedTunnels(eps, netvpn.Discovery{}, nil) // discovery succeeded and found nothing
	if len(got) != 1 {
		t.Fatalf("a removed tunnel must be reported, got %+v", got)
	}
	if got[0].EndpointID != "external-awg0" || !got[0].Enabled {
		t.Errorf("unexpected finding: %+v", got[0])
	}
	if got[0].Reason == "" {
		t.Error("the user needs to be told what happened, not just that something is wrong")
	}
}

// A tunnel that is still there must never be reported — a false alarm here would send someone
// looking for a fault that does not exist.
func TestMissingAdoptedTunnels_PresentTunnelIsSilent(t *testing.T) {
	eps := []model.Endpoint{extEndpoint("external-awg0", "awg0", "KEY-A", true)}
	live := []netvpn.DiscoveredVPN{{Iface: "awg0", PublicKey: "KEY-A"}}

	if got := missingAdoptedTunnels(eps, netvpn.Discovery{VPNs: live}, nil); len(got) != 0 {
		t.Errorf("a present tunnel must not be reported: %+v", got)
	}
}

// A RENAMED tunnel is still present. Matching on the key must prevent a false "missing" report,
// which would otherwise fire every time someone renamed an interface.
func TestMissingAdoptedTunnels_RenamedTunnelIsNotMissing(t *testing.T) {
	eps := []model.Endpoint{extEndpoint("external-awg0", "awg0", "KEY-A", true)}
	live := []netvpn.DiscoveredVPN{{Iface: "awg1", PublicKey: "KEY-A"}} // renamed, same key

	if got := missingAdoptedTunnels(eps, netvpn.Discovery{VPNs: live}, nil); len(got) != 0 {
		t.Errorf("a renamed tunnel is still present and must not be reported missing: %+v", got)
	}
}

// The reverse: a tunnel whose key was never captured is still matched by interface name.
func TestMissingAdoptedTunnels_MatchesByIfaceWhenNoKey(t *testing.T) {
	eps := []model.Endpoint{extEndpoint("external-tun0", "tun0", "", true)}
	live := []netvpn.DiscoveredVPN{{Iface: "tun0"}}

	if got := missingAdoptedTunnels(eps, netvpn.Discovery{VPNs: live}, nil); len(got) != 0 {
		t.Errorf("matched by interface name; must not be reported: %+v", got)
	}
}

// A FAILED discovery means "unknown", not "everything is gone". Reporting every adopted tunnel as
// missing because one probe failed would be worse than saying nothing.
func TestMissingAdoptedTunnels_FailedDiscoveryReportsNothing(t *testing.T) {
	eps := []model.Endpoint{extEndpoint("external-awg0", "awg0", "KEY-A", true)}

	if got := missingAdoptedTunnels(eps, netvpn.Discovery{Err: errors.New("ndmc show interface: exit status 1")}, nil); len(got) != 0 {
		t.Errorf("a failed discovery must not be reported as mass tunnel removal: %+v", got)
	}
}

// Only external endpoints are checked — a WayHop-created endpoint has no native interface to lose.
func TestMissingAdoptedTunnels_IgnoresNonExternal(t *testing.T) {
	eps := []model.Endpoint{{
		ID: "wayhop-made", Engine: model.EngineSingBox, Enabled: true,
		Params: map[string]any{"interface": "awg0"},
	}}
	if got := missingAdoptedTunnels(eps, netvpn.Discovery{}, nil); len(got) != 0 {
		t.Errorf("non-external endpoints have no native interface: %+v", got)
	}
}

// A disabled endpoint is still reported (the config is still wrong) but flagged as not enabled, so
// the UI can rank an actively-routing dead tunnel above a dormant one.
func TestMissingAdoptedTunnels_DisabledIsReportedButMarked(t *testing.T) {
	eps := []model.Endpoint{extEndpoint("external-awg0", "awg0", "KEY-A", false)}

	got := missingAdoptedTunnels(eps, netvpn.Discovery{}, nil)
	if len(got) != 1 {
		t.Fatalf("want the finding, got %+v", got)
	}
	if got[0].Enabled {
		t.Error("a disabled endpoint must be marked as such so it can be ranked lower")
	}
}

// The spec's "ignore this unmanaged object" drift action. A tunnel deliberately removed from the
// router must be dismissible, or the same warning reappears on every refresh forever — and a warning
// that cannot be dismissed is one people learn to ignore wholesale.
func TestMissingAdoptedTunnels_IgnoredEndpointIsSuppressed(t *testing.T) {
	eps := []model.Endpoint{
		extEndpoint("external-awg0", "awg0", "KEY-A", true),
		extEndpoint("external-awg1", "awg1", "KEY-B", true),
	}

	got := missingAdoptedTunnels(eps, netvpn.Discovery{}, []string{"external-awg0"})
	if len(got) != 1 {
		t.Fatalf("want only the un-dismissed tunnel, got %+v", got)
	}
	if got[0].EndpointID != "external-awg1" {
		t.Errorf("wrong tunnel suppressed: %+v", got[0])
	}
}

// Dismissing one tunnel must not blind the user to the next one that disappears — the ignore list
// holds IDs, never a suppress-everything flag.
func TestMissingAdoptedTunnels_IgnoreIsPerObjectNotGlobal(t *testing.T) {
	eps := []model.Endpoint{extEndpoint("external-awg9", "awg9", "KEY-Z", true)}

	got := missingAdoptedTunnels(eps, netvpn.Discovery{}, []string{"external-awg0", "external-awg1"})
	if len(got) != 1 {
		t.Errorf("an unrelated dismissal must not suppress a new disappearance: %+v", got)
	}
}
