package server

import (
	"context"
	"strings"
	"testing"

	"wayhop/internal/platform"
)

// The consistency assertion WH-DIAG-006 exists for: /api/healthcheck and /api/native/capabilities
// describe ONE datapath, so for a single captured fixture they may not return mutually exclusive
// verdicts. They cannot, structurally, because both render the same platform.OffloadState — this
// pins the rendering so a future edit to the row cannot reintroduce the contradiction.
//
// The fixture is the AX3000T's: the firewall config says offload is off while the same router has
// connections carrying an offload mark. The old row read only the config and said "flow offload is
// off … the hardware fast path is unused" while capabilities reported the offloaded flows.
func TestFlowOffloadCheck_AgreesWithCapabilities(t *testing.T) {
	fixtures := map[string]platform.OffloadInputs{
		"config off but flows offloaded": {
			Requested:       "sw",
			FirewallUCI:     "config defaults\n\toption flow_offloading '0'\n",
			FlowtablesKnown: true,
			Flowtables:      "table inet fw4 {\n\tflowtable ft {\n\t\tflags offload\n\t}\n}\n",
			Conntrack:       "ipv4 2 tcp 6 431999 ESTABLISHED src=192.0.2.10 [OFFLOAD] mark=0 use=1",
		},
		"configured hw, nothing offloaded": {
			Requested:       "hw",
			FirewallUCI:     "config defaults\n\toption flow_offloading '1'\n\toption flow_offloading_hw '1'\n",
			FlowtablesKnown: true,
			Flowtables:      "table inet fw4 {\n\tflowtable ft {\n\t\tflags offload\n\t}\n}\n",
			Conntrack:       "ipv4 2 tcp 6 431999 ESTABLISHED src=192.0.2.10 [ASSURED] mark=0 use=1",
		},
		"nothing measurable": {Requested: "hw"},
	}
	for name, in := range fixtures {
		t.Run(name, func(t *testing.T) {
			st := platform.DetectOffload(in) // exactly what /api/native/capabilities serialises
			row := flowOffloadCheck(context.Background(), st)
			text := strings.ToLower(row.Summary + " " + row.Detail)

			if row.ID != "offload" {
				t.Fatalf("ID = %q, want offload", row.ID)
			}
			switch st.Effective {
			case "hw", "sw":
				if row.Status != "pass" {
					t.Errorf("capabilities report effective=%q but the row is %q", st.Effective, row.Status)
				}
				if strings.Contains(text, "offload is off") || strings.Contains(text, "unused") {
					t.Errorf("capabilities report effective=%q, but the row says %q", st.Effective, text)
				}
			case "off":
				if !strings.Contains(text, "off") {
					t.Errorf("capabilities report off, but the row says %q", text)
				}
			case "unknown":
				// An unmeasurable datapath is not a verdict, so the row reports "na" and says only that
				// it could not be read. What it must never do is name a state.
				if row.Status != "na" {
					t.Errorf("capabilities could not measure the datapath, but the row status is %q", row.Status)
				}
				if !strings.Contains(text, "could not be read") {
					t.Errorf("capabilities could not measure the datapath, but the row says %q", text)
				}
				if row.Fix != "" && !strings.Contains(row.Fix, "no offload setting") {
					t.Errorf("an unmeasured datapath must not carry actionable advice: %q", row.Fix)
				}
			}
		})
	}
}

// A row that already reports the fast path in use must not also tell the operator to enable it.
func TestFlowOffloadCheck_NoAdviceWhenHardwareIsAlreadyInUse(t *testing.T) {
	st := platform.DetectOffload(platform.OffloadInputs{
		Requested: "hw",
		Conntrack: "ipv4 2 tcp 6 431999 ESTABLISHED src=192.0.2.10 [HW_OFFLOAD] mark=0 use=1",
	})
	row := flowOffloadCheck(context.Background(), st)
	if row.Status != "pass" || row.Fix != "" {
		t.Fatalf("status=%q fix=%q, want a clean pass with nothing to advise", row.Status, row.Fix)
	}
}

// A cancelled battery must not turn into a verdict about the router.
func TestFlowOffloadCheck_CancelledIsNotAVerdict(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	row := flowOffloadCheck(ctx, platform.OffloadState{Effective: "off"})
	// This test always meant "na" — it just had no such status to ask for, so it settled for the
	// amber that put a cancelled check on the operator's to-do list.
	if row.Status != "na" || !strings.Contains(row.Summary, "cancelled") {
		t.Fatalf("status=%q summary=%q, want a cancelled non-verdict", row.Status, row.Summary)
	}
}
