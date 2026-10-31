package keenetic

import (
	"strings"
	"testing"

	"wayhop/internal/awg"
	"wayhop/internal/model"
)

// QA-127. The writer holds the firmware's line as well as the planner: on a KeeneticOS release that
// takes only the AmneziaWG 1 settings it refuses the AmneziaWG 2 ones instead of writing a
// `wireguard asc` line the router rejects, and writes the nine-argument form it does take.
func TestQA127WriterCappedByFirmwareGeneration(t *testing.T) {
	e := awgEndpoint()
	e.Protocol = model.ProtoAmneziaWG
	e.Params["s3"], e.Params["s4"] = 15, 25
	if _, err := WireguardCommands(e, WireguardOpts{Index: 5, AWGGeneration: awg.Gen1}); err == nil ||
		!strings.Contains(err.Error(), "KeeneticOS release") {
		t.Fatalf("AmneziaWG 2 settings at a generation-1 firmware: err = %v, want a refusal", err)
	}
	// Zero, and anything above the writer's own, is the writer's own: unchanged.
	for _, gen := range []awg.Generation{awg.GenNone, awg.Gen2, awg.Gen31} {
		cmds, err := WireguardCommands(e, WireguardOpts{Index: 5, AWGGeneration: gen})
		if err != nil || !strings.Contains(strings.Join(cmds, "\n"), " 15 25") {
			t.Fatalf("generation %v: err %v, cmds %q; want S3/S4 written", gen, err, cmds)
		}
	}
	plain := awgEndpoint()
	plain.Protocol = model.ProtoAmneziaWG
	cmds, err := WireguardCommands(plain, WireguardOpts{Index: 5, AWGGeneration: awg.Gen1})
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range cmds {
		if strings.HasPrefix(line, "wireguard asc ") && len(strings.Fields(line)) != 2+len(ascBase) {
			t.Fatalf("generation-1 asc = %q, want the nine-argument form", line)
		}
	}
}
