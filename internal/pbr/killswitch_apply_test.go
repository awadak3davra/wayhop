package pbr

import (
	"errors"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// devDownRunner records every command and fails the per-egress `default dev <iface>` route the way
// the kernel does when the tunnel iface is absent, so we can verify Apply tolerates it.
type devDownRunner struct {
	cmds      []string
	failedDev bool
}

func (d *devDownRunner) Run(stdin, name string, args ...string) (string, error) {
	c := strings.TrimSpace(name + " " + strings.Join(args, " "))
	d.cmds = append(d.cmds, c)
	if strings.Contains(c, "route replace default dev ") {
		d.failedDev = true
		// Mirror ExecRunner: the "device is absent" signal is wrapped into the ERROR (%w: %s), so
		// isMissingDeviceErr can distinguish a down tunnel from a generic apply failure.
		return "Cannot find device", errors.New(`exit status 2: Cannot find device "awg0"`)
	}
	return "", nil
}

func (d *devDownRunner) ran(sub string) bool {
	for _, c := range d.cmds {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

// TestKillSwitchFailClosed_BlackholeSurvivesDownTunnel: when the tunnel iface is down at apply
// time the `default dev` route fails — but Apply must NOT abort (which would tear out the whole
// plane incl. the kill-switch blackhole, i.e. fail OPEN). The fwmark rule + blackhole must still
// install so the kill-switched carve-out fails CLOSED.
func TestKillSwitchFailClosed_BlackholeSurvivesDownTunnel(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "awg", Engine: model.EngineAmneziaWG, Server: "1.2.3.4", Port: 51820,
				Params: map[string]any{"private_key": "k", "peer_public_key": "k", "local_address": []string{"10.0.0.2/32"}}},
		},
		Groups: []model.Group{{ID: "g", Name: "G", Type: model.GroupURLTest, Members: []string{"awg"}, KillSwitch: true}},
		Rules: []model.Rule{
			{ID: "r", IPCIDR: []string{"1.2.3.0/24"}, Outbound: "g"},
			{ID: "def", Default: true, Outbound: model.OutboundDirect},
		},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	r := &devDownRunner{}
	if err := plan.Apply(r, Options{}); err != nil {
		t.Fatalf("Apply must tolerate a down `default dev` route (kill-switch fail-closed), got: %v", err)
	}
	if !r.failedDev {
		t.Fatal("test precondition: the `default dev` route should have been attempted + failed")
	}
	if !r.ran("ip route replace blackhole default metric") {
		t.Errorf("the kill-switch blackhole must still install when the tunnel iface is down:\n%s", strings.Join(r.cmds, "\n"))
	}
	if !r.ran("ip rule add fwmark") {
		t.Errorf("the fwmark rule must still install:\n%s", strings.Join(r.cmds, "\n"))
	}
}
