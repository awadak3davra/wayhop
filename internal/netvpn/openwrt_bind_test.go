package netvpn

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

const bindFirewall = `firewall.@zone[0]=zone
firewall.@zone[0].name='lan'
firewall.@zone[0].network='lan'
firewall.@zone[1]=zone
firewall.@zone[1].name='wan'
firewall.@zone[2]=zone
firewall.@zone[2].name='vpn'
firewall.@zone[2].network='awg0' 'awg1'
`

func bindFirewallWith(devices string) string {
	return bindFirewall + "firewall.@zone[2].device=" + devices + "\n"
}

func TestParseFirewallZonesReadsDevices(t *testing.T) {
	zones := ParseFirewallZones(bindFirewallWith("'wr_a' 'tun+'"))
	if got := zones[2].Devices; !reflect.DeepEqual(got, []string{"wr_a", "tun+"}) {
		t.Fatalf("devices = %v", got)
	}
	if zones[0].Devices != nil {
		t.Errorf("a zone with no device list got %v", zones[0].Devices)
	}
}

func TestBuildDeviceBinding(t *testing.T) {
	b, err := BuildDeviceBinding("wr_a", "vpn", bindFirewall)
	if err != nil {
		t.Fatal(err)
	}
	want := DeviceBinding{Device: "wr_a", Zone: "vpn", ZoneRef: "@zone[2]",
		Commands: []string{"uci add_list firewall.@zone[2].device='wr_a'"}, Commit: FirewallCommitCmds()}
	if !reflect.DeepEqual(b, want) {
		t.Errorf("binding = %+v, want %+v", b, want)
	}
	if b, err := BuildDeviceBinding("wr_a", "vpn", bindFirewallWith("'wr_a'")); err != nil || len(b.Commands) != 0 {
		t.Errorf("a device the zone lists already: %+v, %v", b, err)
	}
	for name, c := range map[string][3]string{
		"no zone reviewed": {"wr_a", "", bindFirewall},
		"zone absent":      {"wr_a", "dmz", bindFirewall},
		"unsafe name":      {"wr_a;reboot", "vpn", bindFirewall},
	} {
		if _, err := BuildDeviceBinding(c[0], c[1], c[2]); err == nil {
			t.Errorf("%s: planned", name)
		}
	}
}

// bindRunner answers `uci show firewall` with before until the first staged write, then with after.
func bindRunner(before, after string) *RecordRunner {
	rr := &RecordRunner{Responses: map[string]string{"uci show firewall": before}, Fail: map[string]error{}}
	rr.OnCommand = func(cmd string, r *RecordRunner) {
		if strings.HasPrefix(cmd, "uci add_list firewall.") || strings.HasPrefix(cmd, "uci del_list firewall.") {
			r.Responses["uci show firewall"] = after
		}
	}
	return rr
}

func TestDeviceBindingApply(t *testing.T) {
	b, _ := BuildDeviceBinding("wr_a", "vpn", bindFirewall)

	rr := bindRunner(bindFirewall, bindFirewallWith("'wr_a'"))
	res, err := b.Apply(rr)
	if err != nil || !res.Applied {
		t.Fatalf("apply: %+v, %v", res, err)
	}
	want := []string{"uci changes firewall", "uci show firewall", "uci add_list firewall.@zone[2].device='wr_a'",
		"uci show firewall", "uci commit firewall", "/etc/init.d/firewall reload"}
	if !reflect.DeepEqual(rr.Cmds, want) {
		t.Errorf("commands:\n%q\nwant\n%q", rr.Cmds, want)
	}

	staged := bindRunner(bindFirewall, bindFirewallWith("'wr_a'"))
	staged.Responses["uci changes firewall"] = "firewall.@zone[0].input='ACCEPT'"
	if _, err := b.Apply(staged); err == nil || len(staged.Cmds) != 1 {
		t.Errorf("someone else's staged edit: err %v, commands %q", err, staged.Cmds)
	}

	moved := bindRunner(strings.ReplaceAll(bindFirewall, "name='vpn'", "name='guest'"), "")
	if res, err := b.Apply(moved); err == nil || len(res.Preflight) == 0 || hasPrefixCmd(moved.Cmds, "uci add_list") {
		t.Errorf("zone moved: res %+v, err %v, commands %q", res, err, moved.Cmds)
	}

	lost := bindRunner(bindFirewall, bindFirewall) // the add does not show up in the buffer
	res, err = b.Apply(lost)
	if err == nil || res.Applied || res.Rollback != RollbackDone || hasPrefixCmd(lost.Cmds, "uci commit") {
		t.Errorf("unverified write: res %+v, err %v, commands %q", res, err, lost.Cmds)
	}

	present, _ := BuildDeviceBinding("wr_a", "vpn", bindFirewallWith("'wr_a'"))
	quiet := bindRunner(bindFirewallWith("'wr_a'"), "")
	if res, err := present.Apply(quiet); err != nil || !res.Applied || hasPrefixCmd(quiet.Cmds, "uci commit") {
		t.Errorf("already bound: res %+v, err %v, commands %q", res, err, quiet.Cmds)
	}
	// A replay of the plan that added it - a boot converging to the committed state - writes nothing:
	// `uci add_list` would list the device twice.
	replay := bindRunner(bindFirewallWith("'wr_a'"), "")
	if res, err := b.Apply(replay); err != nil || !res.Applied || hasPrefixCmd(replay.Cmds, "uci add_list") {
		t.Errorf("replay: res %+v, err %v, commands %q", res, err, replay.Cmds)
	}
	gone := bindRunner(bindFirewall, "")
	if _, err := present.Apply(gone); err == nil {
		t.Error("a plan that adds nothing succeeded against a zone that lost the device")
	}
}

func TestDeviceUnbinding(t *testing.T) {
	fw := bindFirewallWith("'wr_a' 'tun+'") + "firewall.@zone[0].device='wr_a'\n"
	u := BuildDeviceUnbinding("wr_a", fw)
	wantCmds := []string{"uci del_list firewall.@zone[0].device='wr_a'", "uci del_list firewall.@zone[2].device='wr_a'"}
	if !reflect.DeepEqual(u.Commands, wantCmds) || len(u.Zones) != 2 {
		t.Fatalf("unbinding = %+v", u)
	}
	after := strings.ReplaceAll(strings.ReplaceAll(fw, "'wr_a' 'tun+'", "'tun+'"), "firewall.@zone[0].device='wr_a'\n", "")
	rr := bindRunner(fw, after)
	if res, err := u.Apply(rr); err != nil || !res.Applied || !hasPrefixCmd(rr.Cmds, "uci commit firewall") {
		t.Fatalf("apply: %+v, %v, %q", res, err, rr.Cmds)
	}

	if empty := BuildDeviceUnbinding("wr_b", fw); len(empty.Commands) != 0 || len(empty.Commit) != 0 {
		t.Errorf("a device no zone lists got a plan: %+v", empty)
	}
	gone := bindRunner(after, "")
	if res, err := u.Apply(gone); err != nil || !res.Applied || hasPrefixCmd(gone.Cmds, "uci del_list") {
		t.Errorf("already unbound: %+v, %v, %q", res, err, gone.Cmds)
	}
	moved := bindRunner(strings.ReplaceAll(fw, "name='lan'", "name='guest'"), after)
	if res, err := u.Apply(moved); err == nil || len(res.Preflight) == 0 || hasPrefixCmd(moved.Cmds, "uci del_list") {
		t.Errorf("zone moved: %+v, %v, %q", res, err, moved.Cmds)
	}
	failing := bindRunner(fw, after)
	failing.Fail["uci del_list firewall.@zone[2].device='wr_a'"] = errors.New("uci: entry not found")
	if res, err := u.Apply(failing); err == nil || res.Rollback != RollbackDone || hasPrefixCmd(failing.Cmds, "uci commit") {
		t.Errorf("failed write: %+v, %v, %q", res, err, failing.Cmds)
	}
}

func hasPrefixCmd(cmds []string, prefix string) bool {
	for _, c := range cmds {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}
