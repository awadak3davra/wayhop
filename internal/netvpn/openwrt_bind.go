package netvpn

import (
	"errors"
	"fmt"
	"strings"
)

// openwrt_bind.go puts a device netifd does not own into a firewall zone: the TUN WayHop's userspace
// AmneziaWG (amneziawg-go) creates for a connection the router's own AmneziaWG cannot carry.
//
// Without a zone that device is not forwarded at all. fw4's forward chain has policy drop, and a LAN
// packet leaving through an interface no zone names falls to `jump handle_reject` - measured on the
// AX3000T (OpenWrt 25.12.2), whose forward chain accepts only per-zone traffic plus sing-box's own
// tun0 rules.
//
// The zone lists it by DEVICE, not by network interface. fw4 matches a zone's `device` list against
// raw netdev names (parse_zone reads `device` as a list and adds it to match_devices, read off the
// router's own /usr/share/ucode/fw4.uc), so nothing in /etc/config/network is written and netifd never
// hears of the device. That is the point: a `proto none` network section would put netifd in charge of
// a device another process creates and deletes, and netifd acts on the name - the teardown of the
// amneziawg interface a previous Apply created runs `ip link del` on whatever answers to it.
//
// Same discipline as the tunnel plans: built from a snapshot, staged, read back, then committed, and
// refused when the snapshot no longer holds.

// DeviceBinding is the plan that adds Device to one firewall zone's device list.
type DeviceBinding struct {
	Device string

	// Zone is the zone's stable name, ZoneRef the section that held it when the plan was built. The
	// reference is an index and indices shift, so the write re-checks that it still holds the name.
	Zone, ZoneRef string

	// Commands stage the addition; empty when the zone already listed the device at build time.
	Commands []string

	// Commit is the mutating tail.
	Commit []string
}

// BuildDeviceBinding plans device into the zone named zoneName, against `uci show firewall`.
func BuildDeviceBinding(device, zoneName, uciFirewall string) (DeviceBinding, error) {
	if !validUCIName(device) {
		return DeviceBinding{}, fmt.Errorf("bind device: %q is not a usable device name", device)
	}
	if zoneName == "" {
		return DeviceBinding{}, fmt.Errorf("bind device %s: no firewall zone was reviewed, and a device no zone lists is not forwarded", device)
	}
	zones := ParseFirewallZones(uciFirewall)
	z, ok := FindZone(zones, zoneName)
	if !ok {
		return DeviceBinding{}, fmt.Errorf("bind device %s: firewall zone %q does not exist on this router (zones present: %s)",
			device, zoneName, strings.Join(zoneNames(zones), ", "))
	}
	b := DeviceBinding{Device: device, Zone: z.Name, ZoneRef: z.Ref, Commit: FirewallCommitCmds()}
	if !contains(z.Devices, device) {
		// Only when absent: `uci add_list` appends unconditionally, and fw4 would render the duplicate.
		b.Commands = []string{fmt.Sprintf("uci add_list firewall.%s.device=%s", z.Ref, q(device))}
	}
	return b, nil
}

// PreflightAgainst is the check before writing: the zone must still sit where the plan found it.
func (b DeviceBinding) PreflightAgainst(freshFirewall string) []Difference {
	for _, z := range ParseFirewallZones(freshFirewall) {
		if z.Ref == b.ZoneRef {
			if z.Name == b.Zone {
				return nil
			}
			return []Difference{{Field: "firewall zone " + b.ZoneRef, Want: b.Zone, Got: z.Name}}
		}
	}
	return []Difference{{Field: "firewall zone " + b.ZoneRef, Want: b.Zone, Got: "absent"}}
}

// VerifyAgainst is the check after writing: the zone lists the device.
func (b DeviceBinding) VerifyAgainst(freshFirewall string) []Difference {
	z, ok := FindZone(ParseFirewallZones(freshFirewall), b.Zone)
	if !ok {
		return []Difference{{Field: "firewall zone " + b.Zone, Want: "present, listing " + b.Device, Got: "absent"}}
	}
	if !contains(z.Devices, b.Device) {
		return []Difference{{Field: "firewall zone " + b.Zone, Want: "lists device " + b.Device, Got: "does not"}}
	}
	return nil
}

// Apply writes the binding: nothing else may be staged for the firewall, the zone must still be where
// the plan found it, and the staged result is read back before it is committed.
func (b DeviceBinding) Apply(r Runner) (ApplyResult, error) {
	var res ApplyResult
	sh := func(cmd string) (string, error) {
		res.Ran = append(res.Ran, cmd)
		return r.Run("", "sh", "-c", cmd)
	}
	before, err := firewallUnstaged(sh, "bind "+b.Device)
	if err != nil {
		return res, err
	}
	if d := b.PreflightAgainst(before); len(d) > 0 {
		res.Preflight = d
		return res, fmt.Errorf("bind %s: the firewall changed after this plan was built (%s)", b.Device, d[0])
	}
	// Already listed: nothing to stage. This is also what makes a replay of the same plan - a boot
	// converging to the committed state - idempotent: `uci add_list` would append the device again.
	if len(b.VerifyAgainst(before)) == 0 {
		res.Applied = true
		return res, nil
	}
	if len(b.Commands) == 0 {
		return res, fmt.Errorf("bind %s: the zone no longer lists the device and this plan adds nothing; the plan is stale", b.Device)
	}
	return res, stageVerifyCommit(sh, &res, "bind "+b.Device, b.Commands, b.Commit, b.VerifyAgainst)
}

// DeviceUnbinding is the plan that takes Device out of every zone that lists it.
type DeviceUnbinding struct {
	Device string

	// Zones are the zones that listed it when the plan was built, with the section each held.
	Zones []Zone

	Commands []string
	Commit   []string
}

// BuildDeviceUnbinding plans device out of every zone in `uci show firewall` that lists it. A device
// no zone lists gives a plan with no commands: there is nothing to take out.
func BuildDeviceUnbinding(device, uciFirewall string) DeviceUnbinding {
	u := DeviceUnbinding{Device: device}
	for _, z := range ParseFirewallZones(uciFirewall) {
		if contains(z.Devices, device) {
			u.Zones = append(u.Zones, Zone{Ref: z.Ref, Name: z.Name})
			u.Commands = append(u.Commands, fmt.Sprintf("uci del_list firewall.%s.device=%s", z.Ref, q(device)))
		}
	}
	if len(u.Commands) != 0 {
		u.Commit = FirewallCommitCmds()
	}
	return u
}

// VerifyRemoved is the check after writing: no zone lists the device any more.
func (u DeviceUnbinding) VerifyRemoved(freshFirewall string) []Difference {
	var out []Difference
	for _, z := range ParseFirewallZones(freshFirewall) {
		if contains(z.Devices, u.Device) {
			out = append(out, Difference{Field: "firewall zone " + z.Name, Want: "no longer lists " + u.Device, Got: "still lists it"})
		}
	}
	return out
}

// Apply takes the device out: the zones must still sit where the plan found them, and the staged
// result is read back before it is committed.
func (u DeviceUnbinding) Apply(r Runner) (ApplyResult, error) {
	var res ApplyResult
	sh := func(cmd string) (string, error) {
		res.Ran = append(res.Ran, cmd)
		return r.Run("", "sh", "-c", cmd)
	}
	before, err := firewallUnstaged(sh, "unbind "+u.Device)
	if err != nil {
		return res, err
	}
	if len(u.VerifyRemoved(before)) == 0 {
		res.Applied = true // already out of every zone
		return res, nil
	}
	current := map[string]string{}
	for _, z := range ParseFirewallZones(before) {
		current[z.Ref] = z.Name
	}
	for _, z := range u.Zones {
		if current[z.Ref] != z.Name {
			res.Preflight = []Difference{{Field: "firewall zone " + z.Ref, Want: z.Name, Got: orAbsent(current[z.Ref])}}
			return res, fmt.Errorf("unbind %s: the firewall changed after this plan was built (%s)", u.Device, res.Preflight[0])
		}
	}
	return res, stageVerifyCommit(sh, &res, "unbind "+u.Device, u.Commands, u.Commit, u.VerifyRemoved)
}

// firewallUnstaged returns `uci show firewall`, refusing when something else is staged for the
// firewall: the rollback discards the whole buffer, so it would discard that too.
func firewallUnstaged(sh func(string) (string, error), what string) (string, error) {
	out, err := sh("uci changes firewall")
	if err != nil {
		return "", fmt.Errorf("%s: reading staged firewall changes: %w", what, err)
	}
	if strings.TrimSpace(out) != "" {
		return "", fmt.Errorf("%s: the firewall has uncommitted changes; refusing, because rolling back would discard them too:\n%s",
			what, strings.TrimSpace(out))
	}
	fw, err := sh("uci show firewall")
	if err != nil {
		return "", fmt.Errorf("%s: reading the firewall config: %w", what, err)
	}
	return fw, nil
}

// stageVerifyCommit runs the staged commands, reads the firewall back, checks it, and only then
// commits; any failure before the commit reverts the firewall buffer.
func stageVerifyCommit(sh func(string) (string, error), res *ApplyResult, what string, commands, commit []string,
	verify func(string) []Difference) error {
	for _, c := range commands {
		if out, err := sh(c); err != nil {
			rb := revertConfigs(sh, res, "firewall")
			return errors.Join(fmt.Errorf("%s: %q failed%s: %w: %s", what, c, rollbackNote(res.Rollback), err, strings.TrimSpace(out)), rb)
		}
	}
	after, err := sh("uci show firewall")
	if err != nil {
		rb := revertConfigs(sh, res, "firewall")
		return errors.Join(fmt.Errorf("%s: re-reading after the write%s: %w", what, rollbackNote(res.Rollback), err), rb)
	}
	if d := verify(after); len(d) > 0 {
		res.Verify = d
		rb := revertConfigs(sh, res, "firewall")
		return errors.Join(fmt.Errorf("%s: the staged firewall does not match what was intended (%s)%s", what, d[0], rollbackNote(res.Rollback)), rb)
	}
	for _, c := range commit {
		if out, err := sh(c); err != nil {
			return fmt.Errorf("%s: %q failed AFTER the change was verified; the firewall may be half-applied: %w: %s",
				what, c, err, strings.TrimSpace(out))
		}
	}
	res.Applied = true
	return nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func orAbsent(s string) string {
	if s == "" {
		return "absent"
	}
	return s
}
