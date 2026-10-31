package generator

import (
	"strings"

	"wayhop/internal/model"
)

// sshAlgorithmMinMinor is the first sing-box 1.x minor whose ssh outbound takes cipher, mac and
// kex_algorithm. 1.12 and 1.13 reject an unknown field, which would fail the shared config.
const sshAlgorithmMinMinor = 14

// sshAlgorithmKeys are those three fields, each a list param of the same name (model/ssh.go).
var sshAlgorithmKeys = []string{"cipher", "mac", "kex_algorithm"}

// sshOutbound fills a sing-box ssh outbound (1.12+). Validate has refused what sing-box cannot load
// (model.EndpointParamProblem), so this only renders. An empty user is left out (sing-box then logs
// in as root), as is an empty client_version (a random OpenSSH one).
func sshOutbound(e *model.Endpoint, ob map[string]any) error {
	p := e.Params
	ob["type"] = "ssh"
	if u := strings.TrimSpace(str(p, "user")); u != "" {
		ob["user"] = u
	}
	if pw := str(p, "password"); pw != "" {
		ob["password"] = pw
	}
	if k := model.SSHPrivateKey(e); k != "" {
		ob["private_key"] = k
		if pp := str(p, "private_key_passphrase"); pp != "" {
			ob["private_key_passphrase"] = pp
		}
	}
	// A host key that does not parse is an error, never dropped: without it the connection would
	// accept any server, which is exactly what pinning it was meant to stop.
	keys, err := model.SSHHostKeys(e)
	if err != nil {
		return err
	}
	if len(keys) > 0 {
		lines := make([]string, len(keys))
		for i, k := range keys {
			lines[i] = k.String()
		}
		ob["host_key"] = lines
		// Offer only the pinned types, or the server may answer with a key it has but nobody pinned
		// (model.SSHHostKeyAlgorithms says why).
		ob["host_key_algorithms"] = model.SSHHostKeyAlgorithms(keys)
	}
	if v := str(p, "client_version"); v != "" {
		ob["client_version"] = v
	}
	return nil
}

// sshCoreExtras adds the algorithm restrictions to an ssh outbound for a core that takes them. On
// an older or unknown core they are left out, and the connection negotiates from x/crypto's
// defaults; the review says so when the known core is older (SSHAlgorithmsNeedNewerCore).
func sshCoreExtras(e *model.Endpoint, ob map[string]any, coreVersion string) {
	if coreMinor(coreVersion) < sshAlgorithmMinMinor {
		return
	}
	for _, k := range sshAlgorithmKeys {
		if l := sshList(e.Params, k); len(l) > 0 {
			ob[k] = l
		}
	}
}

// SSHAlgorithmsNeedNewerCore reports an SSH connection that restricts its algorithms on a known core
// older than 1.14, which is applied without the restriction. An unknown version says nothing.
func SSHAlgorithmsNeedNewerCore(e *model.Endpoint, coreVersion string) bool {
	if e.Protocol != model.ProtoSSH {
		return false
	}
	m := coreMinor(coreVersion)
	if m < 0 || m >= sshAlgorithmMinMinor {
		return false
	}
	for _, k := range sshAlgorithmKeys {
		if len(sshList(e.Params, k)) > 0 {
			return true
		}
	}
	return false
}

// SSHExitGetsUDP reports whether traffic that may be UDP is sent to the SSH endpoint id: by an
// enabled rule (the default one included) or routing list, neither of which matches on the network
// and so sends UDP as well as TCP, or by a DNS server that queries over UDP (udp, DoQ, DoH3) with the
// endpoint as its detour - directly or through a group holding it. sing-box's ssh outbound carries
// TCP only (it registers no UDP, and ListenPacket fails), so that UDP is refused ("UDP is not
// supported by outbound"), or in an automatic group sent to a member that carries it.
func SSHExitGetsUDP(p *model.Profile, id string) bool {
	var targets []string
	for _, r := range p.Rules {
		if !r.Disabled {
			targets = append(targets, r.Outbound)
		}
	}
	for _, l := range p.RoutingLists {
		if l.Enabled {
			targets = append(targets, l.Outbound)
		}
	}
	if p.DNS != nil && p.DNS.Enabled {
		for _, s := range p.DNS.Servers {
			if s.Enabled && (s.Type == "udp" || s.Type == "quic" || s.Type == "h3") {
				targets = append(targets, s.Detour)
			}
		}
	}
	seen := map[string]bool{}
	var holds func(tag string) bool
	holds = func(tag string) bool {
		if tag == id {
			return true
		}
		if tag == "" || seen[tag] {
			return false
		}
		seen[tag] = true
		if g := p.GroupByID(tag); g != nil {
			for _, m := range g.Members {
				if holds(m) {
					return true
				}
			}
		}
		return false
	}
	for _, t := range targets {
		if holds(t) {
			return true
		}
	}
	return false
}

// sshList reads an algorithm list param, a list or a comma or newline separated string, without
// blanks.
func sshList(p map[string]any, k string) []string {
	raw, _ := model.ParamLines(p, k)
	var out []string
	for _, l := range raw {
		for _, s := range strings.Split(l, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}
