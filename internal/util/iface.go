package util

import (
	"fmt"
	"hash/fnv"
)

// AWGIface is the deterministic Linux interface name for an AmneziaWG endpoint: short (<=15 chars,
// kernel limit), stable, and derived from the endpoint ID so every plane that has to name the device
// agrees on exactly one. fnv, not a crypto hash — this is a name, not a secret.
//
// The separator is an UNDERSCORE, and that is load-bearing rather than cosmetic. Three planes name
// this device now: the generator's bind_interface, the plugin's `ip link add`, and — since the
// native path — the uci section the interface is written under. uci refuses a hyphen in a section
// name (measured on OpenWrt 24.10: `uci set network.wr-1a2b3c4d=interface` answers "Invalid
// argument"), and the amneziawg proto handler names the device after the section verbatim
// (`ip link add dev "${config}" type amneziawg`), so the section name IS the device name and there
// is no second knob to reconcile them with. The kernel takes either form (both `wr_44284aea` and
// `wr-44284aea` create fine), so the underscore is the only spelling that satisfies all three.
//
// It was a hyphen until the native writer arrived and quietly disagreed with it, routing traffic out
// of a device that did not exist. Endpoints carried by the awg-quick plugin path get their device
// renamed once, at the next apply — a tunnel restart, which apply does anyway.
func AWGIface(id string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(id))
	return fmt.Sprintf("wr_%08x", h.Sum32()) // "wr_" + 8 hex = 11 chars
}
