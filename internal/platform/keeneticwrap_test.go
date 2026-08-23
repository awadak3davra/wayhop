package platform

import (
	"strings"
	"testing"
)

// lower mirrors what decideKeenetic does to the text before matching, so these tests exercise the
// same input the production path builds.
func lower(s string) string { return strings.ToLower(s) }

// ndmcVersionWrapped is a live Keenetic (KeeneticOS 5.01) printing its component list, with
// its own wrapping preserved. Captured from `ndmc -c "show version"`, not written by hand — and the
// wrapping is the point: ndmc breaks the list at a fixed column and splits NAMES across the break.
// Three are split in that device's real output, verbatim below: `nathelper-` / `sip`,
// `opkg-` / `kmod-netfilter-addons`, `opkg-` / `kmod-video`.
const ndmcVersionWrapped = `        release: 5.01.C.3.0-1
        sandbox: preview
     components: acl,base,cloudcontrol,corewireless,ddns,
                       dhcpd,dns-filter,dns-https,dns-tls,dot1x,easyconfig,
                       exfat,ext,fat,ftp,hfsplus,igmp,ike-client,ip6,ipsec,l2tp,
                       lang-en,lang-ru,mdns,miniupnpd,monitor,mws,nathelper-ftp,
                       nathelper-h323,nathelper-pptp,nathelper-rtsp,nathelper-
                       sip,ndmp,ndns,ntfs,ocserver,openconnect,openvpn,opkg,
                       opkg-kmod-audio,opkg-kmod-fs,opkg-kmod-netfilter,opkg-
                       kmod-netfilter-addons,opkg-kmod-video,ppe,pppoe,
                       usbserial-extra,webdav,wireguard,zerotier
`

// The device as it is: every name this file asks about must be found, wrapped list and all.
func TestHasComponent_TheOperatorsKeeneticAsItPrints(t *testing.T) {
	for _, comp := range []string{"wireguard", "ipsec", "l2tp", "openvpn", "openconnect", "ppe"} {
		if !hasComponent(lower(ndmcVersionWrapped), comp) {
			t.Errorf("component %q not found in the device's own version text", comp)
		}
	}
	caps := decideKeenetic(hostInputs{ndmcVersion: ndmcVersionWrapped})
	if !caps.Native["wireguard"] || !caps.Native["amneziawg"] {
		t.Fatalf("the router that prints this has WireGuard; Native = %+v", caps.Native)
	}
	if caps.Accel.Kind != "ppe" {
		t.Errorf("ppe is in the list and the accelerator is %+v", caps.Accel)
	}
}

// The case the wrap actually threatens. `wireguard` sits mid-line on this device today — luck of
// position, since the list grows with every installed component. Put it on a boundary, exactly as
// ndmc splits `nathelper-`/`sip`, and a substring match reports a router with WireGuard as having
// none: the panel would then offer to install a firmware component the box already carries.
func TestHasComponent_ANameSplitByTheWrapIsStillFound(t *testing.T) {
	split := `     components: acl,base,ddns,usbserial-extra,webdav,wire
                       guard,zerotier
`
	if !hasComponent(lower(split), "wireguard") {
		t.Fatal(`a component split across ndmc's line wrap was reported absent`)
	}
	caps := decideKeenetic(hostInputs{ndmcVersion: split})
	if !caps.Native["wireguard"] || !caps.Native["amneziawg"] {
		t.Errorf("Native = %+v, want wireguard and amneziawg", caps.Native)
	}
	if caps.Installable["wireguard"] != "" {
		t.Errorf("it also offers to install what the router already has: %q", caps.Installable["wireguard"])
	}
}

// And the other half: a whole-token match, so a name is never found INSIDE another one. `ppe` is
// three letters and this file asks for it by name; a substring check reports hardware offload on any
// router whose component list happens to contain those letters.
func TestHasComponent_DoesNotMatchInsideAnotherName(t *testing.T) {
	for _, tc := range []struct{ text, comp string }{
		{"     components: acl,base,ppe-legacy,zerotier\n", "ppe"},
		{"     components: acl,wireguard-lite,zerotier\n", "wireguard"},
		{"     components: acl,base,zerotier\n", "ppe"},
	} {
		if hasComponent(lower(tc.text), tc.comp) {
			t.Errorf("%q was reported present in %q", tc.comp, tc.text)
		}
	}
}
