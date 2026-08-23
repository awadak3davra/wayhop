package platform

// DemoCapabilities returns a deterministic, fully capable OpenWrt-shaped fixture for demo and
// off-router test paths. It deliberately performs no host probes: demo mode must not depend on the
// developer machine's binaries, kernel modules, package manager, or netifd tree.
//
// Every populated mutable collection is newly allocated so callers may treat the result like an
// ordinary probe response without changing package data or another caller's snapshot.
func DemoCapabilities() Capabilities {
	return Capabilities{
		Platform: string(OpenWrt),
		Native: map[string]bool{
			"amneziawg": true,
			"wireguard": true,
		},
		Installable:     map[string]string{},
		SingboxRequired: append([]string(nil), singboxRequired...),
		SingboxPresent:  true,
		Accel: Accel{
			Kind: "nft-flowtable",
			HW:   true,
		},
		NetifdProtos: map[string]bool{
			"amneziawg": true,
			"wireguard": true,
		},
	}
}
