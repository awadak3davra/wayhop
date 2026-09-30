package main

import "os"

// dropInheritedLoaderPath removes LD_LIBRARY_PATH from this process's environment before anything
// can spawn a child, so no child inherits it.
//
// The daemon itself is built with CGO_ENABLED=0: a static binary that never consults the dynamic
// loader, so the variable means nothing to it. It means a great deal to what it runs. Entware's init
// starts every service with LD_LIBRARY_PATH=/opt/lib:/opt/usr/lib:/lib:/usr/lib - Entware's own
// libraries FIRST - and the daemon passed that straight on to the firmware's /bin/ndmc, which is
// linked against the firmware's /lib. Handed Entware's libraries instead, ndmc cannot start:
//
//	ndm: ndmc: system failed [0xcffd0062].
//	ndm: Cli::Main: failed to initialize.
//
// Measured on a live Keenetic (KeeneticOS, Entware on USB): the same `ndmc -c "show running-config"`
// returned exit 0 and 46 KB from a login shell, and exit 1 with only that 120-byte failure under the
// daemon's environment; LD_BIND_NOW, the other loader variable in that environment, was innocent.
// Every Apply therefore stopped at capture ("exact execution host capture is unavailable"), and the
// adapter that applies config line by line, NDM interface discovery and the platform capability
// probe all run ndmc the same way.
//
// Removing it is safe for the Entware binaries the daemon also runs: ipset, iptables, ip6tables and
// dnsmasq from /opt were each measured to run without it, because Entware builds them with an RPATH
// to /opt/lib. Done once, here, rather than at each exec site - there are several, and the next one
// would have been written without knowing.
func dropInheritedLoaderPath() {
	_ = os.Unsetenv("LD_LIBRARY_PATH")
}
