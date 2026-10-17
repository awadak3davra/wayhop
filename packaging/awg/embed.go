// Package awg carries WayHop's standalone AmneziaWG installer, install-awg.sh, into the daemon.
//
// One script is used three ways (by hand, by bootstrap.sh/install.sh --with-awg, and by the daemon's
// Components page), so the decision of what to install on a router - the kernel module when the
// router's release and target have a matching kmod, userspace amneziawg-go otherwise, or a refusal
// when neither fits - is made in exactly one place. The daemon embeds the script rather than fetching
// it, so the installer it runs is the one this binary was built and tested with. The contract it is
// run against is in docs/AWG_FULL_INSTALL.md (development repository), "Installer contract".
package awg

import _ "embed"

//go:embed install-awg.sh
var installScript []byte

// InstallScript returns the embedded installer. A copy, so no caller can change what the next one
// runs.
func InstallScript() []byte { return append([]byte(nil), installScript...) }
