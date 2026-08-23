package pm

import "strings"

// SplitApkOwner separates an apk owner token into the package name and its version.
//
// `apk info --who-owns` answers with name AND version glued together, verified on the OpenWrt
// 25.12.2 test box:
//
//	/bin/busybox      is owned by busybox-1.37.0-r6
//	/usr/bin/sing-box is owned by sing-box-1.12.17-r1
//	/usr/sbin/nft     is owned by nftables-json-1.1.6-r1
//	/usr/bin/curl     is owned by curl-8.19.0-r1
//
// So Owner() returns "sing-box-1.12.17-r1" where a caller wanting to run `apk add <pkg>` needs
// "sing-box". Feeding the whole token to a package-manager verb would name a package that does not
// exist. The panel already shows the raw token to the operator as "package {0}", which is a string
// they cannot use anywhere.
//
// The split cannot be "cut at the last dash" (that yields "sing-box-1.12.17" and "r1") nor "cut at
// the first dash" ("sing" and "box-1.12.17-r1"). The rule apk's own naming follows is that the
// version begins at the FIRST dash followed by a digit — which is why nftables-json survives it, and
// why a name like dnscrypt-proxy2 does too: the dash before "proxy2" is followed by a letter.
func SplitApkOwner(owner string) (name, version string) {
	owner = strings.TrimSpace(owner)
	for i := 0; i+1 < len(owner); i++ {
		if owner[i] != '-' {
			continue
		}
		if c := owner[i+1]; c >= '0' && c <= '9' {
			return owner[:i], owner[i+1:]
		}
	}
	return owner, "" // no version part: already a bare name
}

// PackageName normalises whatever Owner() reported into a name a package-manager verb can take.
// opkg's `search` already answers with the bare name, so only apk needs the split.
func (m Manager) PackageName(owner string) string {
	if m.Kind == Apk {
		n, _ := SplitApkOwner(owner)
		return n
	}
	return strings.TrimSpace(owner)
}
