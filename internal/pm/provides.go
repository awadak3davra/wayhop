package pm

import (
	"context"
	"fmt"
	"strings"
)

// A package name can be VIRTUAL. opkg lets a package declare `Provides:` and then answers to that
// name as well as its own — measured on the Keenetic:
//
//	opkg status sing-box-go   ->  Provides: sing-box-go-any, sing-box
//	opkg list sing-box        ->  (empty)
//	opkg whatprovides sing-box->  sing-box-go
//	opkg install --noaction sing-box -> Package sing-box-go (1.13.3-2) installed in root is up to date.
//
// So "the feed has no package called sing-box" is a WRONG conclusion from an empty `opkg list`: the
// name resolves, the install works, and a caller that stops at the list refuses an operation the
// package manager can perform. That is a regression this repo introduced by adding a feed-existence
// check for apk — where an empty list really does mean absent — and applying it to both managers.
//
// apk is deliberately NOT given an implementation here. It has its own provides mechanism, and no
// measurement of it has been taken on a real box; guessing at the output shape is exactly what put
// three defects into the apk parsers before the device was read. Unresolved is reported as such, and
// the caller keeps the name it had.

// Resolve maps a possibly-virtual package name to the real package that provides it. The second
// return says whether a DIFFERENT name was found; an error means the question could not be asked.
func (m Manager) Resolve(ctx context.Context, name string) (string, bool, error) {
	if !ValidPkgName(name) {
		return "", false, fmt.Errorf("pm: refusing unsafe package name %q", name)
	}
	switch m.Kind {
	case Opkg:
		out, err := m.run(ctx, "opkg", "whatprovides", name)
		if err != nil {
			return "", false, fmt.Errorf("pm: whatprovides %s: %w", name, err)
		}
		if p := parseWhatProvides(out, name); p != "" {
			return p, true, nil
		}
		return "", false, nil
	case Apk:
		// apk has the same trap, measured on the AX3000T:
		//
		//	apk list   libustream-openssl  ->  (empty)
		//	apk search --exact libustream-openssl -> libustream-openssl20201210-2026.03.01~99f1c0db-r1
		//
		// so the feed-existence check would refuse an install apk can perform, exactly as it did on
		// opkg. `--exact` is NOT exact, which is the second measured surprise: `apk search --exact
		// sing-box` returns sing-box-1.12.17-r1 AND sing-box-tiny-1.12.17-r1. Taking the first line
		// would be right there only by luck.
		//
		// The rule that survives both samples: if any returned package's BARE name equals the name
		// asked about, the name is real and needs no resolution; only when none does is it virtual,
		// and then the first line is the provider.
		out, err := m.run(ctx, "apk", "search", "--exact", name)
		if err != nil {
			return "", false, fmt.Errorf("pm: search %s: %w", name, err)
		}
		var first string
		for _, ln := range strings.Split(out, "\n") {
			ln = strings.TrimSpace(ln)
			if ln == "" {
				continue
			}
			bare, _ := SplitApkOwner(ln)
			if bare == name {
				return "", false, nil // the name is a real package
			}
			if first == "" && ValidPkgName(bare) {
				first = bare
			}
		}
		if first != "" {
			return first, true, nil
		}
		return "", false, nil
	default:
		return "", false, fmt.Errorf("pm: no package manager detected")
	}
}

// parseWhatProvides reads opkg's answer:
//
//	What provides sing-box
//	    sing-box-go
//
// The header line is skipped by requiring a valid package token, and a provider identical to the
// name asked about is not a resolution — it is the same package, and reporting it as a redirect
// would make the caller think it had learned something.
func parseWhatProvides(out, asked string) string {
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "What provides") {
			continue
		}
		// opkg can list several providers; the first is the one it would install.
		if f := strings.Fields(ln); len(f) > 0 && ValidPkgName(f[0]) && f[0] != asked {
			return f[0]
		}
	}
	return ""
}
