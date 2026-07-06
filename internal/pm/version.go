package pm

import (
	"regexp"
	"strings"
)

// revRe drops the packaging revision suffix (opkg "-rN"/"-N", apk "-rN") so a feed version compares
// to a raw upstream tag: "1.12.22-r1" -> "1.12.22"; "1.19.27-1" -> "1.19.27".
var revRe = regexp.MustCompile(`-r?\d+$`)

func stripRev(v string) string { return revRe.ReplaceAllString(strings.TrimSpace(v), "") }

var verNumRe = regexp.MustCompile(`\d+\.\d+(\.\d+)?`)

// parseOpkgVersion pulls the version from `opkg status` "Version: X" text.
func parseOpkgVersion(status string) string {
	for _, ln := range strings.Split(status, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(ln), "Version:"); ok {
			return stripRev(verNumRe.FindString(v))
		}
	}
	return ""
}

// parseApkVersion pulls the version from `apk list --installed` "<pkg>-<ver> ..." lines.
func parseApkVersion(list, pkg string) string {
	for _, ln := range strings.Split(list, "\n") {
		ln = strings.TrimSpace(ln)
		if rest, ok := strings.CutPrefix(ln, pkg+"-"); ok {
			return stripRev(verNumRe.FindString(rest))
		}
	}
	return stripRev(verNumRe.FindString(list))
}
