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

// parseOpkgPackageVersion preserves the package revision. Package-manager status must compare the
// exact build in the installed database with the exact build offered by the repository; stripping
// "-r1" made an installed 1.12.17-r1 look older than the same repository build.
func parseOpkgPackageVersion(status string) string {
	for _, ln := range strings.Split(status, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(ln), "Version:"); ok {
			return strings.TrimSpace(v)
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

// parseApkPackageVersion preserves apk's complete version token, including its -rN package
// revision. The first whitespace-delimited token is <package>-<version>; requiring a digit after
// the package prefix prevents a sibling such as sing-box-doc from being mistaken for sing-box.
func parseApkPackageVersion(list, pkg string) string {
	prefix := pkg + "-"
	for _, ln := range strings.Split(list, "\n") {
		ln = strings.TrimSpace(ln)
		rest, ok := strings.CutPrefix(ln, prefix)
		if !ok || rest == "" || rest[0] < '0' || rest[0] > '9' {
			continue
		}
		version, _, _ := strings.Cut(rest, " ")
		version = strings.TrimSpace(version)
		if ValidVersion(version) {
			return version
		}
	}
	return ""
}
