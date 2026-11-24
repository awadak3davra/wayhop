package initserver

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// SingBoxPin is the sing-box release a router resolved over api.github.com for a server it sets
// up or updates: the version and the sha256 of each linux tarball the script may fetch. With a
// pin the server installs exactly that build and checks it; without one it asks api.github.com
// itself and takes the digest from the same answer. A download the script cannot check is not
// installed: the mirror chain (wr_fetch) exists for servers that cannot reach GitHub, and a
// mirror is exactly who could serve a different binary to a root install.
type SingBoxPin struct {
	Version string
	SHA256  map[string]string // "amd64" | "arm64" | "armv7" -> lowercase hex
}

var (
	pinVerRe = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	pinSumRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// SingBoxArches are the server architectures the install scripts map to sing-box tarballs.
var SingBoxArches = []string{"amd64", "arm64", "armv7"}

// PinFromAssets builds a pin from a release tag and its assets' (name, "sha256:<hex>") pairs, as
// api.github.com reports them. It is nil when the tag is not a plain x.y.z or no linux tarball of
// the three architectures carries a digest: no pin, and the server falls back to its own lookup.
func PinFromAssets(tag string, digests map[string]string) *SingBoxPin {
	ver := strings.TrimPrefix(strings.TrimSpace(tag), "v")
	if !pinVerRe.MatchString(ver) {
		return nil
	}
	p := &SingBoxPin{Version: ver, SHA256: map[string]string{}}
	for _, a := range SingBoxArches {
		d := strings.ToLower(strings.TrimSpace(digests[fmt.Sprintf("sing-box-%s-linux-%s.tar.gz", ver, a)]))
		if sum, ok := strings.CutPrefix(d, "sha256:"); ok && pinSumRe.MatchString(sum) {
			p.SHA256[a] = sum
		}
	}
	if len(p.SHA256) == 0 {
		return nil
	}
	return p
}

// shell renders the pin as shell assignments the install helper reads. Only validated values are
// emitted (x.y.z and 64 hex digits), so nothing from a release listing reaches the remote shell
// unchecked; an invalid or nil pin renders nothing.
func (p *SingBoxPin) shell() string {
	if p == nil || !pinVerRe.MatchString(p.Version) {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "SB_PIN_VER='%s'\n", p.Version)
	arches := make([]string, 0, len(p.SHA256))
	for a := range p.SHA256 {
		arches = append(arches, a)
	}
	sort.Strings(arches)
	for _, a := range arches {
		if pinSumRe.MatchString(p.SHA256[a]) && (a == "amd64" || a == "arm64" || a == "armv7") {
			fmt.Fprintf(&b, "SB_PIN_SHA_%s='%s'\n", a, p.SHA256[a])
		}
	}
	return b.String()
}

// sbDigestFromAPI is the shell pipeline that reads the sha256 of one tarball from a release JSON
// api.github.com returned (pretty-printed: an asset's "name" line comes before its "digest" line).
// $1 is the JSON, $2 the asset name. It prints the hex or nothing.
const sbDigestFromAPI = `wr_sb_digest() {
  printf '%s\n' "$1" | sed -n "/\"name\": *\"$2\"/,/\"digest\"/p" | grep -o 'sha256:[0-9a-f]*' | head -1 | cut -d: -f2
}
`

// singBoxInstallShell defines wr_sb_install: install sing-box from the official release after
// checking its sha256, taking the version and digest from the router's pin when there is one and
// from api.github.com otherwise. Without a 64-hex digest it refuses.
const singBoxInstallShell = sbDigestFromAPI + `wr_sb_install() {
  apt-get install -y curl tar >/dev/null 2>&1 || true
  A=$(dpkg --print-architecture 2>/dev/null || echo amd64)
  case "$A" in amd64) SB=amd64;; arm64) SB=arm64;; armhf) SB=armv7;; *) SB=amd64;; esac
  VER="${SB_PIN_VER:-}"
  case "$SB" in amd64) SUM="${SB_PIN_SHA_amd64:-}";; arm64) SUM="${SB_PIN_SHA_arm64:-}";; *) SUM="${SB_PIN_SHA_armv7:-}";; esac
  if [ -z "$VER" ]; then
    J=$(curl -fsS https://api.github.com/repos/SagerNet/sing-box/releases/latest 2>/dev/null || true)
    VER=$(printf '%s\n' "$J" | grep -o '"tag_name":[^,]*' | head -1 | sed 's/.*"v\{0,1\}\([0-9][^"]*\)".*/\1/')
    [ -z "$VER" ] || SUM=$(wr_sb_digest "$J" "sing-box-${VER}-linux-${SB}.tar.gz")
    # GitHub API blocked from this server? fall back to the releases atom feed (proxiable by
    # wr_fetch's mirror chain), taking the newest STABLE tag (skip -alpha/-beta/-rc suffixes).
    [ -n "$VER" ] || VER=$(wr_fetch https://github.com/SagerNet/sing-box/releases.atom 2>/dev/null | grep -o 'releases/tag/v[0-9][^"<]*' | sed 's@releases/tag/v@@' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
  fi
  [ -n "$VER" ] || { log "failed to resolve sing-box version (GitHub API + mirror both failed)"; return 1; }
  [ ${#SUM} -eq 64 ] || { log "no sha256 for sing-box ${VER} (${SB}): neither the router nor api.github.com gave one, and a binary nobody can check is not installed"; return 1; }
  wr_fetch "https://github.com/SagerNet/sing-box/releases/download/v${VER}/sing-box-${VER}-linux-${SB}.tar.gz" /tmp/sb.tgz || { log "failed to download sing-box ${VER}"; return 1; }
  echo "${SUM}  /tmp/sb.tgz" | sha256sum -c - >/dev/null 2>&1 || { log "the sing-box ${VER} download does not match its sha256 - refusing it"; rm -f /tmp/sb.tgz; return 1; }
  tar -xzf /tmp/sb.tgz -C /tmp || { log "failed to extract sing-box archive"; return 1; }
  install -m755 "/tmp/sing-box-${VER}-linux-${SB}/sing-box" /usr/local/bin/sing-box
  rm -rf /tmp/sb.tgz "/tmp/sing-box-${VER}-linux-${SB}" 2>/dev/null || true
}
`
