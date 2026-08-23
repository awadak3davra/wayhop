#!/bin/sh
# make-index.sh — (re)generate + usign-sign the opkg `Packages` index for every per-token dir under
# the feed root (both the OpenWrt ipk/ tree and the Entware entware/ tree). Pure sh + tar/gzip/
# sha256sum + the bundled usigntool — no perl/opkg-utils needed. The WHOLE index is rebuilt from the
# current package set every run (single-signed-index trust model; never append).
#
# Usage: make-index.sh <feed-root> <usign-sec> <usign-pub> <usigntool-bin>
#   apk indexes (packages.adb) are produced+signed separately inside the apk container (feed.yml).
set -eu
[ "$#" -eq 4 ] || { echo "usage: make-index.sh <feed-root> <usign-sec> <usign-pub> <usigntool-bin>" >&2; exit 2; }
ROOT="$1"; USEC="$2"; UPUB="$3"; UTOOL="$4"
[ -s "$UPUB" ] || { echo "make-index: public verification key is missing or empty: $UPUB" >&2; exit 2; }
verified=0

for d in "$ROOT"/ipk/*/ "$ROOT"/entware/*/; do
  [ -d "$d" ] || continue
  pkgs="${d%/}/Packages"
  : > "$pkgs"
  found=0
  for ipk in "${d%/}"/*.ipk; do
    [ -e "$ipk" ] || continue
    found=1
    tmp="$(mktemp -d)"
    # An .ipk is a gzipped TAR of the three members (see pack-ipk.sh) — `ar p` read the container
    # this indexer used to be paired with, and stopped working the moment the packer was corrected.
    # The member is stored as ./control.tar.gz and must be named that way: a bare `control.tar.gz`
    # matches nothing on either GNU tar or busybox tar, and `--wildcards` is GNU-only.
    # Checked rather than left to `set -e`: an unreadable container aborts the run either way, but
    # the bare pipeline dies on "Unexpected EOF" from the SECOND tar, which describes neither the
    # file at fault nor what is wrong with it.
    if ! tar -xzOf "$ipk" ./control.tar.gz 2>/dev/null | tar -xz -C "$tmp" 2>/dev/null; then
      echo "cannot read $ipk — the package format and this indexer disagree" >&2
      exit 1
    fi
    ctl="$(find "$tmp" -name control -type f | head -n1)"
    [ -n "$ctl" ] || { echo "no control file inside $ipk — the package format and this indexer disagree" >&2; exit 1; }
    sz="$(wc -c < "$ipk" | tr -d ' ')"
    sha="$(sha256sum "$ipk" | cut -d' ' -f1)"
    cat "$ctl" >> "$pkgs"
    printf 'Filename: %s\nSize: %s\nSHA256sum: %s\n\n' "$(basename "$ipk")" "$sz" "$sha" >> "$pkgs"
    rm -rf "$tmp"
  done
  if [ "$found" != 1 ]; then rm -f "$pkgs"; continue; fi
  gzip -9kf "$pkgs"
  sig="${d%/}/Packages.sig"
  "$UTOOL" sign -sec "$USEC" -m "$pkgs" -out "$sig"
  if ! "$UTOOL" verify -pub "$UPUB" -m "$pkgs" -sig "$sig" >/dev/null; then
    rm -f "$sig"
    echo "make-index: signature for $pkgs does not match $UPUB" >&2
    exit 1
  fi
  verified=$((verified + 1))
  echo "  indexed + signed + verified ${d%/}/Packages ($(grep -c '^Package:' "$pkgs") pkgs)"
done
[ "$verified" -gt 0 ] || { echo "make-index: no package index was generated — refusing an empty signed feed" >&2; exit 1; }
