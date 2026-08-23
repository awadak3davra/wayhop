#!/bin/sh
# check-feed-index.sh — run the real feed indexer over a real packed .ipk.
#
# make-index.sh lifts each package's control metadata into the signed `Packages` index that opkg
# downloads, and feed.yml calls it on the release path. It read the container with `ar`, which was
# correct for the archive the packer used to emit and wrong from the moment that packer was
# corrected — a reader and a writer of the same format, changed one at a time. Nothing caught it,
# because no gate had ever run the indexer at all; the first sign would have been a published feed
# whose index was empty or absent.
#
# So this packs with the shipped packer and indexes with the shipped indexer, then checks the index
# against the file it describes. The malformed cases are the point: an .ipk this indexer cannot read
# must stop the run, not yield an index that quietly describes nothing.
#
# Both halves run in a pinned Debian image with GNU tar already present. The malformed ar fixture is
# emitted directly from the archive header below, so the gate performs no networked package install.
#
# Needs Docker and Go. Without either this exits 3 and says so — an indexer nobody ran must not
# report as one that passed.
set -eu

BUILDER_IMAGE="${WAYHOP_FEED_BUILDER_IMAGE:-debian:12@sha256:813017f3d62be4b5891a7acca6a01bdcd4b8513daa81b1ab99d3a50385b26931}"
INDEX_IMAGE="${WAYHOP_FEED_INDEX_IMAGE:-debian:12@sha256:813017f3d62be4b5891a7acca6a01bdcd4b8513daa81b1ab99d3a50385b26931}"

command -v docker >/dev/null 2>&1 || { echo "no docker — the feed index was NOT exercised" >&2; exit 3; }
docker info >/dev/null 2>&1 || { echo "docker is not running — the feed index was NOT exercised" >&2; exit 3; }
command -v go >/dev/null 2>&1 || { echo "no go toolchain on PATH" >&2; exit 2; }

# Git Bash hands the daemon a mount source it cannot resolve; both are no-ops on a Linux runner.
hostpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf %s "$1"; fi; }

work=$(mktemp -d)

# The containers write into $work as root, so on Linux the files come back root-owned and the
# invoking user cannot remove them. Hand them back, and never let cleanup decide the verdict: with
# `set -e` a failing command in an EXIT trap becomes the script's exit status.
cleanup() {
  st=$?
  MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker run --rm -v "$(hostpath "$work"):/w" \
    "$BUILDER_IMAGE" chown -R "$(id -u):$(id -g)" /w >/dev/null 2>&1 || :
  rm -rf "$work" 2>/dev/null || :
  exit "$st"
}
trap cleanup EXIT

echo "building usigntool for the indexing host"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$work/usigntool" ./packaging/feed/usigntool

echo "packing one real .ipk and two an indexer must refuse"
MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker run --rm \
  -v "$(hostpath "$PWD"):/src:ro" -v "$(hostpath "$work"):/w" -w /w "$BUILDER_IMAGE" sh -euc '
  cp -r /src/packaging /w/packaging
  printf "#!/bin/true\n" > /w/dummy-bin
  SOURCE_DATE_EPOCH=0 sh /w/packaging/feed/pack-ipk.sh /w/dummy-bin 1.0.0 1 /w/packed x86_64 >/dev/null

  # the feed under test: one real package, plus a token directory with nothing in it
  mkdir -p /w/feed/ipk/x86_64 /w/feed/ipk/mips_24kc
  cp /w/packed/x86_64/*.ipk /w/feed/ipk/x86_64/

  # fault 1 — the container this indexer used to be paired with. Same three members, ar instead of
  # tar: exactly what the packer emitted before it was corrected.
  mkdir -p /w/ar-feed/ipk/x86_64
  mkdir /w/unpacked && cd /w/unpacked && tar -xzf /w/packed/x86_64/*.ipk
  ar_member() {
    file="$1"; name="$2"; size="$(wc -c < "$file" | tr -d " ")"
    printf "%-16s%-12s%-6s%-6s%-8s%-10s\140\n" "$name/" 0 0 0 100644 "$size"
    cat "$file"
    [ $((size % 2)) -eq 0 ] || printf "\n"
  }
  {
    printf "!<arch>\n"
    ar_member debian-binary debian-binary
    ar_member control.tar.gz control.tar.gz
    ar_member data.tar.gz data.tar.gz
  } > /w/ar-feed/ipk/x86_64/wayhop_1.0.0-1_x86_64.ipk

  # fault 2 — right container, no control member. The metadata the index is made of is simply absent.
  mkdir -p /w/noctl-feed/ipk/x86_64
  cd /w/unpacked && tar -czf /w/noctl-feed/ipk/x86_64/wayhop_1.0.0-1_x86_64.ipk ./debian-binary ./data.tar.gz
' >/dev/null

out=$(MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker run --rm -v "$(hostpath "$work"):/w" "$INDEX_IMAGE" sh -euc '
  fail=0
  ok() { echo "  PASS  $1"; }
  no() { echo "  FAIL  $1"; fail=$((fail + 1)); }

  chmod +x /w/usigntool
  /w/usigntool genkey -pub /w/key.pub -sec /w/key.sec >/dev/null
  /w/usigntool genkey -pub /w/wrong.pub -sec /w/wrong.sec >/dev/null

  idx() { sh /w/packaging/feed/make-index.sh "$1" /w/key.sec "${2:-/w/key.pub}" /w/usigntool; }

  idx /w/feed >/w/run.log 2>&1 && ok "the indexer ran over a real packed .ipk" \
    || { echo "  FAIL  the indexer failed on a real packed .ipk"; sed "s/^/        /" /w/run.log; exit 1; }

  P=/w/feed/ipk/x86_64/Packages
  ipk=$(ls /w/feed/ipk/x86_64/*.ipk)

  [ -f "$P" ] && ok "an index was written for the token that has a package" || no "no index was written"
  grep -q "^Package: wayhop$" "$P" && ok "the index names the package" || no "the index does not name the package"

  # The three fields opkg uses to fetch and trust the file. Each is compared to the file on disk,
  # not to another line of the index — an index consistent only with itself proves nothing.
  want_name=$(basename "$ipk")
  got_name=$(grep "^Filename: " "$P" | head -n1 | cut -d" " -f2)
  [ "$got_name" = "$want_name" ] && ok "Filename points at the package on disk" || no "Filename is $got_name, the file is $want_name"

  want_sz=$(wc -c < "$ipk" | tr -d " ")
  got_sz=$(grep "^Size: " "$P" | head -n1 | cut -d" " -f2)
  [ "$got_sz" = "$want_sz" ] && ok "Size matches the package byte count" || no "Size is $got_sz, the file is $want_sz"

  want_sha=$(sha256sum "$ipk" | cut -d" " -f1)
  got_sha=$(grep "^SHA256sum: " "$P" | head -n1 | cut -d" " -f2)
  [ "$got_sha" = "$want_sha" ] && ok "SHA256sum matches the package" || no "SHA256sum does not match the package"

  # A wrong checksum must be visible AS wrong: prove the comparison above can fail.
  printf "x" >> "$ipk"
  [ "$(sha256sum "$ipk" | cut -d" " -f1)" != "$got_sha" ] && ok "the checksum check reacts to a changed byte" \
    || no "the checksum did not change when the package did"
  truncate -s -1 "$ipk"

  [ -f "$P.gz" ] && ok "the gzipped index exists" || no "no gzipped index"
  gzip -cd "$P.gz" | cmp -s - "$P" && ok "the gzipped index is the index" || no "the gzipped index differs from the index"

  [ -f "$P.sig" ] && ok "the index is signed" || no "the index is not signed"
  /w/usigntool verify -pub /w/key.pub -m "$P" -sig "$P.sig" >/dev/null 2>&1 \
    && ok "the signature verifies against the key that made it" || no "the signature does not verify"

  # The production indexer receives the public key that devices download. It must fail in the
  # signing step itself if the configured secret belongs to a different key, before publication.
  cp -a /w/feed /w/wrong-key-feed
  if idx /w/wrong-key-feed /w/wrong.pub >/w/wrong-key.log 2>&1; then
    no "the indexer accepted a signing key that does not match the published public key"
  else
    ok "a signing/public-key mismatch stops the indexer"
  fi
  [ ! -e /w/wrong-key-feed/ipk/x86_64/Packages.sig ] \
    && ok "a key mismatch leaves no publishable signature" || no "a key mismatch left a Packages.sig behind"

  mkdir -p /w/empty-feed/ipk/x86_64
  if idx /w/empty-feed >/w/empty.log 2>&1; then
    no "an empty feed was accepted as a signed publication"
  else
    ok "a feed with zero package indexes is refused"
  fi

  # Signing something else must not verify, or the check above is satisfied by anything.
  printf "tampered\n" >> "$P"
  /w/usigntool verify -pub /w/key.pub -m "$P" -sig "$P.sig" >/dev/null 2>&1 \
    && no "the signature verified over a modified index" || ok "a modified index fails verification"

  [ ! -e /w/feed/ipk/mips_24kc/Packages ] && ok "a token with no package gets no index" \
    || no "a token with no package got an index anyway"

  # --- the malformed containers. Each must stop the run and say why. ---
  if idx /w/ar-feed >/w/ar.log 2>&1; then
    no "an .ipk in the old ar container was accepted"
  else
    ok "an .ipk in the old ar container is refused"
    grep -q "the package format and this indexer disagree" /w/ar.log \
      && ok "the refusal names the format disagreement" || no "the refusal does not say what was wrong"
  fi
  [ ! -e /w/ar-feed/ipk/x86_64/Packages ] || [ ! -s /w/ar-feed/ipk/x86_64/Packages ] \
    && ok "no usable index was left behind for the unreadable package" \
    || no "an index was written for a package that could not be read"

  if idx /w/noctl-feed >/w/noctl.log 2>&1; then
    no "an .ipk with no control member was accepted"
  else
    ok "an .ipk with no control member is refused"
  fi

  [ "$fail" = 0 ]
') || {
  echo "$out"
  echo "the feed index gate failed" >&2
  exit 1
}
echo "$out"
n=$(echo "$out" | grep -c '  PASS ')
echo "feed index: $n checks on a real packed .ipk — metadata, signature, and two containers it must refuse"
