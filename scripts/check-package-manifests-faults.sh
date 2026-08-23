#!/bin/sh
# check-package-manifests-faults.sh — does the manifest audit actually catch a broken guarantee?
#
# The audit passes today because the packaging is correct, and a passing audit over correct input
# proves nothing about the audit. Each case here copies the packaging tree, breaks exactly one
# guarantee, and requires a refusal. If any of these pass, the audit is decoration.
set -eu

A="scripts/check-package-manifests.sh"
[ -f "$A" ] || { echo "FAIL  $A is missing — this gate has no subject"; exit 2; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fails=0

fresh() { # $1 = destination root
  rm -rf "$1"
  mkdir -p "$1/packaging"
  cp -r packaging/feed "$1/packaging/feed"
  cp -r packaging/openwrt "$1/packaging/openwrt"
  # S99wayhop is audited too (the init script must not invent who started the daemon), so the
  # fixture has to carry it — without it every case exits 2 ("missing subject") instead of 0/1.
  cp packaging/install.sh packaging/harden-state.sh packaging/S99wayhop "$1/packaging/"
  cp Makefile build.ps1 "$1/"
  # The installers are checked against the flag set main.go actually defines, so the fixture needs
  # it for the same reason it needs S99wayhop: without it every case exits 2 instead of 0/1.
  mkdir -p "$1/cmd/wayhop"
  cp cmd/wayhop/main.go "$1/cmd/wayhop/"
}

case_() { # name expected-exit root
  name="$1"; want="$2"; root="$3"
  got=0
  sh "$A" "$root" >/dev/null 2>&1 || got=$?
  if [ "$got" = "$want" ]; then
    echo "  PASS  $name (exit $got)"
  else
    echo "  FAIL  $name: exit $got, want $want"
    fails=$((fails + 1))
  fi
}

r="$tmp/r"

fresh "$r"
case_ 'an untouched copy passes' 0 "$r"

# An installer calling a CLI flag the daemon does not define builds fine, unit-tests fine, and then
# exits 2 on a real router with the binary already in place. That shipped once: packaging/openwrt
# kept two removed ledger flags after everything else was fixed, because the check listed forbidden
# names instead of deriving the permitted set.
fresh "$r"
sed -i 's#wayhop" --version#wayhop" --initialize-empty-ledger#' "$r/packaging/openwrt/install.sh"
case_ 'an installer calling a flag main.go does not define is refused' 1 "$r"

# ... and the reverse direction: a flag deleted from main.go must redden every script still passing
# it, not quietly widen what counts as valid.
fresh "$r"
sed -i 's/flag.Bool("version"/flag.Bool("wersion"/' "$r/cmd/wayhop/main.go"
case_ 'removing a flag from main.go reddens the installers that pass it' 1 "$r"

# The guarantee that keeps an upgrade from clobbering a config: without the guard, a payload could
# start shipping /etc/wayhop and nothing would notice until someone lost their setup.
fresh "$r"
sed -i 's/REFUSING to build/quietly building/' "$r/packaging/feed/pack-ipk.sh"
case_ 'losing the ipk payload guard is refused' 1 "$r"

fresh "$r"
sed -i 's/REFUSING to build/quietly building/' "$r/packaging/feed/pack-apk.sh"
case_ 'losing the apk payload guard is refused' 1 "$r"

# A pre-remove that deletes the config turns an uninstall into data loss.
fresh "$r"
printf '\nrm -rf /etc/wayhop\n' >> "$r/packaging/feed/prerm"
case_ 'a pre-remove that deletes the config directory is refused' 1 "$r"

fresh "$r"
printf '\nrm -f /etc/wayhop/config.json\n' >> "$r/packaging/feed/prerm.apk"
case_ 'a pre-remove that deletes config.json is refused' 1 "$r"

# Seeding unconditionally overwrites an existing config on every install.
fresh "$r"
sed -i 's/\[ ! -f/[ -e/' "$r/packaging/feed/postinst"
case_ 'seeding without the absent-check is refused' 1 "$r"

fresh "$r"
sed -i 's/chmod 0600/chmod 0644/' "$r/packaging/feed/postinst.apk"
case_ 'a world-readable seeded config is refused' 1 "$r"

fresh "$r"
sed -i 's/chmod 0700/chmod 0755/' "$r/packaging/harden-state.sh"
case_ 'a migration that leaves state roots listable is refused' 1 "$r"

fresh "$r"
sed -i '/DATA_ROOT\/profile.json/d' "$r/packaging/harden-state.sh"
case_ 'dropping legacy data-root profile protection is refused' 1 "$r"

fresh "$r"
sed -i 's#harden-state.sh /etc/wayhop#harden-state-missing.sh /etc/wayhop#' "$r/packaging/feed/postupgrade.apk"
case_ 'dropping the apk upgrade migration is refused' 1 "$r"

# A service that is never enabled comes back from a reboot dead.
fresh "$r"
sed -i 's/enable/disabl3/g' "$r/packaging/feed/postinst"
case_ 'a post-install that stops enabling the service is refused' 1 "$r"

# The binary must keep landing where the installers, the init script and the docs all point.
fresh "$r"
sed -i 's#data/usr/sbin/wayhop#data/usr/bin/wayhop#' "$r/packaging/feed/pack-ipk.sh"
case_ 'moving the binary out of /usr/sbin is refused' 1 "$r"

# The authenticated-upgrade boundary must survive every package format. In particular, apk must
# stage away from the live path because its pre-install hook runs after extraction.
fresh "$r"
sed -i '/control\/preinst/d' "$r/packaging/feed/pack-ipk.sh"
case_ 'dropping the opkg pre-extraction ledger gate is refused' 1 "$r"

fresh "$r"
sed -i 's/pre-upgrade:/pre-upgrade-disabled:/' "$r/packaging/feed/pack-apk.sh"
case_ 'dropping the apk upgrade ledger gate is refused' 1 "$r"

fresh "$r"
sed -i 's#root/usr/libexec/wayhop#root/usr/sbin#' "$r/packaging/feed/pack-apk.sh"
case_ 'letting apk overwrite the live binary before its gate is refused' 1 "$r"

# Direct tar upgrades must never replace the current daemon unless a byte-identical rollback copy
# has been staged. Local packagers must also carry the helper that proves which build answered.
fresh "$r"
sed -i '/cmp -s.*wayhop.bak.new/d' "$r/packaging/install.sh"
case_ 'dropping the Entware rollback verification is refused' 1 "$r"

fresh "$r"
sed -i '/cmp -s.*wayhop.bak.new/d' "$r/packaging/openwrt/install.sh"
case_ 'dropping the OpenWrt rollback verification is refused' 1 "$r"

fresh "$r"
sed -i 's/identity-match\.sh/identity-missing.sh/g' "$r/Makefile"
case_ 'dropping the local-package identity verifier is refused' 1 "$r"

# A firmware sysupgrade wipes the overlay; without the keep entry it takes the config too.
fresh "$r"
rm -f "$r/packaging/openwrt/wayhop.keep"
case_ 'losing the sysupgrade keep list is refused' 1 "$r"

fresh "$r"
sed -i 's#/etc/wayhop##' "$r/packaging/openwrt/wayhop.keep"
case_ 'a keep list that no longer names the config is refused' 1 "$r"

# A tree whose layout moved must be an error, not a pass: every assertion would have been skipped.
mkdir -p "$tmp/empty/packaging/feed"
case_ 'a packaging tree with nothing to audit is an error' 2 "$tmp/empty"

case_ 'a missing packaging tree is an error' 2 "$tmp/nope"

if [ "$fails" -gt 0 ]; then
  echo "$fails manifest-audit case(s) failed"
  exit 1
fi
echo "package manifest faults: 24 cases, including 22 broken guarantees that must be refused"
