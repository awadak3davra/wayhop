#!/bin/sh
# check-package-manifests.sh — the package guarantees, pinned.
#
# OpenWrt 25.12 is advertised as supported and its packages are what an operator installs, upgrades
# and removes. The properties below are what makes that safe, and every one of them is currently
# correct — which is exactly why they need pinning: each is one edit away from silently going, and
# the failure surfaces on someone's router, once, as a lost config or a service that never comes back.
#
# What is asserted, per flavour (opkg .ipk, apk, Entware):
#   - the binary lands at the documented path, executable;
#   - the procd init lands at /etc/init.d/wayhop, executable, and post-install enables it;
#   - the payload does NOT contain the config tree — protection by omission, so neither an upgrade
#     nor a remove can touch /etc/wayhop, because the package does not own it;
#   - post-install seeds a config only when one is ABSENT, and at 0600;
#   - pre-install refuses a legacy upgrade before package extraction unless an authenticated Apply
#     checkpoint already exists; a proven-fresh install initializes an explicit-empty checkpoint;
#   - pre-remove stops and disables the service and deletes no user config;
#   - the sysupgrade keep entry ships, so a firmware flash does not take the config with it.
#
# Usage: check-package-manifests.sh [root]   (root defaults to the repo root, so the fault tests can
#                                             point it at a mutated copy)
set -eu

ROOT="${1:-.}"
F="$ROOT/packaging/feed"
[ -d "$F" ] || { echo "check-package-manifests: $F is not there — nothing to audit" >&2; exit 2; }

fails=0
checked=0
# A file that is not there means the packaging LAYOUT moved, which is a different answer from a
# guarantee being broken: this audit cannot speak about a tree it does not recognise, and saying
# "27 broken" about a missing directory would be a verdict it has no basis for.
missing=0
ok_()  { checked=$((checked + 1)); echo "  ok    $1"; }
bad_() { checked=$((checked + 1)); fails=$((fails + 1)); echo "  FAIL  $1" >&2; }

# want <file> <label> <pattern>   — the file must contain the pattern
want() {
  f="$F/$1"; label="$2"; pat="$3"
  if [ ! -f "$f" ]; then missing=$((missing + 1)); bad_ "$label: $1 is missing"; return; fi
  if grep -q -- "$pat" "$f"; then ok_ "$label"; else bad_ "$label  [$1 has no /$pat/]"; fi
}

# reject <file> <label> <pattern> — the file must NOT contain the pattern
reject() {
  f="$F/$1"; label="$2"; pat="$3"
  if [ ! -f "$f" ]; then missing=$((missing + 1)); bad_ "$label: $1 is missing"; return; fi
  if grep -q -- "$pat" "$f"; then bad_ "$label  [$1 matches /$pat/]"; else ok_ "$label"; fi
}

# want_root <path> <label> <pattern> — assertions outside packaging/feed (direct tar installers and
# local packagers) use the same fail-closed accounting.
want_root() {
  f="$ROOT/$1"; label="$2"; pat="$3"
  if [ ! -f "$f" ]; then missing=$((missing + 1)); bad_ "$label: $1 is missing"; return; fi
  if grep -q -- "$pat" "$f"; then ok_ "$label"; else bad_ "$label  [$1 has no /$pat/]"; fi
}

echo "package manifests under $ROOT:"

# --- the binary and the init script land where the docs and the installers say -----------------
want pack-ipk.sh      'ipk: binary installed 0755 at /usr/sbin/wayhop'   'install -m0755 "\$BIN"  *"\$work/data/usr/sbin/wayhop"'
want pack-ipk.sh      'ipk: procd init installed 0755'                   'install -m0755 "\$INIT" *"\$work/data/etc/init.d/wayhop"'
want pack-apk.sh      'apk: binary staged away from the live path'       'usr/libexec/wayhop/wayhop'
reject pack-apk.sh    'apk: payload cannot overwrite the live binary before pre-install' 'root/usr/sbin/wayhop'
want postinst.apk     'apk: post-install publishes the gated payload'    'usr/sbin/wayhop.new'
want postupgrade.apk  'apk: post-upgrade publishes the gated payload'    'usr/sbin/wayhop.new'
want pack-apk.sh      'apk: procd init staged'                           'etc/init.d/wayhop'
want pack-entware.sh  'entware: binary staged'                           'wayhop'

# --- direct tar deployment must retain a verified rollback and its identity checker ------------
want_root packaging/install.sh 'Entware tar: rollback backup is staged atomically' 'wayhop.bak.new'
want_root packaging/install.sh 'Entware tar: rollback backup is byte-verified'      'cmp -s.*wayhop.bak.new'
want_root packaging/openwrt/install.sh 'OpenWrt tar: rollback backup is staged atomically' 'wayhop.bak.new'
want_root packaging/openwrt/install.sh 'OpenWrt tar: rollback backup is byte-verified'      'cmp -s.*wayhop.bak.new'
want_root Makefile 'Make package: bundles the identity verifier' 'identity-match.sh'
want_root Makefile 'Make package: bundles the IPTV retirement migration' 'retire-iptv.sh'
want_root build.ps1 'Windows package: bundles the identity verifier' 'identity-match.sh'
want_root build.ps1 'Windows package: bundles the IPTV retirement migration' 'retire-iptv.sh'

# --- apply state: an upgrade needs no ritual, and the scripts must not invent one -----------------
# The daemon imports whatever applied state it finds on first start, so a package script that made an
# upgrade conditional on a pre-existing record would refuse a router that is perfectly upgradable.
# The pre-install hooks stay in the control set (shape stability); they must stay inert.
want pack-ipk.sh      'ipk: ships a pre-install hook'      'control/preinst'
want pack-entware.sh  'entware: ships a pre-install hook'  'control/preinst'
want pack-apk.sh      'apk: pre-install hook is wired'      'pre-install:$HERE/preinst'
want pack-apk.sh      'apk: pre-upgrade hook is wired'      'pre-upgrade:$HERE/preinst'
for p in preinst preinst.entware postinst postinst.apk postinst.entware; do
  reject "$p" "$p: does not gate on a previous-generation ledger" 'apply-ledger-v1'
  reject "$p" "$p: does not run a removed ledger command"         '\-\-[a-z-]*-ledger'
done

# --- installers may only pass flags the binary actually defines ----------------------------------
# The loop above lists the flags we remembered to remove, in the five files we remembered to check.
# That is the wrong shape, and it cost us: packaging/openwrt/install.sh went on calling two removed
# ledger flags long after the rest was fixed. Nothing caught it, because a shell script that calls a
# nonexistent flag builds fine and unit-tests fine - Go's flag package exits 2, so the install dies
# half-done on a real router, binary and config in place and the service never started.
# So derive the permitted set from main.go instead of listing the forbidden one, and check every
# script that runs the binary. A flag removed from main.go now reddens this the same day.
MAIN_GO="$ROOT/cmd/wayhop/main.go"
FLAGS_DEFINED=" $(echo $([ -f "$MAIN_GO" ] && grep -oE 'flag[.][A-Za-z]+[(]"[a-z-]+"' "$MAIN_GO" |
  grep -oE '"[a-z-]+"' | tr -d '"')) "
# Fail closed on an absent or unparseable main.go rather than deriving an empty permitted set: an
# empty set would redden every script at once, which reads as a mass failure instead of "the gate
# lost its subject", and a pattern that silently stopped matching would do the same the day the flag
# block is rewritten.
if [ "$FLAGS_DEFINED" = "  " ]; then
  missing=$((missing + 1))
  bad_ "installer flags: cmd/wayhop/main.go is missing or defines no flags"
else
for s in packaging/install.sh packaging/openwrt/install.sh packaging/feed/preinst          packaging/feed/preinst.entware packaging/feed/postinst packaging/feed/postinst.apk          packaging/feed/postinst.entware; do
  f="$ROOT/$s"
  if [ ! -f "$f" ]; then missing=$((missing + 1)); bad_ "installer flags: $s is missing"; continue; fi
  undefined=""
  for u in $(grep -E '(wayhop|[$]BIN|[$]SBIN/wayhop)"? +--' "$f" | grep -oE ' --[a-z][a-z-]*' |
             sed 's/ --//' | sort -u); do
    case "$FLAGS_DEFINED" in *" $u "*) ;; *) undefined="$undefined --$u" ;; esac
  done
  if [ -n "$undefined" ]; then
    bad_ "installer flags: $s passes flag(s) main.go does not define:$undefined"
  else
    ok_ "installer flags: $s passes only flags main.go defines"
  fi
done
fi

# --- protection by omission: the package must not own the config tree ---------------------------
# This is the whole reason an upgrade cannot clobber a config and a remove cannot delete one. Both
# packers carry a build-time guard; losing it would not fail anything until a user lost their setup.
want pack-ipk.sh 'ipk: refuses a payload containing the config tree'  'REFUSING to build'
want pack-apk.sh 'apk: refuses a payload containing the config tree'  'REFUSING to build'

# --- post-install seeds only what is absent, at 0600 --------------------------------------------
for p in postinst postinst.apk postinst.entware; do
  want "$p" "$p: seeds a config only when none exists" '\[ ! -f'
  want "$p" "$p: the seeded config is 0600"            'chmod 0600'
done
want postinst         'ipk: post-install enables the service'      'enable'
want postinst.apk     'apk: post-install enables the service'      'enable'
want postinst.entware 'entware: post-install registers the init'   'S99wayhop'

# --- the init script does not invent who started the daemon ------------------------------------
# rc.unslung passes its own second argument through, and on KeeneticOS the firmware starts Entware
# with none — so a default of "manual" logged every BOOT start as a human's doing. Read back from
# a live Keenetic native log: "Started WayHop from manual." for a start nobody performed.
# An operator diagnosing an unexpected restart is reading exactly this line.
want_root packaging/S99wayhop 'init: an unnamed caller stays unnamed'      'CALLER=${2:-}'
want_root packaging/S99wayhop 'init: the agent is appended only when known' 'FROM=${CALLER:+ from $CALLER}'
want_root packaging/S99wayhop 'init: the start line carries that suffix'    'Started $DESC$FROM'

# --- every install path repairs historical world-readable state without sweeping operator files --
want_root packaging/harden-state.sh 'state migration: state/data roots become 0700' 'chmod 0700 "\$_path"'
want_root packaging/harden-state.sh 'state migration: known secret files become 0600' 'chmod 0600 "\$_path"'
want_root packaging/harden-state.sh 'state migration: legacy data-root profiles are protected' 'DATA_ROOT/profile.json'
want_root packaging/harden-state.sh 'state migration: only generated backup names are selected' 'wayhop-backup-.*\.json'
want_root packaging/harden-state.sh 'state migration: symlinks are refused' '\[ -L'
want pack-ipk.sh     'ipk: ships the state migration helper'     'usr/libexec/wayhop/harden-state.sh'
want pack-apk.sh     'apk: ships the state migration helper'     'usr/libexec/wayhop/harden-state.sh'
want pack-entware.sh 'entware: ships the state migration helper' 'opt/libexec/wayhop/harden-state.sh'
want postinst        'ipk: post-install runs the state migration' '/usr/libexec/wayhop/harden-state.sh /etc/wayhop /var/lib/wayhop'
want postinst.apk    'apk: post-install runs the state migration' '/usr/libexec/wayhop/harden-state.sh /etc/wayhop /var/lib/wayhop'
want postupgrade.apk 'apk: post-upgrade runs the state migration' '/usr/libexec/wayhop/harden-state.sh /etc/wayhop /var/lib/wayhop'
want postinst.entware 'entware: post-install runs the state migration' '/opt/libexec/wayhop/harden-state.sh'
want_root packaging/install.sh 'Entware tar: installer runs the state migration' 'harden-state.sh.*"\$ETC" "\$VAR"'
want_root packaging/openwrt/install.sh 'OpenWrt tar: installer runs the state migration' 'harden-state.sh.*"\$ETC" "\$VAR"'
want_root Makefile 'Make package: bundles the state migration' 'harden-state.sh'
want_root build.ps1 'Windows package: bundles the state migration' 'harden-state.sh'

# --- pre-remove stops the service and keeps the operator's config -------------------------------
for p in prerm prerm.apk prerm.entware; do
  want   "$p" "$p: stops the service"                    'stop'
  reject "$p" "$p: does not delete the config directory" 'rm .*-r.*/etc/wayhop'
  reject "$p" "$p: does not delete config.json"          'rm .*config\.json'
done

# --- a firmware sysupgrade must not take the config with it -------------------------------------
want pack-ipk.sh 'ipk: ships the sysupgrade keep entry' 'lib/upgrade/keep.d'
# ...and refuses to build without it: the else-branch below catches the file going missing from
# the REPO, but only the packer itself can catch it missing from a build context (a partial
# checkout, a tarball build) - pack-apk has failed closed all along, pack-ipk now matches.
want pack-ipk.sh 'ipk: refuses to build without the keep list' 'keep file not found'
if [ -f "$ROOT/packaging/openwrt/wayhop.keep" ]; then
  if grep -q '/etc/wayhop' "$ROOT/packaging/openwrt/wayhop.keep"; then
    ok_ 'the keep list names the config directory'
  else
    bad_ 'the keep list does not name /etc/wayhop, so a sysupgrade would drop it'
  fi
else
  bad_ 'packaging/openwrt/wayhop.keep is missing, so a sysupgrade would drop the config'
fi

# A run that asserted nothing is not a pass: it means the layout moved and every check above was
# skipped rather than satisfied.
if [ "$missing" -gt 0 ] || [ "$checked" -lt 55 ]; then
  echo "$missing packaging file(s) absent of $checked assertion(s) — the layout moved, so this audit
cannot say whether the guarantees hold" >&2
  exit 2
fi
if [ "$fails" -gt 0 ]; then
  echo "$fails of $checked package guarantee(s) broken" >&2
  exit 1
fi
echo "package manifests: $checked guarantees hold across opkg, apk and Entware"
