package initserver

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// HardenKeysScript generates a fresh ed25519 SSH keypair ON THE SERVER, installs
// the public key into the target user's authorized_keys, and prints the private
// key (base64) so wayhop can hand it back for the user to download. It does NOT touch
// password auth — that is a separate, gated step (HardenLockdownScript) run only
// after the user has saved the key and key-auth is confirmed working.
func HardenKeysScript(user string) string {
	if user == "" {
		user = "root"
	}
	return fmt.Sprintf(`#!/bin/sh
set -e
log() { echo "[wayhop-harden] $*"; }
TARGET_USER=%q
HOME_DIR=$(getent passwd "$TARGET_USER" 2>/dev/null | cut -d: -f6)
[ -n "$HOME_DIR" ] || HOME_DIR="$HOME"
log "installing key for $TARGET_USER ($HOME_DIR)"
mkdir -p "$HOME_DIR/.ssh"; chmod 700 "$HOME_DIR/.ssh"
TMPD=$(mktemp -d); trap 'rm -rf "$TMPD"' EXIT INT TERM
KF="$TMPD/key"
ssh-keygen -t ed25519 -N '' -C 'wayhop-managed' -f "$KF" >/dev/null
touch "$HOME_DIR/.ssh/authorized_keys"
cat "$KF.pub" >> "$HOME_DIR/.ssh/authorized_keys"
sort -u "$HOME_DIR/.ssh/authorized_keys" -o "$HOME_DIR/.ssh/authorized_keys"
chmod 600 "$HOME_DIR/.ssh/authorized_keys"
chown -R "$TARGET_USER" "$HOME_DIR/.ssh" 2>/dev/null || true
echo "WR_SSH_PUB=$(cat "$KF.pub")"
echo "WR_SSH_KEY_B64=$(base64 -w0 < "$KF" 2>/dev/null || base64 < "$KF" | tr -d '\n')"
log "key installed into authorized_keys"
`, user)
}

// HardenLockdownScript disables SSH password authentication and ensures pubkey
// auth is on, then reloads sshd. DESTRUCTIVE: only safe once a working key is
// installed and saved. Also drops a sshd_config.d override so cloud-init images
// don't silently re-enable passwords.
const HardenLockdownScript = `#!/bin/sh
set -e
log() { echo "[wayhop-harden] $*"; }
SSHD=/etc/ssh/sshd_config
[ -f "$SSHD" ] || { echo "WR_HARDEN_ERR=no sshd_config"; exit 1; }
cp "$SSHD" "$SSHD.wayhop.bak" 2>/dev/null || true
sed -i 's/^[#[:space:]]*PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD"
grep -q '^PasswordAuthentication no' "$SSHD" || echo 'PasswordAuthentication no' >> "$SSHD"
sed -i 's/^[#[:space:]]*PubkeyAuthentication.*/PubkeyAuthentication yes/' "$SSHD"
grep -q '^PubkeyAuthentication yes' "$SSHD" || echo 'PubkeyAuthentication yes' >> "$SSHD"
if [ -d /etc/ssh/sshd_config.d ]; then
  printf 'PasswordAuthentication no\nPubkeyAuthentication yes\n' > /etc/ssh/sshd_config.d/00-wayhop-hardening.conf
fi
if command -v sshd >/dev/null 2>&1; then sshd -t || { echo "WR_HARDEN_ERR=sshd config test failed"; exit 1; }; fi
( systemctl reload sshd || systemctl reload ssh || service ssh reload || service sshd reload ) 2>/dev/null || true
echo "WR_HARDEN_OK=1"
log "password auth disabled; pubkey auth enforced"
`

// ExtractSSHKey pulls the private key (decoded from WR_SSH_KEY_B64) and the
// public key (WR_SSH_PUB) the harden-keys script printed.
func ExtractSSHKey(output string) (priv, pub string) {
	for _, ln := range strings.Split(output, "\n") {
		ln = strings.TrimSpace(ln)
		if v, ok := strings.CutPrefix(ln, "WR_SSH_KEY_B64="); ok {
			if b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v)); err == nil {
				priv = string(b)
			}
		}
		if v, ok := strings.CutPrefix(ln, "WR_SSH_PUB="); ok {
			pub = strings.TrimSpace(v)
		}
	}
	return priv, pub
}

// LockdownConfirmed reports whether the lockdown script signalled success.
func LockdownConfirmed(output string) bool {
	return strings.Contains(output, "WR_HARDEN_OK=1")
}
