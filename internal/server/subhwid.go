package server

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"wayhop/internal/config"
	"wayhop/internal/platform"
)

// Subscription HWID (competitor gap 25). Provider panels with a device limit tie a subscription to the
// device that fetches it: Remnawave reads x-hwid, x-device-os, x-ver-os, x-device-model and user-agent
// (remnawave/backend src/common/utils/extract-hwid-headers/extract-hwid-headers.util.ts), and with its
// limit on answers 404 to a fetch that carries no x-hwid. Happ and v2RayTun send one; WayHop sent none,
// so such a subscription could not be fetched at all.

// hwidPattern is the x-hwid Remnawave accepts. It ignores any other value, which with the device limit
// on is the same 404 as sending none, so the panel refuses such a value instead of storing it.
var hwidPattern = regexp.MustCompile(`^[a-zA-Z0-9=-]{10,64}$`)

// validHWID reports whether v is an x-hwid Remnawave would read.
func validHWID(v string) bool { return hwidPattern.MatchString(v) }

// errStoredHWID is a stored HWID that is not one the provider would read: hand-edited in config.json,
// since the panel, the import and a restore all refuse one. The import (mode "") and the refresh both
// refuse to send it: the provider would ignore it, and a device-limited panel's 404 would then be
// blamed on the provider instead of on the edited value.
var errStoredHWID = errors.New("the stored hwid is not 10 to 64 letters, digits, '=' or '-'")

// newHWID returns 16 random hex digits. Nothing of the router goes into it (no serial, MAC or model):
// the provider learns that one device fetches the subscription, not which hardware it is.
func newHWID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate hwid: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// hwidDeviceOS is the x-device-os sent beside x-hwid: the router platform only. The OS version
// (x-ver-os) and the model (x-device-model) are never sent: the device limit works without them, and
// with them the random ID would come with the firmware and the hardware it runs on.
func hwidDeviceOS(p platform.Platform) string {
	switch p {
	case platform.Keenetic:
		return "KeeneticOS"
	case platform.OpenWrt:
		return "OpenWrt"
	}
	return "Linux"
}

// setSubscriptionHeaders is the one place a subscription request gets its headers, for the import and
// the refresh alike, so the provider sees the same client both times: the User-Agent (the configured
// one or "wayhop") and, when an HWID is set, x-hwid with x-device-os. With no HWID nothing but the
// User-Agent is sent.
func setSubscriptionHeaders(h http.Header, ua, hwid string, p platform.Platform) {
	h.Set("User-Agent", subscriptionUserAgent(ua))
	if hwid == "" {
		return
	}
	h.Set("X-Hwid", hwid)
	h.Set("X-Device-Os", hwidDeviceOS(p))
}

// checkHWIDRequest validates the HWID choice of an import that fetches a URL (a pasted text sends
// nothing, so its choice is not checked): mode "" keeps what is stored, "off" sends none, "generate"
// WayHop's own random ID, "custom" the value given, which Remnawave must accept.
func checkHWIDRequest(mode, custom string) error {
	switch mode {
	case "", "off", "generate":
		return nil
	case "custom":
		if !validHWID(custom) {
			return fmt.Errorf("hwid must be 10 to 64 letters, digits, '=' or '-': a provider panel ignores any other value, as if none were sent")
		}
		return nil
	}
	return fmt.Errorf("hwid_mode must be off, generate or custom")
}

// subscriptionHWID resolves the x-hwid an import of rawURL sends for a checked mode. It never touches
// Subscription.HWID: that is what the stored URL is fetched with, and the import changes it only
// together with the URL, once the fetch has succeeded, so a failed import or one of another URL
// leaves the stored subscription asking as before.
//
// "generate" sends GeneratedHWID, made on the first such import and saved at once, before the fetch:
// the provider can count the device on that first request even when the answer then fails, and a
// retry must not present a second device. "off" and "custom" never clear it, so going back to
// "generate" presents the same device again. Mode "" (the panel could not read the stored choice)
// keeps the stored HWID for the stored URL and sends none to another URL: an ID one provider knows
// this router by is not for another provider to see.
func (s *Server) subscriptionHWID(mode, custom, rawURL string) (string, error) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	sub := &s.cfg.Subscription
	switch mode {
	case "off":
		return "", nil
	case "custom":
		return custom, nil
	case "generate":
		if validHWID(sub.GeneratedHWID) {
			return sub.GeneratedHWID, nil
		}
		id, err := newHWID()
		if err != nil {
			return "", err
		}
		old := sub.GeneratedHWID
		sub.GeneratedHWID = id
		if err := s.cfg.Save(); err != nil {
			sub.GeneratedHWID = old // keep memory == disk; an ID that is not kept must not be sent
			return "", fmt.Errorf("save the generated hwid: %w", err)
		}
		return id, nil
	}
	if rawURL != sub.URL {
		return "", nil
	}
	if sub.HWID != "" && !validHWID(sub.HWID) {
		return "", errStoredHWID
	}
	return sub.HWID, nil
}

// subscriptionRedirect is the CheckRedirect of every subscription fetch (the import and the refresh
// alike, and the other fetches of user-given URLs that share the client). Go copies the first
// request's headers onto each redirect and adds the URL it came from as Referer:
//   - Referer is removed on every redirect: it is the subscription URL, whose path or query is the
//     account token, and the next hop (a CDN, or anyone the provider redirects to) has no business
//     with it (QA-126);
//   - x-hwid and x-device-os go only to the host the operator gave: a redirect to another host must
//     not learn the ID this router is known by to the provider.
func subscriptionRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return fmt.Errorf("stopped after 5 redirects")
	}
	req.Header.Del("Referer")
	if !strings.EqualFold(req.URL.Hostname(), via[0].URL.Hostname()) {
		req.Header.Del("X-Hwid")
		req.Header.Del("X-Device-Os")
	}
	return nil
}

// subscriptionStatusError is the error for a subscription fetch answered with a status other than
// 200. A 404 to a fetch that sent no HWID says what it most likely is: Remnawave with its device limit
// on answers 404 to exactly that, and "404 Not Found" alone reads as a wrong URL.
func subscriptionStatusError(status string, code int, hwid string) string {
	msg := "subscription returned status " + status
	if code == http.StatusNotFound && hwid == "" {
		msg += " (a provider with a device limit needs an HWID)"
	}
	return msg
}

// restoredHWID is the HWID a restore keeps: the backup's own when it has a usable one, else the current
// one. An empty value (an older backup, or one taken with the HWID off) and the redaction mark (an
// export without secrets) keep the current ID, since changing it takes another device slot. A value
// the provider would ignore is refused before anything is restored.
func restoredHWID(fromBackup, current string) (string, error) {
	switch fromBackup {
	case "", config.RedactedMark:
		return current, nil
	}
	if !validHWID(fromBackup) {
		return "", fmt.Errorf("subscription hwid is not 10 to 64 letters, digits, '=' or '-'")
	}
	return fromBackup, nil
}

// restoredHWIDs applies restoredHWID to both IDs a backup carries, the one the stored URL is fetched
// with and the generated one, against the current subscription.
func restoredHWIDs(hwid, generated string, cur config.Subscription) (string, string, error) {
	h, err := restoredHWID(hwid, cur.HWID)
	if err != nil {
		return "", "", err
	}
	g, err := restoredHWID(generated, cur.GeneratedHWID)
	if err != nil {
		return "", "", fmt.Errorf("generated %w", err)
	}
	return h, g, nil
}
