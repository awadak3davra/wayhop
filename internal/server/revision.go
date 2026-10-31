package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"wayhop/internal/config"
	"wayhop/internal/store"
)

// QA-152. A connection, group or routing list is saved whole, and so are the settings: the page
// sends back the object it loaded with its edit applied. A form or a switch left open while another
// tab, device or script saved a newer version therefore put the older one back, with a 200 - a
// connection's on/off switch restored the server another tab had just changed, and a Settings save
// undid what Components had saved to updater.download_via.
//
// These writes now take the revision their copy was read at in If-Match, and one whose revision is
// no longer current is refused 412 with nothing saved. For a connection, group or routing list it is
// the revision of that one object (model.EndpointRev and the rest), which GET /api/profile?lite=1
// lists in `revs`: a profile-wide generation, which the DNS plane uses for its single document,
// moved with every write anywhere and made every open form stale on the next feed refresh. For the
// settings it is configRev. The header stays optional so a script that never sent one keeps working;
// the panel sends it from every form that edits an existing object, and its switches change
// `enabled` alone (PATCH), which no other edit can make stale. A save answers the object's revision
// before and after it (`was`, `rev`), so a page that saved from a current copy can keep that copy.

// revStaleCode marks a 412 refusal so a client can tell it from every other error.
const revStaleCode = "STALE"

// profileRevOf reads the optional If-Match of a connection, group or routing list write: the
// object's revision as the caller's copy had it. No header, or "*", is the unconditional write. Any
// other value is compared as it is, so a garbled one is refused rather than read as unconditional: a
// client that meant to send a precondition must not overwrite what it was guarding.
func profileRevOf(r *http.Request) store.Rev {
	raw := ifMatchValue(r)
	if raw == "" || raw == "*" {
		return store.AnyRev
	}
	return store.At(raw)
}

// savedRev is a save's answer: the object as stored, and its revision before (was, empty when it is
// new) and after (rev) the save.
type savedRev[T any] struct {
	Object T
	store.Saved
}

// MarshalJSON writes the object's own fields with rev and was beside them.
func (s savedRev[T]) MarshalJSON() ([]byte, error) {
	b, err := json.Marshal(s.Object)
	if err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	m["rev"], _ = json.Marshal(s.Rev)
	if s.Was != "" {
		m["was"], _ = json.Marshal(s.Was)
	}
	return json.Marshal(m)
}

// decodeEnabledOnly reads a PATCH body, which may say {"enabled": bool} and nothing else.
func decodeEnabledOnly(r *http.Request) (bool, bool) {
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil || body.Enabled == nil {
		return false, false
	}
	return *body.Enabled, true
}

// ifMatchValue is the If-Match header with its quotes and an optional weak marker stripped.
func ifMatchValue(r *http.Request) string {
	raw := strings.TrimSpace(r.Header.Get("If-Match"))
	raw = strings.TrimPrefix(raw, "W/")
	return strings.Trim(raw, `"`)
}

// writeStale answers a write whose If-Match is not the current revision of what it writes.
func writeStale(w http.ResponseWriter, what string) {
	writeJSON(w, http.StatusPreconditionFailed, staleBody(what))
}

// staleBody is the 412 body; what names the object, capitalised ("This connection").
func staleBody(what string) map[string]any {
	return map[string]any{
		"code": revStaleCode,
		"error": what + " changed after this copy was loaded (another tab, device or script saved first), " +
			"so saving it would put the older version back. Nothing was saved: reload to see the current " +
			"version, then make the change again.",
	}
}

// isStale reports a refusal by the store's revision checks.
func isStale(err error) bool {
	return errors.Is(err, store.ErrStale) || errors.Is(err, store.ErrStaleGen)
}

// errStaleConfig is persistConfigAt's refusal of a save based on settings that have since changed.
var errStaleConfig = errors.New("settings changed since they were read")

// configRev is the revision of the settings a PUT /api/config writes: a hash of exactly the fields
// applyConfigFields copies from a request. Those are the fields a stale copy could put back, so they
// are what the revision covers; a change to anything else (a pairing, a dismissed warning, the
// subscription's own settings) does not make a Settings page stale, because its save leaves those
// alone. Computed from the live config, so every writer moves it without having to remember to.
func configRev(c *config.Config) string {
	var saved config.Config
	applyConfigFields(&saved, c)
	b, err := json.Marshal(saved)
	if err != nil {
		return "" // unreachable for a config that loaded; "" makes every If-Match stale, never a false match
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

// configWithRev is GET /api/config's body: the settings and the revision a save of them sends back.
type configWithRev struct {
	config.Config
	Rev string `json:"rev"`
}
