package generator

import (
	"encoding/base64"
	"testing"
)

// TestNormalizeRealityPubKey verifies a reality public key given in any base64
// variant validRealityPubKey accepts is emitted as base64url-without-padding — the
// only form sing-box's reality decoder accepts. The std-base64 (`=`-padded) form is
// what passed validation yet made a real `sing-box check` reject the whole config
// with "decode public_key: illegal base64 data at input byte 43" (the `=`).
func TestNormalizeRealityPubKey(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i*37 + 5) // varied bytes so +/ vs -_ alphabets actually differ
	}
	want := base64.RawURLEncoding.EncodeToString(raw)

	cases := map[string]string{
		"std-padded": base64.StdEncoding.EncodeToString(raw),    // the real bug trigger
		"std-raw":    base64.RawStdEncoding.EncodeToString(raw), // +/ , no padding
		"url-padded": base64.URLEncoding.EncodeToString(raw),    // -_ , padded
		"url-raw":    base64.RawURLEncoding.EncodeToString(raw), // already canonical
	}
	for name, in := range cases {
		got := normalizeRealityPubKey(in)
		if got != want {
			t.Errorf("%s: normalizeRealityPubKey(%q) = %q, want %q", name, in, got, want)
		}
		// The result must decode cleanly as RawURL with no padding (sing-box's decoder).
		if b, err := base64.RawURLEncoding.DecodeString(got); err != nil || len(b) != 32 {
			t.Errorf("%s: normalized key not RawURL-decodable: err=%v len=%d", name, err, len(b))
		}
		// Every emitted case must pass the validity gate too.
		if !validRealityPubKey(in) {
			t.Errorf("%s: input %q should be a valid reality pubkey", name, in)
		}
	}

	// A key the gate would reject is returned unchanged (caller has already gated on
	// validRealityPubKey, so this branch is defensive, not a normal path).
	if got := normalizeRealityPubKey("not-valid-base64!!!"); got != "not-valid-base64!!!" {
		t.Errorf("unparseable key should pass through unchanged, got %q", got)
	}
}
