package iptv

import "testing"

func TestInferExitCountry(t *testing.T) {
	cases := []struct {
		texts []string
		want  string
		ok    bool
	}{
		{[]string{"🇷🇺 Moscow VPS"}, "ru", true},                     // flag
		{[]string{"NL exit", "nl-ams-1.vps.com"}, "nl", true},       // uppercase code
		{[]string{"My Netherlands relay"}, "nl", true},              // country name
		{[]string{"United States west"}, "us", true},                // multi-word name
		{[]string{"reality-front", "login.example.com"}, "", false}, // "in"/"is" lowercase must NOT match
		{[]string{"trust node"}, "", false},                         // "us" inside a word must NOT match
		{[]string{"Germany 🇩🇪 backup"}, "de", true},                 // flag beats/matches name (both de)
		{[]string{"plain server", "1.2.3.4"}, "", false},            // nothing
		{[]string{"RU"}, "ru", true},                                // bare code
		{[]string{"russia lower"}, "ru", true},                      // case-insensitive name
	}
	for _, c := range cases {
		got, ok := InferExitCountry(c.texts...)
		if ok != c.ok || got != c.want {
			t.Errorf("InferExitCountry(%v) = (%q,%v), want (%q,%v)", c.texts, got, ok, c.want, c.ok)
		}
	}
}

func TestInferExitCountryPriority(t *testing.T) {
	// A flag in a later text still beats an ISO code that only appears... actually flag is checked
	// across ALL texts before codes, so a flag anywhere wins over a code.
	got, ok := InferExitCountry("US label", "🇷🇺 server")
	if !ok || got != "ru" {
		t.Fatalf("flag should win over a code in an earlier text: got %q,%v", got, ok)
	}
}

func TestWholePhraseBoundaries(t *testing.T) {
	// "Chile" as a whole word matches; embedded in another word ("Chilean") it must not.
	if code, ok := InferExitCountry("Chile datacenter"); !ok || code != "cl" {
		t.Errorf("whole-word country name should match: got %q,%v", code, ok)
	}
	if _, ok := InferExitCountry("Chilean server"); ok {
		t.Error("country name embedded in a larger word must not match")
	}
}
