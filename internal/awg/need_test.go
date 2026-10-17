package awg

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

// The generation a connection needs, from the attribute each setting arrived as upstream, in every
// shape the model stores a value: strings from an import, ints from code, float64 after JSON.
func TestNeed(t *testing.T) {
	cases := []struct {
		params map[string]any
		want   Generation
	}{
		{nil, Gen1},
		{map[string]any{"private_key": "k"}, Gen1},
		{map[string]any{"jc": 4, "s1": 10, "h1": "5"}, Gen1},
		{map[string]any{"h1": float64(3_000_000_000)}, Gen1}, // above 2^31, as JSON leaves it
		{map[string]any{"h2": "5-10"}, Gen2},
		{map[string]any{"s3": 20}, Gen2},
		{map[string]any{"s4": float64(16)}, Gen2},
		{map[string]any{"i1": "0xdead"}, Gen2},
		{map[string]any{"i5": ""}, Gen1}, // empty is unset
		{map[string]any{"header_protection_key": "k"}, Gen30},
		{map[string]any{"keepalive_timeout": "10"}, Gen30},
		{map[string]any{"max_handshake_attempts": int64(3)}, Gen30},
		{map[string]any{"random_trailers": true}, Gen31},
		{map[string]any{"disable_cookies": "on"}, Gen31},
		{map[string]any{"disable_cookies": float64(1)}, Gen31},
		{map[string]any{"random_trailers": false, "disable_cookies": "off"}, Gen1},
		{map[string]any{"random_trailers": "maybe"}, Gen1}, // unreadable: the plugin refuses it when it translates
		{map[string]any{"s3": 20, "header_protection_key": "k", "random_trailers": "1"}, Gen31},
	}
	for _, c := range cases {
		if got := Need(c.params); got != c.want {
			t.Errorf("Need(%v) = %v, want %v", c.params, got, c.want)
		}
		// What Need reports is exactly the line Beyond draws: nothing beyond it, something beyond the
		// generation below it.
		if b := Beyond(c.params, c.want); b != nil {
			t.Errorf("Beyond(%v, %v) = %v, want nothing", c.params, c.want, b)
		}
		if c.want > Gen1 && Beyond(c.params, c.want-1) == nil {
			t.Errorf("Beyond(%v, %v) is empty, though Need says %v", c.params, c.want-1, c.want)
		}
	}
}

// Beyond names what a writer of a given generation would drop, sorted, and leaves out a switch that
// is off and every key that is not a setting.
func TestBeyond(t *testing.T) {
	p := map[string]any{
		"jc": 4, "h1": "1-2", "s3": 20, "header_protection_key": "k", "rekey_timeout": "5",
		"random_trailers": "on", "disable_cookies": false, "private_key": "k", "peers": []any{},
	}
	for _, c := range []struct {
		g    Generation
		want []string
	}{
		{GenNone, []string{"h1", "header_protection_key", "jc", "random_trailers", "rekey_timeout", "s3"}},
		{Gen1, []string{"h1", "header_protection_key", "random_trailers", "rekey_timeout", "s3"}},
		{Gen2, []string{"header_protection_key", "random_trailers", "rekey_timeout"}},
		{Gen30, []string{"random_trailers"}},
		{Gen31, nil},
	} {
		if got := Beyond(p, c.g); !reflect.DeepEqual(got, c.want) {
			t.Errorf("Beyond(p, %v) = %v, want %v", c.g, got, c.want)
		}
	}
}

// A profile goes through the store as JSON: numbers come back as float64 and must weigh the same.
func TestNeed_SurvivesAJSONRoundTrip(t *testing.T) {
	p := map[string]any{"jc": 4, "s3": 20, "h2": "5-10", "max_handshake_attempts": 3, "disable_cookies": true}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if Need(back) != Need(p) || !reflect.DeepEqual(Beyond(back, Gen2), Beyond(p, Gen2)) {
		t.Errorf("after JSON: Need %v Beyond %v; before: Need %v Beyond %v",
			Need(back), Beyond(back, Gen2), Need(p), Beyond(p, Gen2))
	}
}

// Settings is the table's key set, sorted, and each setting set on its own asks for its generation -
// the list the writers' tests walk has to be the list Need decides by.
func TestSettings(t *testing.T) {
	got := Settings()
	if !sort.StringsAreSorted(got) || len(got) != len(settingGen) {
		t.Fatalf("Settings() = %v: not the sorted key set of the table", got)
	}
	for _, key := range got {
		value := any("1")
		if settingGen[key] == Gen31 {
			value = "on"
		}
		if n := Need(map[string]any{key: value}); n != max(settingGen[key], Gen1) {
			t.Errorf("%s alone needs %v, the table says %v", key, n, settingGen[key])
		}
		if Introduced(key) != settingGen[key] {
			t.Errorf("Introduced(%s) = %v, the table says %v", key, Introduced(key), settingGen[key])
		}
	}
	if Introduced("private_key") != GenNone {
		t.Error("a key that is not an AmneziaWG setting was given a generation")
	}
}

// SettingText reads a value exactly as Need weighs it, in every shape the model stores one: a writer
// that renders by it cannot drop what Need counted, nor write what Need ignored.
func TestSettingText(t *testing.T) {
	for _, c := range []struct {
		in   any
		want string
	}{
		{"100-200", "100-200"}, {7, "7"}, {int64(3_000_000_000), "3000000000"},
		{float64(3_000_000_000), "3000000000"}, {true, ""}, {nil, ""}, {[]any{"1"}, ""},
	} {
		if got := SettingText(c.in); got != c.want {
			t.Errorf("SettingText(%#v) = %q, want %q", c.in, got, c.want)
		}
		weighed := Need(map[string]any{"rekey_timeout": c.in}) == Gen30
		if weighed != (c.want != "") {
			t.Errorf("Need weighs %#v as %v while SettingText reads %q", c.in, weighed, c.want)
		}
	}
}
