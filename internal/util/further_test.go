package util

import "testing"

// TestFirstNonEmpty exercises every shape of input FirstNonEmpty can see:
// no args, all-empty, first-wins, a later non-empty, and a single arg. Each
// case asserts the exact returned string so a subtly-wrong implementation
// (e.g. returning the last non-empty, or skipping index 0) would fail.
func TestFirstNonEmpty(t *testing.T) {
	cases := []struct {
		name string
		vals []string
		want string
	}{
		{name: "no-args", vals: nil, want: ""},
		{name: "single-empty", vals: []string{""}, want: ""},
		{name: "single-nonempty", vals: []string{"a"}, want: "a"},
		{name: "all-empty", vals: []string{"", "", ""}, want: ""},
		{name: "first-wins-over-later", vals: []string{"first", "second"}, want: "first"},
		{name: "skip-leading-empties", vals: []string{"", "", "third"}, want: "third"},
		{name: "skip-one-empty", vals: []string{"", "second", "third"}, want: "second"},
		// A whitespace string is NOT empty; FirstNonEmpty only checks != "".
		{name: "whitespace-is-not-empty", vals: []string{"", " ", "x"}, want: " "},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := FirstNonEmpty(c.vals...)
			if got != c.want {
				t.Fatalf("FirstNonEmpty(%#v) = %q, want %q", c.vals, got, c.want)
			}
		})
	}
}

// TestFirstNonEmptyVariadicLiteral guards the spread form (passing args
// directly rather than via a slice) since that is how callers actually use it.
func TestFirstNonEmptyVariadicLiteral(t *testing.T) {
	if got := FirstNonEmpty("", "", "win"); got != "win" {
		t.Fatalf(`FirstNonEmpty("", "", "win") = %q, want "win"`, got)
	}
	if got := FirstNonEmpty(); got != "" {
		t.Fatalf(`FirstNonEmpty() = %q, want ""`, got)
	}
}

// TestLocalAddr covers each branch of the type switch plus the fallthrough
// default. The asserted strings pin down the exact ", " separator and the
// element-filtering behaviour for []any.
func TestLocalAddr(t *testing.T) {
	cases := []struct {
		name string
		in   map[string]any
		want string
	}{
		// []string branch
		{
			name: "string-slice-multi",
			in:   map[string]any{"local_address": []string{"10.0.0.1/32", "fd00::1/128"}},
			want: "10.0.0.1/32, fd00::1/128",
		},
		{
			name: "string-slice-single",
			in:   map[string]any{"local_address": []string{"10.0.0.1/32"}},
			want: "10.0.0.1/32",
		},
		{
			name: "string-slice-empty",
			in:   map[string]any{"local_address": []string{}},
			want: "",
		},
		// []any branch (the JSON-decoded shape)
		{
			name: "any-slice-all-strings",
			in:   map[string]any{"local_address": []any{"10.0.0.1/32", "fd00::1/128"}},
			want: "10.0.0.1/32, fd00::1/128",
		},
		{
			name: "any-slice-single",
			in:   map[string]any{"local_address": []any{"10.0.0.1/32"}},
			want: "10.0.0.1/32",
		},
		{
			name: "any-slice-empty",
			in:   map[string]any{"local_address": []any{}},
			want: "",
		},
		// Non-string elements inside []any are silently dropped, and the
		// remaining strings are still joined with ", ".
		{
			name: "any-slice-with-non-string-elements",
			in:   map[string]any{"local_address": []any{"10.0.0.1/32", 42, "fd00::1/128", true, nil}},
			want: "10.0.0.1/32, fd00::1/128",
		},
		{
			name: "any-slice-only-non-strings",
			in:   map[string]any{"local_address": []any{42, true, nil}},
			want: "",
		},
		// bare string branch
		{
			name: "bare-string",
			in:   map[string]any{"local_address": "10.0.0.1/32, fd00::1/128"},
			want: "10.0.0.1/32, fd00::1/128",
		},
		{
			name: "bare-string-empty",
			in:   map[string]any{"local_address": ""},
			want: "",
		},
		// default / fallthrough branch
		{
			name: "key-missing",
			in:   map[string]any{"other": "x"},
			want: "",
		},
		{
			name: "key-present-nil-value",
			in:   map[string]any{"local_address": nil},
			want: "",
		},
		{
			name: "wrong-type-int",
			in:   map[string]any{"local_address": 1234},
			want: "",
		},
		{
			name: "wrong-type-int-slice",
			in:   map[string]any{"local_address": []int{1, 2, 3}},
			want: "",
		},
		{
			name: "empty-map",
			in:   map[string]any{},
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := LocalAddr(c.in)
			if got != c.want {
				t.Fatalf("LocalAddr(%#v) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestLocalAddrNilMap confirms a nil map is treated like a map with a missing
// key (Go permits reads from a nil map), returning "" rather than panicking.
func TestLocalAddrNilMap(t *testing.T) {
	var p map[string]any
	if got := LocalAddr(p); got != "" {
		t.Fatalf("LocalAddr(nil) = %q, want %q", got, "")
	}
}

// TestLocalAddrs covers the un-joined slice form used by `ip addr add` (one call
// per address): a dual-stack config must yield BOTH addresses, not one joined
// string a single add would reject.
func TestLocalAddrs(t *testing.T) {
	eq := func(got, want []string) bool {
		if len(got) != len(want) {
			return false
		}
		for i := range got {
			if got[i] != want[i] {
				return false
			}
		}
		return true
	}
	cases := []struct {
		name string
		in   map[string]any
		want []string
	}{
		{"slice-dual", map[string]any{"local_address": []string{"10.0.0.2/32", "fd00::2/128"}}, []string{"10.0.0.2/32", "fd00::2/128"}},
		{"any-dual", map[string]any{"local_address": []any{"10.0.0.2/32", "fd00::2/128"}}, []string{"10.0.0.2/32", "fd00::2/128"}},
		{"single", map[string]any{"local_address": []string{"10.0.0.2/32"}}, []string{"10.0.0.2/32"}},
		{"legacy-joined-string", map[string]any{"local_address": "10.0.0.2/32, fd00::2/128"}, []string{"10.0.0.2/32", "fd00::2/128"}},
		{"blanks-skipped", map[string]any{"local_address": []string{" 10.0.0.2/32 ", "", "  "}}, []string{"10.0.0.2/32"}},
		{"absent", map[string]any{}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := LocalAddrs(c.in); !eq(got, c.want) {
				t.Fatalf("LocalAddrs() = %v, want %v", got, c.want)
			}
		})
	}
}
