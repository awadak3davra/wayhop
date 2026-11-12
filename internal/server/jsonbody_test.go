package server

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestDecodeJSONBody(t *testing.T) {
	type obj struct {
		Name string `json:"name"`
	}
	cases := []struct {
		body string
		ok   bool
		eof  bool
	}{
		{`{"name":"a"}`, true, false},
		{"{\"name\":\"a\"}\n  \t", true, false},
		{`{"name":"a"} {"name":"b"}`, false, false},
		{`{"name":"a"}junk`, false, false},
		{`{"name":"a"}]`, false, false},
		{``, false, true},
	}
	for _, c := range cases {
		var v obj
		err := decodeJSONBody(strings.NewReader(c.body), &v)
		if (err == nil) != c.ok {
			t.Errorf("%q: err = %v, want ok=%v", c.body, err, c.ok)
		}
		if c.eof && !errors.Is(err, io.EOF) {
			t.Errorf("%q: err = %v, want io.EOF", c.body, err)
		}
		if c.ok && v.Name != "a" {
			t.Errorf("%q: decoded %+v", c.body, v)
		}
	}
}

// A write with a second document used to save the first one and answer 200 (found by an API hunter on an
// emulated OpenWrt: a group, the DNS plane, the profile, endpoint bulk and others).
func TestWriteRefusesTrailingJSON(t *testing.T) {
	s := bindTestServer(t, feedProfile(), "")
	before := len(s.store.Profile().Groups)
	body := `{"id":"g-trailing","name":"FIRST","type":"selector","members":["direct"]} {"id":"g-trailing","name":"SECOND"}`
	w := tgDo(t, s, http.MethodPost, "/api/groups", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400: %s", w.Code, w.Body.String())
	}
	if got := len(s.store.Profile().Groups); got != before {
		t.Fatalf("groups %d -> %d: a refused write must change nothing", before, got)
	}
}
