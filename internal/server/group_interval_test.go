package server

import (
	"net/http"
	"testing"
)

// minGroupProbeInterval is checked where groups are written; the panel's field says the same.
func TestGroupProbeIntervalHasAFloor(t *testing.T) {
	s := bindTestServer(t, feedProfile(), "")
	cases := map[string]int{
		`{"id":"g-1s","name":"one","type":"urltest","members":["direct"],"test":{"interval":1}}`:   http.StatusBadRequest,
		`{"id":"g-neg","name":"neg","type":"urltest","members":["direct"],"test":{"interval":-5}}`: http.StatusBadRequest,
		`{"id":"g-5s","name":"five","type":"urltest","members":["direct"],"test":{"interval":5}}`:  http.StatusOK,
		`{"id":"g-def","name":"default","type":"urltest","members":["direct"]}`:                    http.StatusOK,
	}
	for body, want := range cases {
		if w := tgDo(t, s, http.MethodPost, "/api/groups", body); w.Code != want {
			t.Errorf("%s: status %d, want %d: %s", body, w.Code, want, w.Body.String())
		}
	}
}
