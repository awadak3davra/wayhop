package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"velinx/internal/config"
	"velinx/internal/initserver"
	"velinx/internal/serverstore"
	"velinx/internal/store"
)

// serverbins_newServer is a minimal *Server for the per-server binary version/update
// handlers: a Demo-or-not config, a profile store, a server registry, and a job
// manager. Backed by t.TempDir() so nothing leaks between tests.
func serverbins_newServer(t *testing.T, demo bool) *Server {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "profile.json"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	ss, err := serverstore.Open(filepath.Join(dir, "servers.json"))
	if err != nil {
		t.Fatalf("serverstore.Open: %v", err)
	}
	return &Server{
		cfg:     &config.Config{Demo: demo},
		store:   st,
		servers: ss,
		jobs:    initserver.NewJobManager(),
	}
}

// TestCheckVersionsDemo: the demo path of the per-server version check finishes ok
// and reports both managed binaries (sing-box + AmneziaWG).
func TestCheckVersionsDemo(t *testing.T) {
	s := serverbins_newServer(t, true)
	job := s.jobs.New("check-versions", "")
	s.runCheckVersions(job, hardenReq{Host: "203.0.113.7", Port: 22, User: "root"})

	v := provision_waitDone(t, job)
	if !v.OK {
		t.Fatalf("check-versions demo job not ok: %+v", v)
	}
	raw, _ := json.Marshal(v.Result)
	got := string(raw)
	for _, want := range []string{`"singbox"`, `"awg"`, `"update_available"`} {
		if !strings.Contains(got, want) {
			t.Errorf("check-versions result missing %q: %s", want, got)
		}
	}
}

// TestUpdateBinaryDemo: the demo path of a per-server binary update finishes ok and
// echoes the new version for the requested binary.
func TestUpdateBinaryDemo(t *testing.T) {
	s := serverbins_newServer(t, true)
	job := s.jobs.New("update-binary", "")
	s.runUpdateServerBinary(job, serverBinUpdateReq{
		hardenReq: hardenReq{Host: "203.0.113.7", Port: 22, User: "root"},
		Binary:    "singbox", Version: "1.12.17", Confirm: true,
	})

	v := provision_waitDone(t, job)
	if !v.OK {
		t.Fatalf("update-binary demo job not ok: %+v", v)
	}
	if got, _ := v.Result["new_version"].(string); got != "1.12.17" {
		t.Errorf("update-binary new_version = %q, want 1.12.17", got)
	}
}

// TestUpdateBinaryGating pins the request-validation gates on the DESTRUCTIVE remote
// update so they can never silently regress: an unknown binary, a sing-box request
// with no target version, and (outside demo) a request without the explicit confirm
// flag must all be rejected BEFORE any job is launched.
func TestUpdateBinaryGating(t *testing.T) {
	s := serverbins_newServer(t, false) // NON-demo so the confirm gate is active
	post := func(body map[string]any) int {
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/server/update-binary", bytes.NewReader(b))
		w := httptest.NewRecorder()
		s.handleServerUpdateBinary(w, req)
		return w.Code
	}
	cases := []struct {
		name string
		body map[string]any
		want int
	}{
		{"unknown binary", map[string]any{"host": "203.0.113.7", "user": "root", "binary": "mihomo", "version": "1.0.0", "confirm": true}, http.StatusBadRequest},
		{"singbox without version", map[string]any{"host": "203.0.113.7", "user": "root", "binary": "singbox", "confirm": true}, http.StatusBadRequest},
		{"missing confirm (non-demo)", map[string]any{"host": "203.0.113.7", "user": "root", "binary": "singbox", "version": "1.12.17"}, http.StatusBadRequest},
		{"missing host/user", map[string]any{"binary": "singbox", "version": "1.12.17", "confirm": true}, http.StatusBadRequest},
	}
	for _, c := range cases {
		if got := post(c.body); got != c.want {
			t.Errorf("%s: handleServerUpdateBinary returned %d, want %d", c.name, got, c.want)
		}
	}
}
