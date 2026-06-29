package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHandlePBRApply_ModeGated (#1): POST /api/pbr/apply must install a kernel PBR plane ONLY in
// hybrid/fast — never in tun/mixed, where the capture-all sing-box TUN owns all traffic (installing
// one there desyncs the two datapaths). Mirrors handleApply's genOptionsWithPlan mode gate.
func TestHandlePBRApply_ModeGated(t *testing.T) {
	seed := func(s *Server) {
		if err := s.store.UpsertEndpoint(pbr_extEndpoint("ru-awg1", "awg1", "198.51.100.20")); err != nil {
			t.Fatalf("UpsertEndpoint: %v", err)
		}
		if err := s.store.UpsertRoutingList(pbr_list("l", "198.51.100.0/24", "ru-awg1")); err != nil {
			t.Fatalf("UpsertRoutingList: %v", err)
		}
	}
	call := func(s *Server) {
		s.handlePBRApply(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/pbr/apply", nil))
	}

	// tun mode: must NOT install a kernel plane.
	sTun, rrTun := pbrApplyServer(t)
	sTun.cfg.RoutingMode = "tun"
	seed(sTun)
	call(sTun)
	if j := strings.Join(append(append([]string{}, rrTun.Calls...), rrTun.Stdin...), "\n"); strings.Contains(j, "wr_mark") {
		t.Errorf("tun mode must NOT install a kernel PBR plane via /api/pbr/apply, but the wr_mark chain was rendered:\n%s", j)
	}

	// fast mode: MUST install the kernel plane (it is the routing brain).
	sFast, rrFast := pbrApplyServer(t)
	sFast.cfg.RoutingMode = "fast"
	seed(sFast)
	call(sFast)
	if j := strings.Join(append(append([]string{}, rrFast.Calls...), rrFast.Stdin...), "\n"); !strings.Contains(j, "wr_mark") {
		t.Errorf("fast mode must install the kernel PBR plane via /api/pbr/apply:\n%s", j)
	}
}
