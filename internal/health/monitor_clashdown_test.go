package health

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"velinx/internal/clash"
	"velinx/internal/model"
)

// TestMonitorGracefulWhenClashUnreachable locks the stability property the P4 native-only sing-box
// skip relies on: when the clash API client EXISTS but its endpoint is unreachable (sing-box
// stopped — e.g. a fully-kernel-native fast-mode profile), the monitor must degrade gracefully —
// report Unknown (never a false Down), and leave traffic stats untouched — with no panic and no
// per-tick logging. A permanently-absent core must not crash the monitor or spam the tiny overlay.
func TestMonitorGracefulWhenClashUnreachable(t *testing.T) {
	// A clash client whose endpoint refuses connections: start a server, capture its address, then
	// close it so the address is dead. clash.New only stores the address (connects per-request).
	ts := httptest.NewServer(http.NewServeMux())
	addr := strings.TrimPrefix(ts.URL, "http://")
	ts.Close()
	c, err := clash.New(addr, "")
	if err != nil {
		t.Fatalf("clash.New: %v", err)
	}
	m := NewMonitor(c, health_newStore(t, model.Profile{}), nil, false)

	// A group probe (no iface) goes via clash.Delay; an unreachable API must yield Unknown — not
	// Down (which would falsely mark a healthy kernel tunnel as failed) and not a panic.
	if st, _ := m.probe(context.Background(), "g", "", ""); st != Unknown {
		t.Errorf("probe with unreachable clash = %v, want Unknown", st)
	}

	// sampleTraffic must be a harmless no-op (no panic, stats untouched) when /connections fails.
	m.stats["x"] = &stat{totalUp: 42}
	m.sampleTraffic(context.Background(), nil, nowMS())
	if got := m.stats["x"].totalUp; got != 42 {
		t.Errorf("sampleTraffic must not mutate stats when clash is unreachable: totalUp=%d, want 42", got)
	}
}
