package health

import "testing"

// TestSuccessRateIsWindowed proves SuccessRate reflects RECENT health, not the lifetime
// average: a long-healthy endpoint that then fails for a full window reads 0%, whereas the
// old lifetime ratio would still be ~77%.
func TestSuccessRateIsWindowed(t *testing.T) {
	m := &Monitor{stats: map[string]*stat{}}
	for i := 0; i < 100; i++ {
		m.record("e", "E", "endpoint", Alive, 50, int64(1000+i*1000))
	}
	for i := 0; i < healthWindow; i++ {
		m.record("e", "E", "endpoint", Down, 0, int64(200000+i*1000))
	}
	v := toView("e", m.stats["e"], 999999)
	if v.SuccessRate != 0 {
		t.Errorf("windowed success_rate=%d want 0 (last %d probes all failed); lifetime would be ~77%%", v.SuccessRate, healthWindow)
	}
	if v.Probes != 100+healthWindow {
		t.Errorf("probes=%d want %d (lifetime count preserved)", v.Probes, 100+healthWindow)
	}
}

// TestAvgLatencyIsWindowed proves AvgLatencyMs tracks the recent window: after a sustained
// latency spike the average reflects it instead of being diluted by the long fast history.
func TestAvgLatencyIsWindowed(t *testing.T) {
	m := &Monitor{stats: map[string]*stat{}}
	for i := 0; i < 100; i++ {
		m.record("e", "E", "endpoint", Alive, 50, int64(1000+i*1000))
	}
	for i := 0; i < healthWindow; i++ {
		m.record("e", "E", "endpoint", Alive, 500, int64(200000+i*1000))
	}
	v := toView("e", m.stats["e"], 999999)
	if v.AvgLatencyMs != 500 {
		t.Errorf("windowed avg=%d want 500 (last %d probes all 500ms)", v.AvgLatencyMs, healthWindow)
	}
	if v.SuccessRate != 100 {
		t.Errorf("success_rate=%d want 100 (all recent probes ok)", v.SuccessRate)
	}
}
