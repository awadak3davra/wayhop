package server

import (
	"net/http"
	"sort"
	"strconv"
	"strings"

	"wayhop/internal/health"
	"wayhop/internal/version"
)

// handleMetrics serves a Prometheus text-exposition (version 0.0.4) scrape of the
// data WayHop already collects: build info, sing-box state, per-endpoint health
// (up / latency / success-ratio / traffic) from the monitor snapshot, and the latest
// aggregate traffic sample from the hub. It is read-only and purely additive.
//
// To avoid a new dependency the format is hand-written — the text format is trivial:
//
//	# HELP name help text
//	# TYPE name gauge
//	name{label="value"} 1.23
//
// Every data source (monitor / hub / singbox / store) is nil-guarded so the static
// metrics (build_info / up) are always emitted, even on a minimally-constructed Server.
//
// NO SECRETS are emitted: only id / name / protocol labels — never uuid, password,
// keys, or private_key. Label VALUES are escaped per the Prometheus rules.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	var b strings.Builder

	// --- static metrics (always present) ---
	writeHelpType(&b, "wayhop_build_info", "WayHop build information.", "gauge")
	b.WriteString("wayhop_build_info{version=\"")
	b.WriteString(escapeLabel(version.Version))
	b.WriteString("\"} 1\n")

	writeHelpType(&b, "wayhop_up", "Always 1; indicates the WayHop daemon is responding.", "gauge")
	b.WriteString("wayhop_up 1\n")

	// --- sing-box core state ---
	var running, available int
	if s.singbox != nil {
		if s.singbox.Running() {
			running = 1
		}
		if s.singbox.Available() {
			available = 1
		}
	}
	writeHelpType(&b, "wayhop_singbox_running", "1 if the sing-box core process is running, else 0.", "gauge")
	b.WriteString("wayhop_singbox_running ")
	b.WriteString(strconv.Itoa(running))
	b.WriteByte('\n')

	writeHelpType(&b, "wayhop_singbox_available", "1 if the sing-box binary is present and runnable, else 0.", "gauge")
	b.WriteString("wayhop_singbox_available ")
	b.WriteString(strconv.Itoa(available))
	b.WriteByte('\n')

	// --- per-endpoint health (from the monitor snapshot) ---
	// The View carries id/name/state/latency/success%/traffic but NOT the protocol,
	// so derive the protocol from the stored profile (id -> protocol). The profile is
	// non-secret metadata (no keys are placed in labels).
	protoByID := map[string]string{}
	if s.store != nil {
		for _, e := range s.store.Profile().Endpoints {
			protoByID[e.ID] = string(e.Protocol)
		}
	}

	var views []health.View
	if s.monitor != nil {
		views = s.monitor.Snapshot()
	}
	// Stable output: sort the series by id.
	sort.Slice(views, func(i, j int) bool { return views[i].ID < views[j].ID })

	writeHelpType(&b, "wayhop_endpoint_up", "1 if the endpoint/group is alive, else 0.", "gauge")
	for _, v := range views {
		writeEndpointSample(&b, "wayhop_endpoint_up", v, protoByID[v.ID], boolVal(v.State == string(health.Alive)))
	}

	writeHelpType(&b, "wayhop_endpoint_latency_ms", "Last measured endpoint latency in milliseconds.", "gauge")
	for _, v := range views {
		// Omit the series when there is no measurement (latency 0 with a non-alive
		// state means "never measured", not "0 ms").
		if v.LatencyMs <= 0 {
			continue
		}
		writeEndpointSample(&b, "wayhop_endpoint_latency_ms", v, protoByID[v.ID], strconv.Itoa(v.LatencyMs))
	}

	writeHelpType(&b, "wayhop_endpoint_success_ratio", "Probe success ratio (0..1).", "gauge")
	for _, v := range views {
		ratio := float64(v.SuccessRate) / 100.0 // SuccessRate is a 0..100 percent integer
		writeEndpointSample(&b, "wayhop_endpoint_success_ratio", v, protoByID[v.ID], formatFloat(ratio))
	}

	writeHelpType(&b, "wayhop_endpoint_rx_bytes", "Approximate total bytes received (downloaded) attributed to the endpoint.", "gauge")
	for _, v := range views {
		writeEndpointSample(&b, "wayhop_endpoint_rx_bytes", v, protoByID[v.ID], strconv.FormatInt(v.BytesDown, 10))
	}

	writeHelpType(&b, "wayhop_endpoint_tx_bytes", "Approximate total bytes transmitted (uploaded) attributed to the endpoint.", "gauge")
	for _, v := range views {
		writeEndpointSample(&b, "wayhop_endpoint_tx_bytes", v, protoByID[v.ID], strconv.FormatInt(v.BytesUp, 10))
	}

	// --- aggregate live traffic (latest hub sample, already in bytes/s) ---
	var rx, tx int64
	if s.hub != nil {
		if recent := s.hub.RecentN(1); len(recent) > 0 {
			last := recent[len(recent)-1]
			rx, tx = last.Down, last.Up
		}
	}
	writeHelpType(&b, "wayhop_traffic_rx_bytes_per_second", "Latest aggregate download throughput in bytes per second.", "gauge")
	b.WriteString("wayhop_traffic_rx_bytes_per_second ")
	b.WriteString(strconv.FormatInt(rx, 10))
	b.WriteByte('\n')

	writeHelpType(&b, "wayhop_traffic_tx_bytes_per_second", "Latest aggregate upload throughput in bytes per second.", "gauge")
	b.WriteString("wayhop_traffic_tx_bytes_per_second ")
	b.WriteString(strconv.FormatInt(tx, 10))
	b.WriteByte('\n')

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}

// writeHelpType emits the # HELP and # TYPE preamble for a metric family. The HELP
// text is escaped per the Prometheus rules (backslash and newline only).
func writeHelpType(b *strings.Builder, name, help, typ string) {
	b.WriteString("# HELP ")
	b.WriteString(name)
	b.WriteByte(' ')
	b.WriteString(escapeHelp(help))
	b.WriteByte('\n')
	b.WriteString("# TYPE ")
	b.WriteString(name)
	b.WriteByte(' ')
	b.WriteString(typ)
	b.WriteByte('\n')
}

// writeEndpointSample emits one per-endpoint series with the id/name/protocol labels.
// Only those three labels are emitted — never any secret field.
func writeEndpointSample(b *strings.Builder, name string, v health.View, proto, value string) {
	b.WriteString(name)
	b.WriteString("{id=\"")
	b.WriteString(escapeLabel(v.ID))
	b.WriteString("\",name=\"")
	b.WriteString(escapeLabel(v.Name))
	b.WriteString("\",protocol=\"")
	b.WriteString(escapeLabel(proto))
	b.WriteString("\"} ")
	b.WriteString(value)
	b.WriteByte('\n')
}

// boolVal renders a bool as the Prometheus 0/1 gauge convention.
func boolVal(ok bool) string {
	if ok {
		return "1"
	}
	return "0"
}

// formatFloat renders a float without trailing junk (shortest round-trippable form).
func formatFloat(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }

// escapeLabel escapes a Prometheus label VALUE: backslash, double-quote, and newline.
func escapeLabel(s string) string {
	if !strings.ContainsAny(s, "\\\"\n") {
		return s
	}
	r := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", "\\n")
	return r.Replace(s)
}

// escapeHelp escapes HELP text: backslash and newline only (quotes are literal in HELP).
func escapeHelp(s string) string {
	if !strings.ContainsAny(s, "\\\n") {
		return s
	}
	r := strings.NewReplacer("\\", "\\\\", "\n", "\\n")
	return r.Replace(s)
}
