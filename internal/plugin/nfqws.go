package plugin

import (
	"fmt"
	"strconv"
	"strings"

	"velinx/internal/model"
)

// nfqws.go renders the argv for the DPI-desync engine (nfqws2). nfqws2 is a long-running process
// that reads packets from a netfilter NFQUEUE and mangles the handshake so the DPI can't block it;
// the traffic stays on the DIRECT path (no egress). The NFQUEUE divert that feeds it is the
// `desync` routing target (kernel-PBR), NOT this engine. See docs/ARCHITECTURE_DESYNC.md.

// defaultNfqwsQueue is the NFQUEUE number Velinx's nfqws2 listens on — deliberately distinct
// from the user's standalone nfqws install so the two never share a queue.
const defaultNfqwsQueue = 200

// nfqwsSafe reports whether v is a well-formed nfqws2 strategy/fooling token (the composable
// comma-lists like "fake,split2" or "md5sig,badseq"). A value with spaces or shell/control chars
// is rejected so a typo or hostile param can't make nfqws2 fail to start — it falls back to the
// engine default instead (drop-don't-brick, mirroring the generator's safeEnum discipline). The
// argv is exec'd directly (no shell), so this is robustness, not an injection guard.
func nfqwsSafe(v string) bool {
	if v == "" {
		return false
	}
	for _, r := range v {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == ',' || r == '_' || r == '+' || r == '.' || r == '-'
		if !ok {
			return false
		}
	}
	return true
}

// intParam reads an integer param that may arrive as a JSON number (float64 from the API/UI) or a
// string (from an imported config). Returns false when absent or unparseable.
func intParam(p map[string]any, k string) (int, bool) {
	switch t := p[k].(type) {
	case int:
		return t, true
	case int64:
		return int(t), true
	case float64:
		return int(t), true
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(t)); err == nil {
			return n, true
		}
	}
	return 0, false
}

// nfqwsArgs renders the nfqws2 argv from an endpoint's params: the NFQUEUE number plus the desync
// strategy knobs. Only well-formed string tokens are emitted and numbers are range-checked, so a
// malformed param is dropped (the process starts with its own default) rather than bricking it.
func nfqwsArgs(e model.Endpoint) []string {
	p := e.Params
	q := defaultNfqwsQueue
	if n, ok := intParam(p, "qnum"); ok && n >= 0 && n <= 65535 {
		q = n
	}
	args := []string{fmt.Sprintf("--qnum=%d", q)}
	if v := str(p, "dpi_desync"); nfqwsSafe(v) {
		args = append(args, "--dpi-desync="+v)
	}
	if v := str(p, "dpi_desync_fooling"); nfqwsSafe(v) {
		args = append(args, "--dpi-desync-fooling="+v)
	}
	if n, ok := intParam(p, "dpi_desync_ttl"); ok && n > 0 && n <= 255 {
		args = append(args, fmt.Sprintf("--dpi-desync-ttl=%d", n))
	}
	if v := str(p, "dpi_desync_split_pos"); nfqwsSafe(v) {
		args = append(args, "--dpi-desync-split-pos="+v)
	}
	return args
}
