package server

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/core"
)

// The generator renders the sing-box 1.12 schema unless it is told the core is 1.14 or newer
// (generator.Options.CoreVersion). On 1.15 that schema no longer starts: dns.independent_cache stops
// the core at startup and a remote rule-set's download_detour stops it at the first fetch. So every
// config WayHop writes for the router has to say which sing-box will read it.
//
// The Apply pipeline already has that answer: its host snapshot runs the configured binary's
// `version` and pins it to the binary's digest, and materialize passes it on. Generate, the preview
// and the plugin sync build their options here instead, from the same configured binary.

// coreVersionProbeTimeout bounds one `sing-box version` run; the capability probe allows the same.
const coreVersionProbeTimeout = 4 * time.Second

// coreVersionRetry is how long a failed probe of an unchanged binary is remembered before it is
// tried again: long enough that a broken binary is not run on every preview, short enough that a
// transient failure (the binary busy while the updater writes it) does not pin the old schema.
const coreVersionRetry = time.Minute

// coreVersionCache holds the last `sing-box version` answer and the binary identity it came from.
type coreVersionCache struct {
	mu       sync.Mutex
	key      string
	version  string
	failedAt time.Time
}

// coreVersion returns the configured sing-box's raw `version` output for the generator, or "" when
// it is unknown, which keeps the 1.12 schema every supported core accepts. A demo daemon answers ""
// so its config stays the same on every host: the sing-box on a developer's machine is not the
// router's. The binary is run again only when its path, size or modification time changes, which
// is what an engine update changes.
func (s *Server) coreVersion(c config.Config) string {
	if c.Demo {
		return ""
	}
	bin := strings.TrimSpace(c.SingBox.Bin)
	if bin == "" {
		return ""
	}
	if found, err := exec.LookPath(bin); err == nil {
		bin = found
	}
	st, err := os.Stat(bin)
	if err != nil || st.IsDir() {
		return ""
	}
	key := fmt.Sprintf("%s|%d|%d", bin, st.Size(), st.ModTime().UnixNano())

	s.coreVer.mu.Lock()
	defer s.coreVer.mu.Unlock()
	if s.coreVer.key == key && (s.coreVer.version != "" || time.Since(s.coreVer.failedAt) < coreVersionRetry) {
		return s.coreVer.version
	}
	probe := s.coreVersionOf
	if probe == nil {
		probe = func(ctx context.Context, bin string) (string, error) {
			return core.New(bin, c.SingBox.Config).Version(ctx)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), coreVersionProbeTimeout)
	out, err := probe(ctx, bin)
	cancel()
	s.coreVer.key = key
	if err != nil {
		s.coreVer.version, s.coreVer.failedAt = "", time.Now()
		return ""
	}
	s.coreVer.version, s.coreVer.failedAt = strings.TrimSpace(out), time.Time{}
	return s.coreVer.version
}

// executionCoreVersion is the version an Apply's host snapshot read from the configured binary,
// pinned to that binary's digest, so the config is rendered for the core that will run it. "" unless
// the identity probe completed.
func executionCoreVersion(h HostSnapshotV1) string {
	if h.Core.State != coreStateReady || !h.Core.Runnable {
		return ""
	}
	return h.Core.Version
}
