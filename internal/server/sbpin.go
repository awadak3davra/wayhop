package server

import (
	"context"
	"time"

	"wayhop/internal/initserver"
	"wayhop/internal/updater"
)

// singBoxPin resolves a sing-box release over the router's own updater (its api.github.com path,
// mirrors and cache) and returns its version and tarball digests for the server script. version ""
// means the newest stable release. nil on any failure or in demo: the server script then asks
// api.github.com itself and still refuses a tarball it cannot check (SEC-02).
func (s *Server) singBoxPin(ctx context.Context, version string) *initserver.SingBoxPin {
	if s.updater == nil || s.config().Demo {
		return nil
	}
	e := updater.EngineByID("sing-box")
	if e == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var rels []updater.Release
	if version == "" {
		r, err := s.updater.Latest(ctx, *e)
		if err != nil {
			return nil
		}
		rels = []updater.Release{r}
	} else {
		rs, err := s.updater.List(ctx, *e, 15)
		if err != nil {
			return nil
		}
		rels = rs
	}
	want := updater.ParseVersion(version)
	for _, r := range rels {
		if version != "" && (want == "" || updater.ParseVersion(r.Tag) != want) {
			continue
		}
		digests := make(map[string]string, len(r.Assets))
		for _, a := range r.Assets {
			digests[a.Name] = a.Digest
		}
		return initserver.PinFromAssets(r.Tag, digests)
	}
	return nil
}
