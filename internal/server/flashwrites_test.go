package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"wayhop/internal/atomicfile"
)

func TestFlashWrites_ReportsClasses(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "flashwrites-probe.json")
	if err := atomicfile.Write(p, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = atomicfile.Write(p, []byte("{}"), 0o600) // identical: skipped
	rec := httptest.NewRecorder()
	(&Server{}).handleFlashWrites(rec, httptest.NewRequest(http.MethodGet, "/api/diagnostics/flash", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var body struct {
		FlashBytes uint64                 `json:"flash_bytes"`
		Classes    []atomicfile.WriteStat `json:"classes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, c := range body.Classes {
		if c.Class == "flashwrites-probe.json" {
			if c.Writes < 1 || c.Skipped < 1 || body.FlashBytes < 2 {
				t.Fatalf("class = %+v, total %d", c, body.FlashBytes)
			}
			return
		}
	}
	t.Fatalf("probe class missing: %s", rec.Body.String())
}
