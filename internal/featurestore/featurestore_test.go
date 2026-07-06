package featurestore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestOpenAbsentThenRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "features.json")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if s.Get("iptv") != nil {
		t.Fatal("fresh store should have no state")
	}
	if err := s.Set("iptv", json.RawMessage(`{"lists":1}`)); err != nil {
		t.Fatal(err)
	}
	if got := string(s.Get("iptv")); got != `{"lists":1}` {
		t.Fatalf("Get = %q", got)
	}
	// Reopen from disk → persisted (persist-then-commit).
	s2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(s2.Get("iptv")); got != `{"lists":1}` {
		t.Fatalf("after reopen Get = %q, want persisted", got)
	}
}

func TestGetReturnsClone(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "f.json"))
	_ = s.Set("m", json.RawMessage(`{"a":1}`))
	got := s.Get("m")
	got[0] = 'X' // mutate the returned bytes
	if string(s.Get("m")) != `{"a":1}` {
		t.Fatal("Get must return a clone; caller mutation leaked into the store")
	}
}

func TestSetEmptyDeletes(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "f.json"))
	_ = s.Set("m", json.RawMessage(`{"a":1}`))
	if err := s.Delete("m"); err != nil {
		t.Fatal(err)
	}
	if s.Get("m") != nil {
		t.Fatal("Delete should remove the entry")
	}
	if err := s.Delete("never"); err != nil {
		t.Fatalf("deleting an absent id should be a no-op, got %v", err)
	}
	if err := s.Set("", json.RawMessage(`{}`)); err == nil {
		t.Fatal("empty id should error")
	}
}

func TestEmptyFileRecovered(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f.json")
	if err := os.WriteFile(p, []byte("   \n"), 0o600); err != nil { // power-loss artifact
		t.Fatal(err)
	}
	s, err := Open(p)
	if err != nil {
		t.Fatalf("empty/whitespace file must recover, got %v", err)
	}
	if s.Get("x") != nil {
		t.Fatal("recovered store should be empty")
	}
}

func TestJSONHelpers(t *testing.T) {
	type state struct {
		Country string `json:"country"`
		N       int    `json:"n"`
	}
	s, _ := Open(filepath.Join(t.TempDir(), "f.json"))
	if err := s.SetJSON("iptv", state{Country: "it", N: 3}); err != nil {
		t.Fatal(err)
	}
	var got state
	if err := s.GetJSON("iptv", &got); err != nil {
		t.Fatal(err)
	}
	if got.Country != "it" || got.N != 3 {
		t.Fatalf("GetJSON = %+v", got)
	}
	// GetJSON on an unset module leaves v untouched, no error.
	var zero state
	if err := s.GetJSON("nope", &zero); err != nil || zero != (state{}) {
		t.Fatalf("GetJSON(unset) = %+v err=%v", zero, err)
	}
}

// TestConcurrentGetSetNoRace: clone-on-read means lock-free readers never race writers. Run -race.
func TestConcurrentGetSetNoRace(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "f.json"))
	_ = s.Set("m", json.RawMessage(`{"v":0}`))
	var wg sync.WaitGroup
	for r := 0; r < 6; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				b := s.Get("m")
				for range b {
				}
			}
		}()
	}
	for w := 0; w < 3; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				_ = s.Set("m", json.RawMessage(`{"v":9}`))
			}
		}(w)
	}
	wg.Wait()
}
