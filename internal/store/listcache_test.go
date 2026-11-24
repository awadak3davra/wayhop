package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wayhop/internal/atomicfile"
	"wayhop/internal/model"
)

func feedList(id string) model.RoutingList {
	return model.RoutingList{ID: id, Name: id, Outbound: "direct", Enabled: true, CIDRSource: "https://feed.example/" + id + ".txt"}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The feed cache lives in memory and in list-cache.json, never in profile.json, and survives a reopen.
func TestListCache_NotInProfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertRoutingList(feedList("ru")); err != nil {
		t.Fatal(err)
	}
	n, err := s.SetRoutingListCaches(map[string]CacheUpdate{"ru": {Source: "https://feed.example/ru.txt", CIDRs: []string{"10.1.0.0/16", "10.2.0.0/16"}}})
	if err != nil || n != 1 {
		t.Fatalf("SetRoutingListCaches = %d, %v", n, err)
	}
	if got := s.Profile().RoutingLists[0].CIDRCache; len(got) != 2 {
		t.Fatalf("in-memory cache = %v", got)
	}
	prof := readFile(t, path)
	if strings.Contains(prof, "cidr_cache") || strings.Contains(prof, "10.1.0.0") || strings.Contains(prof, "cidr_refreshed") {
		t.Fatalf("profile.json carries the feed cache:\n%s", prof)
	}
	if lc := readFile(t, filepath.Join(dir, ListCacheFileName)); !strings.Contains(lc, "10.1.0.0/16") {
		t.Fatalf("list-cache.json lacks the cache: %s", lc)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	rl := s2.Profile().RoutingLists[0]
	if len(rl.CIDRCache) != 2 || rl.CIDRRefreshed == 0 {
		t.Fatalf("reopened cache = %v (refreshed %d)", rl.CIDRCache, rl.CIDRRefreshed)
	}
}

// An old-format profile.json with inline caches loads with them, and the first write moves them to
// list-cache.json (written first) and drops them from profile.json.
func TestListCache_MigratesOldProfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	old := model.Profile{RoutingLists: []model.RoutingList{feedList("ru")}}
	old.RoutingLists[0].CIDRCache = []string{"192.0.2.0/24"}
	old.RoutingLists[0].CIDRRefreshed = 1_700_000_000
	old.RoutingLists[0].DomainSource = "https://feed.example/names.txt"
	old.RoutingLists[0].DomainCache = []string{"example.org"}
	old.RoutingLists[0].DomainRefreshed = 1_700_000_001
	raw, _ := json.MarshalIndent(old, "", "  ")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := OpenWith(path, Options{CacheFlushEvery: 24 * time.Hour, CacheDebounce: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if rl := s.Profile().RoutingLists[0]; len(rl.CIDRCache) != 1 || len(rl.DomainCache) != 1 {
		t.Fatalf("inline caches not loaded: %+v", rl)
	}
	// Reading alone migrates nothing.
	if _, err := os.Stat(filepath.Join(dir, ListCacheFileName)); !os.IsNotExist(err) {
		t.Fatalf("list-cache.json written on open: %v", err)
	}
	if err := s.UpsertDeviceGroup(model.DeviceGroup{ID: "kids", Name: "Kids"}); err != nil {
		t.Fatal(err)
	}
	prof := readFile(t, path)
	if strings.Contains(prof, "cidr_cache") || strings.Contains(prof, "domain_cache") || !strings.Contains(prof, "kids") {
		t.Fatalf("profile.json not migrated:\n%s", prof)
	}
	lc := readFile(t, filepath.Join(dir, ListCacheFileName))
	if !strings.Contains(lc, "192.0.2.0/24") || !strings.Contains(lc, "example.org") || !strings.Contains(lc, "1700000001") {
		t.Fatalf("list-cache.json after migration: %s", lc)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	rl := s2.Profile().RoutingLists[0]
	if len(rl.CIDRCache) != 1 || rl.CIDRRefreshed != 1_700_000_000 || rl.DomainRefreshed != 1_700_000_001 {
		t.Fatalf("migrated caches lost on reopen: %+v", rl)
	}
}

// A feed refresh never writes profile.json, and with the production policy list-cache.json is written
// once, later (flush on shutdown here), not on each refresh.
func TestListCache_RefreshDoesNotTouchProfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	s, err := OpenWith(path, Options{CacheFlushEvery: 24 * time.Hour, CacheDebounce: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertRoutingList(feedList("ru")); err != nil {
		t.Fatal(err)
	}
	before := readFile(t, path)
	stamp := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		cidrs := []string{"10.0.0.0/8", "172.16." + string(rune('0'+i)) + ".0/24"}
		if _, err := s.SetRoutingListCaches(map[string]CacheUpdate{"ru": {Source: "https://feed.example/ru.txt", CIDRs: cidrs}}); err != nil {
			t.Fatal(err)
		}
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.ModTime().Equal(stamp) || readFile(t, path) != before {
		t.Fatal("a feed refresh rewrote profile.json")
	}
	if _, err := os.Stat(filepath.Join(dir, ListCacheFileName)); !os.IsNotExist(err) {
		t.Fatalf("list-cache.json written before the coalescing window: %v", err)
	}
	if err := s.Close(); err != nil { // graceful shutdown flush
		t.Fatal(err)
	}
	if lc := readFile(t, filepath.Join(dir, ListCacheFileName)); !strings.Contains(lc, "172.16.2.0/24") {
		t.Fatalf("shutdown flush did not write the last cache: %s", lc)
	}
}

// A cache entry recorded for another source is not merged into a re-pointed list.
func TestListCache_IgnoresStaleSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	prof := model.Profile{RoutingLists: []model.RoutingList{feedList("ru")}}
	raw, _ := json.Marshal(prof)
	_ = os.WriteFile(path, raw, 0o600)
	lc, _ := json.Marshal(listCacheFile{Schema: listCacheSchema, Lists: []listCacheEntry{{ID: "ru", CIDRSource: "https://old.example/x", CIDRs: []string{"198.51.100.0/24"}, CIDRRefreshed: 5}}})
	_ = os.WriteFile(filepath.Join(dir, ListCacheFileName), lc, 0o600)
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got := s.Profile().RoutingLists[0].CIDRCache; len(got) != 0 {
		t.Fatalf("stale-source cache merged: %v", got)
	}
}

// listCacheWrites is the process's tally of list-cache.json writes and skipped rewrites so far.
func listCacheWrites() (writes, skipped uint64) {
	all, _ := atomicfile.Stats()
	for _, st := range all {
		if strings.Contains(st.Class, "list-cache") {
			writes += st.Writes
			skipped += st.Skipped
		}
	}
	return writes, skipped
}

// One write of list-cache.json per change. The migration rendered the caches of the
// profile on disk BEFORE the write, so a write that also changed a cache (a feed refresh, the boot-time
// refresh racing the first Apply) wrote the file twice: the old caches, then the new ones at the
// commit's flush. And every publish marked the cache writer, so each commit rendered the whole cache
// file again only to find it unchanged.
func TestListCache_OneWritePerChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	old := model.Profile{RoutingLists: []model.RoutingList{feedList("ru")}}
	old.RoutingLists[0].CIDRCache = []string{"192.0.2.0/24"}
	old.RoutingLists[0].CIDRRefreshed = 1_700_000_000
	raw, _ := json.MarshalIndent(old, "", "  ")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := OpenWith(path, Options{CacheFlushEvery: 24 * time.Hour, CacheDebounce: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	w0, _ := listCacheWrites()
	// The first write after the upgrade is a feed refresh: the migration and the refresh in one.
	if _, err := s.SetRoutingListCaches(map[string]CacheUpdate{"ru": {Source: "https://feed.example/ru.txt", CIDRs: []string{"198.51.100.0/24"}}}); err != nil {
		t.Fatal(err)
	}
	if err := s.FlushListCaches(); err != nil { // the commit's flush
		t.Fatal(err)
	}
	if w, _ := listCacheWrites(); w-w0 != 1 {
		t.Fatalf("list-cache.json written %d times for one change", w-w0)
	}
	if lc := readFile(t, filepath.Join(dir, ListCacheFileName)); !strings.Contains(lc, "198.51.100.0/24") {
		t.Fatalf("list-cache.json: %s", lc)
	}
	// A write that changes no cache does not even render the file at the commit.
	w1, k1 := listCacheWrites()
	if err := s.UpsertDeviceGroup(model.DeviceGroup{ID: "kids", Name: "Kids"}); err != nil {
		t.Fatal(err)
	}
	if err := s.FlushListCaches(); err != nil {
		t.Fatal(err)
	}
	if w, k := listCacheWrites(); w != w1 || k != k1 {
		t.Fatalf("an edit without a cache change: %d writes, %d rendered-and-skipped", w-w1, k-k1)
	}
}
