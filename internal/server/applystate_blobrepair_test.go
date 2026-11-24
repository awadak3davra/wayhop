package server

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

// Review F8: a blob that fails its hash is replaced by the next write of the same content instead of
// being named again (putBlob skips a name it finds on disk).
func TestDamagedBlobIsRewritten(t *testing.T) {
	dir := t.TempDir()
	v := map[string]any{"plan": []string{"10.0.0.0/8", "198.51.100.0/24"}}
	sum, err := putBlob(dir, v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(blobPath(dir, sum), []byte("not gzip at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := getBlob(dir, sum, &got); err == nil {
		t.Fatal("a damaged blob verified")
	}
	if _, err := putBlob(dir, v); err != nil {
		t.Fatal(err)
	}
	if err := getBlob(dir, sum, &got); err != nil {
		t.Fatalf("the same configuration still names the damaged blob: %v", err)
	}
}

// Review F7: before a binary swap the record is rewritten in the inline schema 2 that builds before
// the blob store read; such a build (here: a plain json decode of schema 2, which is all it does)
// gets the committed revision back, and this build still reads it.
func TestLegacyApplyStateForDowngrade(t *testing.T) {
	s := applystate_server(t)
	mat := applystate_demoMaterialization()
	s.recordApplied(true, &appliedRevision{Rev: "c1", At: 1, Materialization: mat})
	if err := s.writeLegacyApplyState(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(s.applyStateFile())
	if err != nil {
		t.Fatal(err)
	}
	var old applyStateRecord // the shape the hotfix line unmarshals
	if err := json.Unmarshal(raw, &old); err != nil || old.Schema != 2 || old.Committed == nil || old.Committed.Rev != "c1" ||
		!bytes.Equal(old.Committed.Materialization.Core.Config, mat.Core.Config) {
		t.Fatalf("old build would not read it: schema %d err %v rec %+v", old.Schema, err, old.Committed)
	}
	again := &Server{cfg: s.cfg, store: s.store, applyStateDir: s.applyStateDir}
	if c := again.committedRevision(); c == nil || c.Rev != "c1" {
		t.Fatalf("this build lost the record: %+v", c)
	}
	// The command-line form works on the file alone.
	s.recordCommit() // schema 3 again
	if err := WriteLegacyApplyState(s.applyStateFile()); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(s.applyStateFile())
	if err := json.Unmarshal(raw, &old); err != nil || old.Schema != 2 || old.Committed == nil {
		t.Fatalf("cli: schema %d err %v", old.Schema, err)
	}
}

// Only proven damage (gzip or the hash says the bytes are wrong, or cut short) removes a
// blob. One whose bytes match its name but do not decode into this build's type is kept and reported:
// removing it took the committed plane's record away from every build.
func TestBlobKeptUnlessItsBytesAreDamaged(t *testing.T) {
	dir := t.TempDir()
	sum, err := putBlob(dir, map[string]any{"plan": "a string"})
	if err != nil {
		t.Fatal(err)
	}
	var wrongType struct {
		Plan []int `json:"plan"`
	}
	if err := getBlob(dir, sum, &wrongType); err == nil {
		t.Fatal("a type mismatch decoded")
	}
	if _, err := os.Stat(blobPath(dir, sum)); err != nil {
		t.Fatal("an intact blob was removed for a decode error")
	}
	raw, _ := os.ReadFile(blobPath(dir, sum))
	flipped := append([]byte(nil), raw...)
	flipped[len(flipped)-9] ^= 0xff // the last deflate byte, before the CRC trailer
	for name, bad := range map[string][]byte{"cut": raw[:len(raw)-6], "flipped": flipped} {
		_ = os.WriteFile(blobPath(dir, sum), bad, 0o600)
		var v map[string]any
		if err := getBlob(dir, sum, &v); err == nil {
			t.Fatalf("%s: a damaged blob read", name)
		}
		if _, err := os.Stat(blobPath(dir, sum)); err == nil {
			t.Fatalf("%s: a damaged blob was kept", name)
		}
	}
}
