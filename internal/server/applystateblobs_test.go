package server

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func applyblobs_files(t *testing.T, s *Server) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(s.applyStateDir, applyBlobDirName))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// bigMaterialization stands in for a router's kernel plane: a large, compressible blob.
func applyblobs_bigMaterialization() executionMaterializationV1 {
	m := applystate_demoMaterialization()
	var b strings.Builder
	for i := 0; i < 20000; i++ {
		b.WriteString("add wh_ru 10.")
		b.WriteString(string(rune('0' + i%10)))
		b.WriteString(".0.0/16\n")
	}
	m.Core.Config = []byte(b.String())
	return m
}

// The record is small and names blobs; the bulky parts are written once and shared.
func TestApplyStateBlobs_RecordShapeAndDedup(t *testing.T) {
	s := applystate_server(t)
	if err := s.store.UpsertEndpoint(profilehandlers_endpoint("v1", "NL")); err != nil {
		t.Fatal(err)
	}
	desired, err := s.captureDesiredSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	mat := applyblobs_bigMaterialization()
	live := &appliedRevision{Rev: desired.DesiredRev, At: 1, Desired: &appliedDesired{Profile: desired.Profile, Config: desired.Config}, Materialization: mat}
	s.setInFlight(false, live.Rev)
	s.recordApplied(false, live)
	path := filepath.Join(s.applyStateDir, applyStateFileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 2048 || !bytes.Contains(raw, []byte(`"materialization_blob"`)) || bytes.Contains(raw, []byte("wh_ru")) {
		t.Fatalf("record is not the small reference form (%d bytes): %.300s", len(raw), raw)
	}
	if got := applyblobs_files(t, s); len(got) != 2 {
		t.Fatalf("blobs = %v, want desired + materialization", got)
	}
	blobDir := filepath.Join(s.applyStateDir, applyBlobDirName)
	var total int64
	for _, n := range applyblobs_files(t, s) {
		fi, _ := os.Stat(filepath.Join(blobDir, n))
		total += fi.Size()
	}
	if total > int64(len(mat.Core.Config))/4 {
		t.Fatalf("blobs not compressed: %d bytes for a %d-byte materialization", total, len(mat.Core.Config))
	}
	// Ack, failure and Keep rewrite only the record: no new blob, existing ones untouched.
	stamp := map[string]int64{}
	for _, n := range applyblobs_files(t, s) {
		fi, _ := os.Stat(filepath.Join(blobDir, n))
		stamp[n] = fi.ModTime().UnixNano()
	}
	s.setAcks([]string{"x"}, true)
	s.recordCommit()
	s.recordFailure("other", nil)
	if got := applyblobs_files(t, s); len(got) != 2 {
		t.Fatalf("blobs after ack/keep = %v", got)
	}
	for _, n := range applyblobs_files(t, s) {
		fi, _ := os.Stat(filepath.Join(blobDir, n))
		if fi.ModTime().UnixNano() != stamp[n] {
			t.Fatalf("blob %s rewritten by a record-only change", n)
		}
	}
	// A restarted daemon reads the same revision back.
	again := &Server{cfg: s.cfg, store: s.store, applyStateDir: s.applyStateDir}
	c := again.committedRevision()
	if c == nil || c.Rev != live.Rev || !bytes.Equal(c.Materialization.Core.Config, mat.Core.Config) || c.Desired == nil ||
		len(c.Desired.Profile.Endpoints) != 1 {
		t.Fatalf("reloaded committed revision differs: %+v", c)
	}
}

// Rolling back a Test drops its blobs once the new record is durable; the committed ones stay.
func TestApplyStateBlobs_SweepAfterRollback(t *testing.T) {
	s := applystate_server(t)
	s.recordApplied(true, &appliedRevision{Rev: "c", At: 1, Materialization: applystate_demoMaterialization()})
	s.recordApplied(false, &appliedRevision{Rev: "l", At: 2, Materialization: applyblobs_bigMaterialization()})
	if got := applyblobs_files(t, s); len(got) != 2 {
		t.Fatalf("blobs with committed + live = %v", got)
	}
	s.recordRollback()
	if got := applyblobs_files(t, s); len(got) != 1 {
		t.Fatalf("blobs after rollback = %v, want only the committed one", got)
	}
}

// Simulated crashes around a write: blobs written but the record not replaced (orphans), and a record
// whose blob is gone. The first recovers with the previous record and sweeps the orphan; the second is
// the unreadable-record path (empty record, logged), never a panic or a half-loaded revision.
func TestApplyStateBlobs_CrashRecovery(t *testing.T) {
	s := applystate_server(t)
	committed := &appliedRevision{Rev: "c", At: 1, Materialization: applyboot_kernelMaterialization()}
	s.recordApplied(true, committed)
	recPath := filepath.Join(s.applyStateDir, applyStateFileName)
	before, _ := os.ReadFile(recPath)

	// Crash after the blobs of a new Apply were written, before its record: write the blob by hand.
	blobDir := filepath.Join(s.applyStateDir, applyBlobDirName)
	orphan, err := putBlob(blobDir, applyblobs_bigMaterialization())
	if err != nil {
		t.Fatal(err)
	}
	// And a temp of a blob write that died mid-way.
	tmp := filepath.Join(blobDir, orphan+applyBlobExt+".123456.tmp")
	if err := os.WriteFile(tmp, []byte("torn"), 0o600); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(recPath); !bytes.Equal(before, after) {
		t.Fatal("test setup changed the record")
	}
	boot := &Server{cfg: s.cfg, store: s.store, applyStateDir: s.applyStateDir}
	c := boot.committedRevision()
	if c == nil || c.Rev != "c" || len(c.Materialization.Kernel.Retire) != 1 {
		t.Fatalf("boot after the crash lost the committed revision: %+v", c)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatalf("torn blob temp not removed at load: %v", err)
	}
	boot.setAcks([]string{"a"}, true) // the next record write sweeps the orphan
	if _, err := os.Stat(blobPath(blobDir, orphan)); !os.IsNotExist(err) {
		t.Fatalf("orphan blob survived the next write: %v", err)
	}

	// A record naming a blob that is gone (or corrupt) is unreadable as a whole.
	var disk applyStateDisk
	raw, _ := os.ReadFile(recPath)
	if err := json.Unmarshal(raw, &disk); err != nil || disk.Committed == nil {
		t.Fatalf("record: %v", err)
	}
	if err := os.WriteFile(blobPath(blobDir, disk.Committed.Materialization), []byte("not gzip"), 0o600); err != nil {
		t.Fatal(err)
	}
	broken := &Server{cfg: s.cfg, store: s.store, applyStateDir: s.applyStateDir}
	if broken.committedRevision() != nil {
		t.Fatal("a corrupt blob must not load as a revision")
	}
}

// A schema-2 record (revisions inline) loads, and the next write converts it to schema 3 with the
// same content.
func TestApplyStateBlobs_ReadsSchema2(t *testing.T) {
	s := applystate_server(t)
	m := applyboot_kernelMaterialization()
	v2 := applyStateRecord{Schema: 2, Committed: &appliedRevision{Rev: "c", At: 7, Materialization: m}, Acks: map[string]int64{"k": 1},
		Last: applyLastResult{At: 7, OK: true, Rev: "c"}}
	raw, _ := json.Marshal(v2)
	if err := os.WriteFile(filepath.Join(s.applyStateDir, applyStateFileName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	c := s.committedRevision()
	if c == nil || c.Rev != "c" || c.At != 7 || len(c.Materialization.Kernel.Retire) != 1 || !s.isAcked("k") {
		t.Fatalf("schema-2 record not read: %+v", c)
	}
	s.setAcks([]string{"k2"}, true)
	out, _ := os.ReadFile(filepath.Join(s.applyStateDir, applyStateFileName))
	if !bytes.Contains(out, []byte(`"schema":3`)) || !bytes.Contains(out, []byte("materialization_blob")) {
		t.Fatalf("not converted: %s", out)
	}
	again := &Server{cfg: s.cfg, store: s.store, applyStateDir: s.applyStateDir}
	if c2 := again.committedRevision(); c2 == nil || !reflect.DeepEqual(c2.Materialization, c.Materialization) {
		t.Fatal("conversion changed the committed materialization")
	}
}

// applyStateDisk must carry every field of applyStateRecord: a field added to the record and not here
// would silently stop surviving a restart.
func TestApplyStateDisk_MirrorsRecord(t *testing.T) {
	rt, dt := reflect.TypeOf(applyStateRecord{}), reflect.TypeOf(applyStateDisk{})
	if rt.NumField() != dt.NumField() {
		t.Fatalf("applyStateRecord has %d fields, applyStateDisk %d", rt.NumField(), dt.NumField())
	}
	for i := 0; i < rt.NumField(); i++ {
		rf := rt.Field(i)
		df, ok := dt.FieldByName(rf.Name)
		if !ok || df.Tag.Get("json") != rf.Tag.Get("json") {
			t.Errorf("field %s (json %q) not mirrored", rf.Name, rf.Tag.Get("json"))
		}
	}
}
