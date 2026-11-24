package server

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"wayhop/internal/atomicfile"
)

// Flash wear, schema 3. A schema-2 record held every revision inline: 4.6 MB on a measured Keenetic
// (the ipset restore script 3.0 MB as base64, the kernel plan 0.8 MB, the desired profile 0.84 MB),
// rewritten in full for every change of the record, including a 50-byte in-flight marker or an
// acknowledgement: two to three whole rewrites per Apply.
//
// Schema 3 keeps the record itself small and stores each revision's two bulky parts, the desired
// snapshot and the materialization, as content-addressed blobs: apply-blobs/<sha256>.json.gz, the
// SHA-256 of the uncompressed JSON. A blob is written once, when content no blob holds yet appears;
// re-applying an unchanged configuration, a Keep (Live becomes Committed: same blobs), a rollback,
// an ack or a failure write only the small record.
//
// Crash safety is the schema-2 rule unchanged, one level down:
//   - every blob a record names is written durably (atomicfile: temp, fsync, rename, dir fsync)
//     BEFORE the record that names it, so a durable record never points at a missing blob;
//   - the record is replaced atomically, as before;
//   - blobs no record names are deleted only AFTER the new record is durable, so a crash at any
//     point leaves the previous record and all its blobs intact (at worst orphans, swept later);
//   - a blob is verified against its name when loaded; a missing or corrupt one makes the record
//     unreadable, which is the existing "starting with an empty record" path, never fatal.
// What boot converge, rollback and the reconcile loop read is exactly what schema 2 stored; only
// where the bytes sit changed.
//
// The record in memory is unchanged (full revisions), so nothing outside this file knows about blobs.
// The marshalled hash of each published revision is memoized by pointer (revisions are immutable once
// published), so an ack or in-flight write does not re-marshal megabytes either.

const applyBlobDirName = "apply-blobs"

const applyBlobExt = ".json.gz"

// appliedRevisionRef is a revision as schema 3 stores it.
type appliedRevisionRef struct {
	Rev    string `json:"rev"`
	At     int64  `json:"at"`
	BootID string `json:"boot_id,omitempty"`
	// Desired is the blob of the desired snapshot, "" when the revision has none (an imported ledger).
	Desired         string `json:"desired_blob,omitempty"`
	Materialization string `json:"materialization_blob"`
}

// applyStateDisk is applyStateRecord with the revisions replaced by references. Every other field is
// the record's own (applyStateDiskRoundTrip test keeps the two in step).
type applyStateDisk struct {
	Schema              int                  `json:"schema"`
	Committed           *appliedRevisionRef  `json:"committed"`
	Live                *appliedRevisionRef  `json:"live"`
	InFlight            *applyInFlight       `json:"in_flight"`
	Acks                map[string]int64     `json:"acks"`
	Last                applyLastResult      `json:"last"`
	RoutingOff          *routingOffRecord    `json:"routing_off,omitempty"`
	RollbackOutstanding *rollbackOutstanding `json:"rollback_outstanding,omitempty"`
}

// revBlobs memoizes the blob names of one published revision.
type revBlobs struct {
	desiredPtr *appliedDesired
	desired    string
	mat        string
}

func (s *Server) applyBlobDir() string {
	return filepath.Join(filepath.Dir(s.applyState.path), applyBlobDirName)
}

func blobPath(dir, sum string) string { return filepath.Join(dir, sum+applyBlobExt) }

// putBlob marshals v, and writes it as a blob unless one with that content exists. Returns its name.
func putBlob(dir string, v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(raw)
	sum := hex.EncodeToString(h[:])
	p := blobPath(dir, sum)
	if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Size() > 0 {
		atomicfile.NoteSkip(p, int(fi.Size()))
		return sum, nil
	}
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed) // MIPS routers: speed over the last 20 %
	if err != nil {
		return "", err
	}
	if _, err := zw.Write(raw); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	if err := atomicfile.Write(p, buf.Bytes(), 0o600); err != nil {
		return "", fmt.Errorf("write %s: %w", p, err)
	}
	return sum, nil
}

// getBlob reads blob sum into v, verifying the content against the name. A blob that exists but fails
// that check is removed: putBlob skips a name it finds on disk, so a damaged file would be
// named again by the next record of the same configuration and fail every boot until it changed.
//
// Only proven damage removes it (gzip refuses the bytes, the stream is cut short, or the
// hash does not match). A blob whose bytes are intact but do not decode into this build's type, or one
// an I/O error kept from being read, is kept and the error reported: another build may read it.
func getBlob(dir, sum string, v any) error {
	err := readBlob(dir, sum, v)
	if errors.Is(err, errBlobDamaged) && isLowerHexRevision(sum, reviewSHA256HexLen) {
		_ = os.Remove(blobPath(dir, sum))
	}
	return err
}

// errBlobDamaged marks a blob whose bytes are proven wrong.
var errBlobDamaged = errors.New("damaged")

// gzipDamage reports whether a read error from the gzip stream proves the bytes wrong.
func gzipDamage(err error) bool {
	var corrupt flate.CorruptInputError
	return errors.Is(err, gzip.ErrHeader) || errors.Is(err, gzip.ErrChecksum) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, io.EOF) || errors.As(err, &corrupt)
}

func readBlob(dir, sum string, v any) error {
	if !isLowerHexRevision(sum, reviewSHA256HexLen) {
		return fmt.Errorf("malformed blob name %q", sum)
	}
	f, err := os.Open(blobPath(dir, sum))
	if err != nil {
		return err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		if gzipDamage(err) {
			return fmt.Errorf("blob %s: %w: %w", sum, errBlobDamaged, err)
		}
		return fmt.Errorf("blob %s: %w", sum, err)
	}
	// Decode while hashing instead of reading the whole JSON first: on a 256 MB router the inflated
	// materialization (3.8 MB measured) would otherwise sit in memory twice during boot.
	h := sha256.New()
	tee := io.TeeReader(zr, h)
	decErr := json.NewDecoder(tee).Decode(v)
	// The rest of the stream is hashed even after a decode error, to tell damaged bytes from bytes this
	// build cannot decode (the decoder may also stop before the end).
	if _, err := io.Copy(io.Discard, tee); err != nil {
		if gzipDamage(err) {
			return fmt.Errorf("blob %s: %w: %w", sum, errBlobDamaged, err)
		}
		return fmt.Errorf("blob %s: %w", sum, err)
	}
	if hex.EncodeToString(h.Sum(nil)) != sum {
		return fmt.Errorf("blob %s: %w: content does not match its name", sum, errBlobDamaged)
	}
	if decErr != nil {
		return fmt.Errorf("blob %s: intact, but not readable by this build: %w", sum, decErr)
	}
	return nil
}

// refFor stores rev's blobs (when not already stored) and returns its reference.
func (s *Server) refFor(dir string, rev *appliedRevision, memo map[*appliedRevision]revBlobs) (*appliedRevisionRef, error) {
	if rev == nil {
		return nil, nil
	}
	st := &s.applyState
	b, ok := st.blobMemo[rev]
	if !ok || b.desiredPtr != rev.Desired || !blobExists(dir, b.mat) || (b.desired != "" && !blobExists(dir, b.desired)) {
		b = revBlobs{desiredPtr: rev.Desired}
		var err error
		if rev.Desired != nil {
			if b.desired, err = putBlob(dir, rev.Desired); err != nil {
				return nil, err
			}
		}
		if b.mat, err = putBlob(dir, rev.Materialization); err != nil {
			return nil, err
		}
	}
	memo[rev] = b
	return &appliedRevisionRef{Rev: rev.Rev, At: rev.At, BootID: rev.BootID, Desired: b.desired, Materialization: b.mat}, nil
}

func blobExists(dir, sum string) bool {
	if sum == "" {
		return false
	}
	fi, err := os.Stat(blobPath(dir, sum))
	return err == nil && fi.Size() > 0
}

// encodeApplyState writes the blobs st.rec needs and returns the record's bytes. Caller holds mu.
func (s *Server) encodeApplyState() ([]byte, map[string]bool, error) {
	st := &s.applyState
	dir := s.applyBlobDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	memo := map[*appliedRevision]revBlobs{}
	committed, err := s.refFor(dir, st.rec.Committed, memo)
	if err != nil {
		return nil, nil, err
	}
	live, err := s.refFor(dir, st.rec.Live, memo)
	if err != nil {
		return nil, nil, err
	}
	st.blobMemo = memo // only the revisions the record holds now
	keep := map[string]bool{}
	for _, b := range memo {
		keep[b.mat] = true
		if b.desired != "" {
			keep[b.desired] = true
		}
	}
	rec := st.rec
	disk := applyStateDisk{
		Schema: applyStateSchema, Committed: committed, Live: live, InFlight: rec.InFlight,
		Acks: rec.Acks, Last: rec.Last, RoutingOff: rec.RoutingOff, RollbackOutstanding: rec.RollbackOutstanding,
	}
	b, err := json.Marshal(disk)
	return b, keep, err
}

// sweepApplyBlobs removes the blobs keep does not name, and temps a crash left. Only after the record
// naming keep is durable.
func (s *Server) sweepApplyBlobs(keep map[string]bool) {
	dir := s.applyBlobDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !e.Type().IsRegular() || !strings.HasSuffix(name, applyBlobExt) {
			continue
		}
		if keep[strings.TrimSuffix(name, applyBlobExt)] {
			continue
		}
		_ = os.Remove(filepath.Join(dir, name))
	}
}

// decodeApplyState reads a schema-2 (inline) or schema-3 (blob) record. Caller holds mu.
func (s *Server) decodeApplyState(raw []byte) (applyStateRecord, error) {
	var head struct {
		Schema int `json:"schema"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return applyStateRecord{}, err
	}
	switch head.Schema {
	case 2:
		// The inline format: read as it always was; the next write stores it as schema 3.
		var rec applyStateRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			return applyStateRecord{}, err
		}
		rec.Schema = applyStateSchema
		return rec, nil
	case applyStateSchema:
	default:
		return applyStateRecord{}, fmt.Errorf("unknown schema %d", head.Schema)
	}
	var disk applyStateDisk
	if err := json.Unmarshal(raw, &disk); err != nil {
		return applyStateRecord{}, err
	}
	dir := s.applyBlobDir()
	memo := map[*appliedRevision]revBlobs{}
	load := func(ref *appliedRevisionRef) (*appliedRevision, error) {
		if ref == nil {
			return nil, nil
		}
		rev := &appliedRevision{Rev: ref.Rev, At: ref.At, BootID: ref.BootID}
		if ref.Desired != "" {
			rev.Desired = &appliedDesired{}
			if err := getBlob(dir, ref.Desired, rev.Desired); err != nil {
				return nil, fmt.Errorf("revision %s desired: %w", ref.Rev, err)
			}
		}
		if err := getBlob(dir, ref.Materialization, &rev.Materialization); err != nil {
			return nil, fmt.Errorf("revision %s materialization: %w", ref.Rev, err)
		}
		memo[rev] = revBlobs{desiredPtr: rev.Desired, desired: ref.Desired, mat: ref.Materialization}
		return rev, nil
	}
	rec := applyStateRecord{
		Schema: applyStateSchema, InFlight: disk.InFlight, Acks: disk.Acks, Last: disk.Last,
		RoutingOff: disk.RoutingOff, RollbackOutstanding: disk.RollbackOutstanding,
	}
	var err error
	if rec.Committed, err = load(disk.Committed); err != nil {
		return applyStateRecord{}, err
	}
	if rec.Live, err = load(disk.Live); err != nil {
		return applyStateRecord{}, err
	}
	s.applyState.blobMemo = memo
	return rec, nil
}

// legacyApplyStateSchema is the inline record every build before the blob store reads. Those builds
// read any other schema as "unreadable" and start with an empty record: no boot converge, nothing
// owned, so the installed plane is orphaned.
const legacyApplyStateSchema = 2

// writeLegacyApplyState rewrites the record as schema 2 (inline revisions, the shape decodeApplyState
// still reads), so the binary about to replace this one, older or newer, reads it. The self-update
// runs it before every swap; a downgrade by hand runs `wayhop apply-state-v2 <path>`. It costs one
// full-size write per update (about 4.6 MB on a large profile); the next persist by a blob-store
// build turns it back into schema 3. The blob directory is left alone: an old build ignores it, a new
// one sweeps what the record no longer names.
func (s *Server) writeLegacyApplyState() error {
	st := &s.applyState
	st.mu.Lock()
	defer st.mu.Unlock()
	rec := *s.stateLocked()
	if _, err := os.Stat(st.path); errors.Is(err, fs.ErrNotExist) {
		return nil // nothing recorded yet: an old build starts the same way
	}
	rec.Schema = legacyApplyStateSchema
	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("apply-state: encode schema %d: %w", legacyApplyStateSchema, err)
	}
	if err := atomicfile.Write(st.path, b, 0o600); err != nil {
		return fmt.Errorf("apply-state: write schema %d: %w", legacyApplyStateSchema, err)
	}
	return nil
}

// WriteLegacyApplyState is writeLegacyApplyState for the file at path, from the command line, with no
// daemon running. A record it cannot read is left as it is and reported.
func WriteLegacyApplyState(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("apply-state: %w", err)
	}
	s := &Server{applyStateDir: filepath.Dir(path)}
	s.applyState.path = path
	rec, err := s.decodeApplyState(raw)
	if err != nil {
		return fmt.Errorf("apply-state: %s is unreadable, left as it is: %w", path, err)
	}
	if rec.Acks == nil {
		rec.Acks = map[string]int64{}
	}
	s.applyState.loaded, s.applyState.rec = true, rec
	return s.writeLegacyApplyState()
}
