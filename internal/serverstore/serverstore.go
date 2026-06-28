// Package serverstore persists the list of VPN servers the user manages for
// redundancy. It mirrors the tiny atomic-JSON pattern of internal/store. It NEVER
// stores SSH credentials — only the reachable address, user, and what was set up.
package serverstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"

	"wakeroute/internal/atomicfile"
)

// Server is one managed VPN server. No password/key is ever persisted here.
type Server struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Host      string   `json:"host"`
	Port      int      `json:"port"`
	User      string   `json:"user"`
	Installed []string `json:"installed"` // protocol ids provisioned on it
	Hardened  bool     `json:"hardened"`  // password auth disabled + key installed
	Note      string   `json:"note,omitempty"`
	CreatedAt string   `json:"created_at,omitempty"`
	LastJob   string   `json:"last_job,omitempty"` // most recent job id
}

// Store guards the server list persisted at path.
type Store struct {
	path string
	mu   sync.RWMutex
	srv  []Server
}

// Open loads servers.json, creating an empty list if absent.
func Open(path string) (*Store, error) {
	s := &Store{path: path}
	data, err := os.ReadFile(path)
	// Treat a missing OR empty/whitespace-only file identically: start from an empty
	// list and rewrite a valid file. An existing zero-length / whitespace-only file is
	// the canonical power-loss / jffs2 / overlayfs artifact on a router; it reads as
	// (nil, nil), would otherwise reach json.Unmarshal([]byte{}) → "unexpected end of
	// JSON input" → the daemon refuses to boot. A genuinely-corrupt NON-empty file
	// still falls through to the parse error below.
	if errors.Is(err, os.ErrNotExist) || (err == nil && len(bytes.TrimSpace(data)) == 0) {
		if err == nil {
			log.Printf("wakeroute: servers %s is empty; recreating empty list", path)
			if werr := s.saveLocked(s.srv); werr != nil {
				return nil, fmt.Errorf("rewrite empty servers %s: %w", path, werr)
			}
		}
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read servers %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &s.srv); err != nil {
		return nil, fmt.Errorf("parse servers %s: %w", path, err)
	}
	return s, nil
}

// List returns a copy of the server list. Each Server's Installed slice is
// deep-cloned: a shallow copy aliases the backing array, which a lock-free reader
// (e.g. the GET /servers handler marshalling the result) would race if a writer
// later mutates Installed in place. Mirrors store.Profile()'s defensive cloning.
func (s *Store) List() []Server {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Server, len(s.srv))
	copy(out, s.srv)
	for i := range out {
		out[i].Installed = append([]string{}, out[i].Installed...)
	}
	return out
}

// Get returns a server by id, with its Installed slice cloned (see List).
func (s *Store) Get(id string) (Server, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sv := range s.srv {
		if sv.ID == id {
			sv.Installed = append([]string{}, sv.Installed...)
			return sv, true
		}
	}
	return Server{}, false
}

// Upsert inserts or replaces a server by ID (ID is required).
//
// Persist-then-commit: it builds the candidate slice, persists it via saveLocked,
// and only swaps s.srv into place on success. If the underlying atomic write fails
// (e.g. a full overlay / EROFS) the in-memory list is left untouched, so it can
// never diverge from disk — a "saved" record that exists only in RAM and vanishes
// on reboot, or a still-present record reads claim was deleted.
func (s *Store) Upsert(sv Server) error {
	if sv.ID == "" {
		return errors.New("server id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cand := make([]Server, len(s.srv))
	copy(cand, s.srv)
	replaced := false
	for i := range cand {
		if cand[i].ID == sv.ID {
			cand[i] = sv
			replaced = true
			break
		}
	}
	if !replaced {
		cand = append(cand, sv)
	}
	if err := s.saveLocked(cand); err != nil {
		return err
	}
	s.srv = cand
	return nil
}

// Patch applies fn to the stored server with id (if present) and persists.
// Persist-then-commit (see Upsert): fn is applied to a COPY of the element, the
// candidate slice is persisted, and s.srv is swapped only on a successful write.
func (s *Store) Patch(id string, fn func(*Server)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.srv {
		if s.srv[i].ID == id {
			cand := make([]Server, len(s.srv))
			copy(cand, s.srv)
			// Deep-clone the only reference field: a shallow copy aliases the live
			// element's Installed backing array, so an in-place mutation in fn (e.g.
			// append(sv.Installed[:0], ...)) would leak into s.srv even when the save
			// below fails, breaking persist-then-commit. Mirrors List/Get's cloning.
			cand[i].Installed = append([]string{}, cand[i].Installed...)
			fn(&cand[i]) // mutate the copy, not the live element
			if err := s.saveLocked(cand); err != nil {
				return err
			}
			s.srv = cand
			return nil
		}
	}
	return fmt.Errorf("server %q not found", id)
}

// Delete removes a server by id.
// Persist-then-commit (see Upsert): the surviving subset is persisted first and
// s.srv is replaced only on a successful write.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cand := make([]Server, 0, len(s.srv))
	found := false
	for _, sv := range s.srv {
		if sv.ID == id {
			found = true
			continue
		}
		cand = append(cand, sv)
	}
	if !found {
		return fmt.Errorf("server %q not found", id)
	}
	if err := s.saveLocked(cand); err != nil {
		return err
	}
	s.srv = cand
	return nil
}

// saveLocked atomically + durably writes srv. Callers must hold s.mu (write). It
// takes the candidate slice as an argument so a failed write never touches the
// committed in-memory s.srv (persist-then-commit; see Upsert).
func (s *Store) saveLocked(srv []Server) error {
	if s.path == "" {
		return errors.New("server store has no path")
	}
	data, err := json.MarshalIndent(srv, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(s.path, data, 0o600)
}
