// Package featurestore persists per-plugin (feature-module) state as one atomic copy-on-write JSON
// file (features.json), mirroring internal/serverstore's persist-then-commit pattern. Each module
// owns an OPAQUE json.RawMessage blob keyed by its module id — so featurestore stays decoupled from
// every module's schema (the module marshals/unmarshals its own type via GetJSON/SetJSON). Get
// returns a CLONE; a write persists to disk BEFORE swapping the in-memory map, so RAM never diverges
// from disk (a "saved" record can't exist only in memory, nor a "deleted" one linger on disk).
package featurestore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"

	"wayhop/internal/atomicfile"
)

// Store guards the per-module state map persisted at path.
type Store struct {
	path string
	mu   sync.RWMutex
	data map[string]json.RawMessage
}

// Open loads features.json, creating an empty store if the file is absent OR empty/whitespace-only
// (the canonical power-loss / jffs2 / overlayfs artifact on a router — read as (nil,nil) or empty,
// which would otherwise crash json.Unmarshal and refuse boot; same handling as serverstore.Open).
func Open(path string) (*Store, error) {
	s := &Store{path: path, data: map[string]json.RawMessage{}}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) || (err == nil && len(bytes.TrimSpace(raw)) == 0) {
		if err == nil {
			log.Printf("wayhop: features %s is empty; recreating empty store", path)
			if werr := s.saveLocked(s.data); werr != nil {
				return nil, fmt.Errorf("rewrite empty features %s: %w", path, werr)
			}
		}
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read features %s: %w", path, err)
	}
	if err := json.Unmarshal(raw, &s.data); err != nil {
		return nil, fmt.Errorf("parse features %s: %w", path, err)
	}
	if s.data == nil {
		s.data = map[string]json.RawMessage{}
	}
	return s, nil
}

// Get returns a CLONE of a module's state blob (nil if unset). The clone protects the caller from a
// later in-place mutation of the backing bytes — a lock-free reader must never alias the stored map.
func (s *Store) Get(id string) json.RawMessage {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.data[id]
	if !ok {
		return nil
	}
	return append(json.RawMessage(nil), b...)
}

// Set persists a module's state blob (persist-then-commit: the candidate map is written to disk
// first, s.data is swapped only on success). An empty/nil blob deletes the entry. id is required.
func (s *Store) Set(id string, v json.RawMessage) error {
	if id == "" {
		return errors.New("feature id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cand := make(map[string]json.RawMessage, len(s.data)+1)
	for k, b := range s.data {
		cand[k] = b
	}
	if len(v) == 0 {
		delete(cand, id)
	} else {
		cand[id] = append(json.RawMessage(nil), v...) // copy so the caller can't mutate the stored bytes
	}
	if err := s.saveLocked(cand); err != nil {
		return err
	}
	s.data = cand
	return nil
}

// Delete removes a module's state (persist-then-commit). An absent id is an idempotent no-op.
func (s *Store) Delete(id string) error { return s.Set(id, nil) }

// GetJSON unmarshals a module's state into v (v is left unchanged if the module has no state yet).
func (s *Store) GetJSON(id string, v any) error {
	b := s.Get(id)
	if b == nil {
		return nil
	}
	return json.Unmarshal(b, v)
}

// SetJSON marshals v and persists it as the module's state.
func (s *Store) SetJSON(id string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.Set(id, b)
}

// saveLocked atomically + durably writes the state map. Callers hold s.mu (write). It takes the
// candidate as an argument so a failed write never touches the committed in-memory map.
func (s *Store) saveLocked(data map[string]json.RawMessage) error {
	if s.path == "" {
		return errors.New("feature store has no path")
	}
	// json.Marshal (NOT MarshalIndent) emits each json.RawMessage value VERBATIM, so a stored blob
	// round-trips byte-for-byte; MarshalIndent would re-indent the values and mutate them on save.
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return atomicfile.Write(s.path, b, 0o600)
}
