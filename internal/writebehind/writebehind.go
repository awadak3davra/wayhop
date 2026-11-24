// Package writebehind coalesces rewrites of one persistent file: a burst of changes costs one flash
// write, a file whose content only matters for an offline start is rewritten at most once per
// MinInterval, and identical content is never rewritten. Pending changes are written on Flush, which
// the daemon calls for every writer on a graceful shutdown (SIGTERM/SIGINT) via FlushAll.
//
// RAM is the scarce resource on the target routers, so the preferred input is Mark(producer): the
// writer keeps no copy and renders the bytes only when it writes. Set(data) buffers a copy, which is
// charged to a ramdir.Budget; a refused reservation (cap reached or free memory low) writes through
// immediately instead of holding the bytes.
package writebehind

import (
	"crypto/sha256"
	"log"
	"os"
	"sync"
	"time"

	"wayhop/internal/atomicfile"
	"wayhop/internal/ramdir"
)

// Options tunes a Writer. Zero Debounce and MinInterval mean write-through.
type Options struct {
	// Debounce waits this long after the last change before writing, so a burst becomes one write.
	Debounce time.Duration
	// MinInterval is the shortest gap between two writes of the file (the rate limit); a change made
	// sooner waits for it. 0 = no limit.
	MinInterval time.Duration
	// Budget charges Set's buffered copy; nil = ramdir.Shared.
	Budget *ramdir.Budget
	// Write performs the durable write; nil = atomicfile.Write.
	Write func(path string, data []byte, perm os.FileMode) error
	// Now is the clock; nil = time.Now (tests).
	Now func() time.Time
}

// Writer is one coalesced file.
type Writer struct {
	path string
	perm os.FileMode
	opt  Options

	mu        sync.Mutex
	producer  func() ([]byte, error)
	buf       []byte // Set's copy, charged to the budget
	charged   int64
	dirty     bool
	lastHash  [32]byte
	hasHash   bool
	lastWrite time.Time
	timer     *time.Timer
	closed    bool
}

var registry struct {
	sync.Mutex
	all []*Writer
}

// New returns a writer for path and registers it for FlushAll.
func New(path string, perm os.FileMode, opt Options) *Writer {
	if opt.Budget == nil {
		opt.Budget = ramdir.Shared
	}
	if opt.Write == nil {
		opt.Write = atomicfile.Write
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	w := &Writer{path: path, perm: perm, opt: opt}
	registry.Lock()
	registry.all = append(registry.all, w)
	registry.Unlock()
	return w
}

// Seed tells the writer what the file already holds and when it was written, so the first change
// after a start neither rewrites identical bytes nor ignores the rate limit.
func (w *Writer) Seed(content []byte, written time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lastHash, w.hasHash, w.lastWrite = sha256.Sum256(content), true, written
}

// Mark records that the file's content changed; produce renders it when the write happens.
func (w *Writer) Mark(produce func() ([]byte, error)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.dropBufLocked()
	w.producer = produce
	w.dirty = true
	w.scheduleLocked()
}

// Set records new content by value. The copy is held against the budget; when the budget refuses
// it the content is written through now (still skipped when identical).
func (w *Writer) Set(data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.dropBufLocked()
	if w.opt.Budget.Reserve(int64(len(data))) {
		w.buf = append([]byte(nil), data...)
		w.charged = int64(len(data))
		w.producer = nil
		w.dirty = true
		w.scheduleLocked()
		return nil
	}
	w.producer = func() ([]byte, error) { return data, nil }
	w.dirty = true
	return w.flushLocked()
}

// Flush writes a pending change now, whatever the timers say.
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.flushLocked()
}

// Pending reports whether a change waits to be written.
func (w *Writer) Pending() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.dirty
}

// Close flushes and unregisters the writer.
func (w *Writer) Close() error {
	err := w.Flush()
	w.mu.Lock()
	w.closed = true
	if w.timer != nil {
		w.timer.Stop()
	}
	w.mu.Unlock()
	registry.Lock()
	for i, x := range registry.all {
		if x == w {
			registry.all = append(registry.all[:i], registry.all[i+1:]...)
			break
		}
	}
	registry.Unlock()
	return err
}

// FlushAll flushes every registered writer (graceful shutdown).
func FlushAll() {
	registry.Lock()
	all := append([]*Writer(nil), registry.all...)
	registry.Unlock()
	for _, w := range all {
		if err := w.Flush(); err != nil {
			log.Printf("writebehind: flush %s: %v", w.path, err)
		}
	}
}

func (w *Writer) dropBufLocked() {
	if w.charged > 0 {
		w.opt.Budget.Release(w.charged)
	}
	w.buf, w.charged = nil, 0
}

// due is when a pending change may be written. Caller holds mu.
func (w *Writer) dueLocked() time.Time {
	now := w.opt.Now()
	due := now.Add(w.opt.Debounce)
	if w.opt.MinInterval > 0 && !w.lastWrite.IsZero() {
		if earliest := w.lastWrite.Add(w.opt.MinInterval); earliest.After(due) {
			due = earliest
		}
	}
	return due
}

func (w *Writer) scheduleLocked() {
	if w.closed {
		return
	}
	wait := w.dueLocked().Sub(w.opt.Now())
	if wait <= 0 && w.opt.Debounce == 0 {
		if err := w.flushLocked(); err != nil {
			log.Printf("writebehind: write %s: %v", w.path, err)
		}
		return
	}
	if w.timer != nil {
		w.timer.Stop()
	}
	w.timer = time.AfterFunc(wait, func() {
		if err := w.Flush(); err != nil {
			log.Printf("writebehind: write %s: %v", w.path, err)
		}
	})
}

func (w *Writer) flushLocked() error {
	if !w.dirty {
		return nil
	}
	data := w.buf
	if data == nil && w.producer != nil {
		var err error
		if data, err = w.producer(); err != nil {
			return err
		}
	}
	sum := sha256.Sum256(data)
	if w.hasHash && sum == w.lastHash {
		atomicfile.NoteSkip(w.path, len(data))
	} else {
		if err := w.opt.Write(w.path, data, w.perm); err != nil {
			return err // stays dirty; the next change or Flush retries
		}
		w.lastHash, w.hasHash = sum, true
		w.lastWrite = w.opt.Now()
	}
	w.dirty = false
	w.producer = nil
	w.dropBufLocked()
	if w.timer != nil {
		w.timer.Stop()
		w.timer = nil
	}
	return nil
}
