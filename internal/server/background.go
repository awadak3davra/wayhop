package server

import (
	"context"
	"sync"
)

// background tracks the goroutines the server starts and does not wait for (warm-ups, watches,
// refreshes), so they can be stopped and joined. Production never stops them: their context is
// context.Background() in all but name.
type background struct {
	mu     sync.Mutex
	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
}

// bgContext is the context background work derives from instead of context.Background().
func (s *Server) bgContext() context.Context {
	b := &s.bg
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ctx == nil {
		b.ctx, b.cancel = context.WithCancel(context.Background())
	}
	return b.ctx
}

// goBackground runs f on a goroutine that stopBackground joins.
func (s *Server) goBackground(f func()) {
	s.bg.wg.Add(1)
	go func() {
		defer s.bg.wg.Done()
		f()
	}()
}

// stopBackground cancels the background work's context, waits for every goroutine goBackground
// started, and leaves a fresh context for work started after it. Tests call it before they restore
// the hooks that work reads.
func (s *Server) stopBackground() {
	b := &s.bg
	b.mu.Lock()
	if b.cancel != nil {
		b.cancel()
	}
	b.ctx, b.cancel = nil, nil
	b.mu.Unlock()
	b.wg.Wait()
}
