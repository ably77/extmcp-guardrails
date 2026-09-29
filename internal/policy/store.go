package policy

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Store holds the current policy and swaps it when the file changes.
// ConfigMap mounts update by symlink swap, so it compares content hashes
// instead of modification times.
type Store struct {
	path string
	cur  atomic.Pointer[Config]
	mu   sync.Mutex
	sum  [32]byte
	bad  [32]byte
}

func NewStore(path string) (*Store, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c, err := Parse(b)
	if err != nil {
		return nil, err
	}
	s := &Store{path: path, sum: sha256.Sum256(b)}
	s.cur.Store(c)
	return s, nil
}

func (s *Store) Get() *Config { return s.cur.Load() }

// Reload re-reads the file. It returns true when a new valid policy took
// effect. An invalid file keeps the previous policy and is reported once.
func (s *Store) Reload() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.path)
	if err != nil {
		return false, err
	}
	sum := sha256.Sum256(b)
	if sum == s.sum || sum == s.bad {
		return false, nil
	}
	c, err := Parse(b)
	if err == nil && c.Mode != s.cur.Load().Mode {
		err = fmt.Errorf("mode change %s -> %s needs a restart", s.cur.Load().Mode, c.Mode)
	}
	if err != nil {
		s.bad = sum
		return false, err
	}
	s.cur.Store(c)
	s.sum = sum
	return true, nil
}

func (s *Store) reloadAndLog(log *slog.Logger) {
	changed, err := s.Reload()
	switch {
	case err != nil:
		log.Error("policy reload failed, keeping previous policy", "path", s.path, "err", err)
	case changed:
		log.Info("policy reloaded", "path", s.path)
	}
}

// Watch polls the file until ctx ends.
func (s *Store) Watch(ctx context.Context, every time.Duration, log *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.reloadAndLog(log)
		}
	}
}
