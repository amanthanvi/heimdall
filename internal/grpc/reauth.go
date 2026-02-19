package grpc

import (
	"sync"
	"time"
)

type reauthCache struct {
	mu      sync.RWMutex
	entries map[string]time.Time
	ttl     time.Duration
	clock   clock
}

func newReauthCache(ttl time.Duration, clk clock) *reauthCache {
	if ttl <= 0 {
		ttl = defaultReauthTTL
	}
	if clk == nil {
		clk = realClock{}
	}
	return &reauthCache{
		entries: map[string]time.Time{},
		ttl:     ttl,
		clock:   clk,
	}
}

func (c *reauthCache) mark(caller callerIdentity) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[caller.key()] = c.clock.Now()
}

func (c *reauthCache) isValid(caller callerIdentity) bool {
	c.mu.RLock()
	ts, ok := c.entries[caller.key()]
	c.mu.RUnlock()
	if !ok {
		return false
	}
	if c.clock.Now().Sub(ts) > c.ttl {
		c.mu.Lock()
		delete(c.entries, caller.key())
		c.mu.Unlock()
		return false
	}
	return true
}

func (c *reauthCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = map[string]time.Time{}
}

type reauthLockout struct {
	mu    sync.Mutex
	state map[string]*lockoutState
	clock clock
}

type lockoutState struct {
	failures    int
	lockedUntil time.Time
}

func newReauthLockout(clk clock) *reauthLockout {
	if clk == nil {
		clk = realClock{}
	}
	return &reauthLockout{
		state: map[string]*lockoutState{},
		clock: clk,
	}
}

func (r *reauthLockout) check(caller callerIdentity) (bool, time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.state[caller.key()]
	if !ok || entry.lockedUntil.IsZero() {
		return false, 0
	}
	now := r.clock.Now()
	if now.After(entry.lockedUntil) || now.Equal(entry.lockedUntil) {
		entry.lockedUntil = time.Time{}
		return false, 0
	}
	return true, entry.lockedUntil.Sub(now)
}

func (r *reauthLockout) recordFailure(caller callerIdentity) time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := r.state[caller.key()]
	if entry == nil {
		entry = &lockoutState{}
		r.state[caller.key()] = entry
	}
	entry.failures++
	duration := lockoutDuration(entry.failures)
	if duration > 0 {
		entry.lockedUntil = r.clock.Now().Add(duration)
	}
	return duration
}

func (r *reauthLockout) reset(caller callerIdentity) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.state, caller.key())
}

func lockoutDuration(failures int) time.Duration {
	switch {
	case failures >= 10:
		return 5 * time.Minute
	case failures >= 5:
		return 30 * time.Second
	case failures >= 3:
		return 5 * time.Second
	default:
		return 0
	}
}
