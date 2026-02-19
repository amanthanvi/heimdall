package grpc

import (
	"sync"
	"time"
)

type rateLimiter struct {
	mu      sync.Mutex
	windows map[string]*rateWindow
	clock   clock
}

type rateWindow struct {
	start time.Time
	count int
}

func newRateLimiter(clk clock) *rateLimiter {
	if clk == nil {
		clk = realClock{}
	}
	return &rateLimiter{
		windows: map[string]*rateWindow{},
		clock:   clk,
	}
}

func (r *rateLimiter) allow(caller callerIdentity, tier authTier) bool {
	limit := tierLimitPerMinute(tier)
	if limit <= 0 {
		return true
	}

	now := r.clock.Now()
	windowKey := caller.key() + ":" + string(rune('0'+tier))

	r.mu.Lock()
	defer r.mu.Unlock()
	window := r.windows[windowKey]
	if window == nil {
		window = &rateWindow{start: now, count: 0}
		r.windows[windowKey] = window
	}
	if now.Sub(window.start) >= time.Minute {
		window.start = now
		window.count = 0
	}
	window.count++
	return window.count <= limit
}
