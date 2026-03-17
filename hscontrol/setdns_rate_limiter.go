package hscontrol

import (
	"sync"

	"github.com/juanfont/headscale/hscontrol/types"
	"golang.org/x/time/rate"
)

type setDNSRateLimiter struct {
	enabled bool

	global *rate.Limiter

	perNodeRate  rate.Limit
	perNodeBurst int

	mu      sync.Mutex
	perNode map[types.NodeID]*rate.Limiter
}

func newSetDNSRateLimiter(cfg types.DNSChallengeRateLimitConfig) *setDNSRateLimiter {
	if !cfg.Enabled {
		return &setDNSRateLimiter{enabled: false}
	}

	globalRPS := cfg.GlobalRPS
	if globalRPS <= 0 {
		globalRPS = 20
	}

	globalBurst := cfg.GlobalBurst
	if globalBurst <= 0 {
		globalBurst = 40
	}

	perNodeRPS := cfg.PerNodeRPS
	if perNodeRPS <= 0 {
		perNodeRPS = 0.5
	}

	perNodeBurst := cfg.PerNodeBurst
	if perNodeBurst <= 0 {
		perNodeBurst = 5
	}

	return &setDNSRateLimiter{
		enabled:      true,
		global:       rate.NewLimiter(rate.Limit(globalRPS), globalBurst),
		perNodeRate:  rate.Limit(perNodeRPS),
		perNodeBurst: perNodeBurst,
		perNode:      make(map[types.NodeID]*rate.Limiter),
	}
}

func (l *setDNSRateLimiter) Allow(nodeID types.NodeID) bool {
	if l == nil || !l.enabled {
		return true
	}

	if !l.global.Allow() {
		return false
	}

	l.mu.Lock()

	nodeLimiter, ok := l.perNode[nodeID]
	if !ok {
		nodeLimiter = rate.NewLimiter(l.perNodeRate, l.perNodeBurst)
		l.perNode[nodeID] = nodeLimiter
	}
	l.mu.Unlock()

	return nodeLimiter.Allow()
}
