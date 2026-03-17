package hscontrol

import (
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
)

func TestSetDNSRateLimiterDisabled(t *testing.T) {
	t.Parallel()

	limiter := newSetDNSRateLimiter(types.DNSChallengeRateLimitConfig{Enabled: false})

	for range 10 {
		assert.True(t, limiter.Allow(types.NodeID(1)))
	}
}

func TestSetDNSRateLimiterPerNode(t *testing.T) {
	t.Parallel()

	limiter := newSetDNSRateLimiter(types.DNSChallengeRateLimitConfig{
		Enabled:      true,
		GlobalRPS:    100,
		GlobalBurst:  100,
		PerNodeRPS:   1,
		PerNodeBurst: 1,
	})

	assert.True(t, limiter.Allow(types.NodeID(1)))
	assert.False(t, limiter.Allow(types.NodeID(1)))
	assert.True(t, limiter.Allow(types.NodeID(2)))
}

func TestSetDNSRateLimiterGlobal(t *testing.T) {
	t.Parallel()

	limiter := newSetDNSRateLimiter(types.DNSChallengeRateLimitConfig{
		Enabled:      true,
		GlobalRPS:    1,
		GlobalBurst:  1,
		PerNodeRPS:   100,
		PerNodeBurst: 100,
	})

	assert.True(t, limiter.Allow(types.NodeID(1)))
	assert.False(t, limiter.Allow(types.NodeID(2)))
}
