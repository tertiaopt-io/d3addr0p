package ws

import (
	"sync"
	"time"
)

// Token-bucket rate limiting for the relay (flood control, not fairness). Two layers:
//
//   - PER CONNECTION: one bucket per WebSocket caps how fast a single client can publish or relay,
//     so one runaway (or hostile) client cannot saturate the bus.
//   - PER SUBJECT (recipient mailbox): one shared bucket per routing key caps how fast ANY number of
//     connections can pour messages into one mailbox, so a botnet of connections cannot bury a single
//     recipient (the mailbox-flood / DDoS case). The bus's maxPendingPerSubject bounds MEMORY; this
//     bounds THROUGHPUT, which is what actually protects the recipient's client.
//
// The gateway stays zero-knowledge: buckets key on the opaque routing key and count frames only;
// nothing about the ciphertext is inspected, and nothing is persisted.

// bucket is a standard token bucket: `rate` tokens/second refill up to `burst`; each allowed event
// spends one token. Zero-value semantics: a bucket starts FULL (first use seeds burst tokens).
type bucket struct {
	tokens float64
	last   time.Time
	rate   float64
	burst  float64
}

// allow spends one token if available, refilling first based on elapsed time. Not concurrency-safe on
// its own; callers hold their own lock (per-connection buckets are single-reader anyway).
func (b *bucket) allow(now time.Time) bool {
	if b.last.IsZero() {
		b.tokens = b.burst
	} else {
		b.tokens += now.Sub(b.last).Seconds() * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// subjectLimiter shares per-recipient buckets across every connection. Idle entries are swept
// opportunistically so the map cannot grow without bound under a subject-churn attack.
type subjectLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64
	burst   float64
	// sweep bookkeeping: prune entries idle longer than idleTTL whenever the map crosses sweepAt.
	idleTTL time.Duration
	sweepAt int
}

func newSubjectLimiter(rate float64) *subjectLimiter {
	return &subjectLimiter{
		buckets: make(map[string]*bucket),
		rate:    rate,
		burst:   rate * 2,
		idleTTL: 5 * time.Minute,
		sweepAt: 65536,
	}
}

// allow spends one token from the subject's bucket (created full on first sight).
func (s *subjectLimiter) allow(subject string, now time.Time) bool {
	if s == nil || s.rate <= 0 {
		return true // limiter disabled
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.buckets[subject]
	if !ok {
		if len(s.buckets) >= s.sweepAt {
			for k, v := range s.buckets {
				if now.Sub(v.last) > s.idleTTL {
					delete(s.buckets, k)
				}
			}
		}
		b = &bucket{rate: s.rate, burst: s.burst}
		s.buckets[subject] = b
	}
	return b.allow(now)
}
