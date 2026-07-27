package ws

import (
	"testing"
	"time"
)

func TestBucketAllowsBurstThenDeniesUntilRefill(t *testing.T) {
	b := &bucket{rate: 10, burst: 20}
	now := time.Unix(1000, 0)
	// The full burst is available immediately (a fresh bucket starts full).
	for i := 0; i < 20; i++ {
		if !b.allow(now) {
			t.Fatalf("burst message %d denied", i)
		}
	}
	if b.allow(now) {
		t.Fatal("message beyond the burst was allowed")
	}
	// Half a second refills rate/2 = 5 tokens.
	later := now.Add(500 * time.Millisecond)
	for i := 0; i < 5; i++ {
		if !b.allow(later) {
			t.Fatalf("refilled message %d denied", i)
		}
	}
	if b.allow(later) {
		t.Fatal("message beyond the refill was allowed")
	}
}

func TestBucketNeverExceedsBurstAfterLongIdle(t *testing.T) {
	b := &bucket{rate: 10, burst: 20}
	now := time.Unix(1000, 0)
	if !b.allow(now) {
		t.Fatal("first message denied")
	}
	// An hour idle refills to the burst cap, never beyond it.
	later := now.Add(time.Hour)
	for i := 0; i < 20; i++ {
		if !b.allow(later) {
			t.Fatalf("post-idle message %d denied", i)
		}
	}
	if b.allow(later) {
		t.Fatal("idle refill exceeded the burst cap")
	}
}

func TestSubjectLimiterIsPerSubjectAndSharedAcrossCallers(t *testing.T) {
	s := newSubjectLimiter(10) // burst 20
	now := time.Unix(1000, 0)
	// Draining subject A does not touch subject B.
	for i := 0; i < 20; i++ {
		if !s.allow("a", now) {
			t.Fatalf("subject a message %d denied", i)
		}
	}
	if s.allow("a", now) {
		t.Fatal("subject a allowed beyond its burst")
	}
	if !s.allow("b", now) {
		t.Fatal("subject b wrongly throttled by subject a")
	}
	// The bucket is shared no matter who calls: a second "connection" hitting subject a is denied too
	// (the whole point: N connections cannot multiply one recipient's inbound rate).
	if s.allow("a", now) {
		t.Fatal("subject a allowed for a second caller while dry")
	}
}

func TestNilOrDisabledSubjectLimiterAllowsEverything(t *testing.T) {
	var s *subjectLimiter
	if !s.allow("a", time.Now()) {
		t.Fatal("nil limiter denied")
	}
	z := newSubjectLimiter(0)
	if !z.allow("a", time.Now()) {
		t.Fatal("disabled limiter denied")
	}
}

func TestSubjectLimiterSweepsIdleEntries(t *testing.T) {
	s := newSubjectLimiter(10)
	s.sweepAt = 4 // tiny threshold so the test exercises the sweep
	now := time.Unix(1000, 0)
	for _, k := range []string{"a", "b", "c", "d"} {
		s.allow(k, now)
	}
	// All four are idle past the TTL when a NEW subject arrives: the sweep prunes them.
	later := now.Add(s.idleTTL + time.Minute)
	s.allow("e", later)
	s.mu.Lock()
	n := len(s.buckets)
	s.mu.Unlock()
	if n != 1 {
		t.Fatalf("sweep left %d buckets, want 1", n)
	}
}
