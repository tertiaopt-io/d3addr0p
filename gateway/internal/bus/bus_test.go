package bus

import (
	"context"
	"strconv"
	"testing"
	"time"
)

// Proves the chosen bus runs locally (M0 acceptance): an opaque blob published to a mailbox
// is delivered to a subscriber, and the bus never inspects the payload.
func TestInProcessDeliversOpaqueBlob(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := New(ctx, 10*time.Millisecond)
	defer b.Close()

	ch, err := b.Subscribe(ctx, "mailbox-A", "")
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	want := []byte{0xDE, 0xAD, 0xD0, 0x0F}
	if err := b.Publish("mailbox-A", NewMessage("m1", want, time.Minute)); err != nil {
		t.Fatalf("publish: %v", err)
	}

	select {
	case got := <-ch:
		if string(got.Payload) != string(want) {
			t.Fatalf("payload mismatch")
		}
		if got.ID != "m1" {
			t.Fatalf("id mismatch: %q", got.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("no delivery")
	}
}

// A message published before any subscriber attaches is held and flushed on subscribe.
func TestPendingFlushedOnSubscribe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := New(ctx, 10*time.Millisecond)
	defer b.Close()

	if err := b.Publish("mailbox-B", NewMessage("m2", []byte("blob"), time.Minute)); err != nil {
		t.Fatalf("publish: %v", err)
	}
	ch, err := b.Subscribe(ctx, "mailbox-B", "")
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	select {
	case got := <-ch:
		if got.ID != "m2" {
			t.Fatalf("id mismatch: %q", got.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("pending blob not flushed")
	}
}

// An undelivered blob is reaped after its transport TTL.
func TestPendingExpires(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := New(ctx, 5*time.Millisecond).(*inProcess)
	defer b.Close()

	_ = b.Publish("mailbox-C", NewMessage("m3", []byte("blob"), 10*time.Millisecond))
	time.Sleep(40 * time.Millisecond)

	b.mu.Lock()
	n := len(b.pending["mailbox-C"])
	b.mu.Unlock()
	if n != 0 {
		t.Fatalf("expected expired blob to be reaped, found %d", n)
	}
}

// A zero/absent TTL is defaulted to a bounded expiry, not kept forever, so it is still reaped.
func TestZeroTTLIsBounded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := New(ctx, time.Minute).(*inProcess)
	defer b.Close()

	m := NewMessage("z1", []byte("blob"), 0) // client sends no TTL
	if m.expiresAt.IsZero() {
		t.Fatal("a zero-TTL message must be given a bounded (non-zero) expiry")
	}
	_ = b.Publish("mailbox-Z", m)
	// Backdate the held blob's expiry and sweep: a bounded expiry means it must be reaped.
	b.mu.Lock()
	for i := range b.pending["mailbox-Z"] {
		b.pending["mailbox-Z"][i].msg.expiresAt = b.now().Add(-time.Hour)
	}
	b.mu.Unlock()
	b.sweep()
	b.mu.Lock()
	n := len(b.pending["mailbox-Z"])
	b.mu.Unlock()
	if n != 0 {
		t.Fatalf("expected zero-TTL blob to be reaped after expiry, found %d", n)
	}
}

// The contested-crash scenario the consumer cursors exist for: a blob delivered to a registered
// consumer that never acked it (it crashed before processing durably) is REDELIVERED when that
// consumer re-subscribes, even though another consumer already received and acked it.
func TestUnackedBlobRedeliversToItsConsumerAfterReconnect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := New(ctx, time.Minute)
	defer b.Close()

	crashCtx, crash := context.WithCancel(ctx)
	chA, _ := b.Subscribe(crashCtx, "gmbox", "device-A")
	chB, _ := b.Subscribe(ctx, "gmbox", "device-B")

	_ = b.Publish("gmbox", NewMessage("commit-B", []byte("rival"), time.Minute))
	<-chA // A received it live...
	<-chB
	b.Ack("gmbox", "commit-B", "device-B") // ...B processed + acked; A CRASHES before acking
	crash()

	// A comes back (reload) and re-subscribes with its stable consumer id: the un-acked rival
	// commit must be redelivered, so A can abort its own stale pending instead of forking.
	chA2, _ := b.Subscribe(ctx, "gmbox", "device-A")
	select {
	case got := <-chA2:
		if got.ID != "commit-B" {
			t.Fatalf("expected the un-acked commit redelivered, got %q", got.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("the un-acked blob was not redelivered to its returning consumer")
	}
}

// The ENTIRE unacked backlog is flushed on one re-subscribe, not just the first channel-buffer's
// worth: truncating at 16 would defer the rival commit past the client's restore backstop and fork
// the very device this feature exists to save.
func TestFullBacklogFlushedOnOneResubscribe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := New(ctx, time.Minute)
	defer b.Close()

	regCtx, gone := context.WithCancel(ctx)
	_, _ = b.Subscribe(regCtx, "backlog", "device-A")
	gone() // registered, then offline: everything published now is held for it

	const n = 40
	for i := 0; i < n; i++ {
		_ = b.Publish("backlog", NewMessage(string(rune('A'+i/26))+string(rune('a'+i%26)), []byte("x"), time.Minute))
	}
	ch, _ := b.Subscribe(ctx, "backlog", "device-A")
	got := 0
	for got < n {
		select {
		case <-ch:
			got++
		case <-time.After(time.Second):
			t.Fatalf("backlog truncated: got %d of %d held blobs on one re-subscribe", got, n)
		}
	}
}

// Held blobs are delivered BEFORE any live publish that races the re-subscribe (per-subject FIFO):
// a returning committer must see the rival commit that preceded its crash before anything newer.
func TestHeldBlobsPrecedeARacingLivePublish(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := New(ctx, time.Minute)
	defer b.Close()

	regCtx, gone := context.WithCancel(ctx)
	_, _ = b.Subscribe(regCtx, "fifo", "device-A")
	gone()
	_ = b.Publish("fifo", NewMessage("held-1", []byte("x"), time.Minute))
	_ = b.Publish("fifo", NewMessage("held-2", []byte("x"), time.Minute))

	ch, _ := b.Subscribe(ctx, "fifo", "device-A")
	_ = b.Publish("fifo", NewMessage("live-3", []byte("x"), time.Minute))
	var order []string
	for len(order) < 3 {
		select {
		case m := <-ch:
			order = append(order, m.ID)
		case <-time.After(time.Second):
			t.Fatalf("expected 3 deliveries, got %v", order)
		}
	}
	if order[0] != "held-1" || order[1] != "held-2" || order[2] != "live-3" {
		t.Fatalf("held blobs must precede the live publish, got %v", order)
	}
}

// A retransmit can hold the SAME id twice; one ack must cover every copy or the duplicate pins
// memory until the TTL.
func TestOneAckCoversSameIdDuplicates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := New(ctx, time.Minute).(*inProcess)
	defer b.Close()

	regCtx, gone := context.WithCancel(ctx)
	_, _ = b.Subscribe(regCtx, "dups", "device-A")
	gone()
	_ = b.Publish("dups", NewMessage("dup", []byte("x"), time.Minute))
	_ = b.Publish("dups", NewMessage("dup", []byte("x"), time.Minute)) // client retransmit, same id
	b.Ack("dups", "dup", "device-A")
	b.mu.Lock()
	held := len(b.pending["dups"])
	b.mu.Unlock()
	if held != 0 {
		t.Fatalf("one ack must cover every same-id copy, found %d still held", held)
	}
}

// AckAcross acks one id across every (subject, consumer) pair in a single call: the connection acks
// across all its mailboxes, but the held blob only drops on the subject that actually held that id.
func TestAckAcrossHitsEveryPairInOneCall(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := New(ctx, time.Minute).(*inProcess)
	defer b.Close()

	chX, _ := b.Subscribe(ctx, "mbox-X", "device-A")
	chY, _ := b.Subscribe(ctx, "mbox-Y", "device-A")
	_ = b.Publish("mbox-X", NewMessage("m", []byte("x"), time.Minute))
	_ = b.Publish("mbox-Y", NewMessage("m", []byte("y"), time.Minute))
	<-chX
	<-chY
	// One frame acks id "m" across both subscribed mailboxes.
	b.AckAcross([]SubjectConsumer{{Subject: "mbox-X", Consumer: "device-A"}, {Subject: "mbox-Y", Consumer: "device-A"}}, "m")
	b.mu.Lock()
	x, y := len(b.pending["mbox-X"]), len(b.pending["mbox-Y"])
	b.mu.Unlock()
	if x != 0 || y != 0 {
		t.Fatalf("AckAcross must drop the id from every held subject; X=%d Y=%d", x, y)
	}
}

// A blob is dropped once EVERY registered consumer has acked it, and not before.
func TestBlobHeldUntilAllConsumersAck(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := New(ctx, time.Minute).(*inProcess)
	defer b.Close()

	chA, _ := b.Subscribe(ctx, "gmbox2", "device-A")
	chB, _ := b.Subscribe(ctx, "gmbox2", "device-B")
	_ = b.Publish("gmbox2", NewMessage("m1", []byte("x"), time.Minute))
	<-chA
	<-chB

	b.Ack("gmbox2", "m1", "device-A")
	b.mu.Lock()
	held := len(b.pending["gmbox2"])
	b.mu.Unlock()
	if held != 1 {
		t.Fatalf("one ack of two consumers must keep the blob held, found %d held", held)
	}
	b.Ack("gmbox2", "m1", "device-B")
	b.mu.Lock()
	held = len(b.pending["gmbox2"])
	b.mu.Unlock()
	if held != 0 {
		t.Fatalf("all consumers acked: the blob must be dropped, found %d held", held)
	}
}

// A registered consumer's re-subscribe does NOT see blobs it already acked (no duplicate storm).
func TestAckedBlobIsNotRedelivered(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := New(ctx, time.Minute)
	defer b.Close()

	firstCtx, done := context.WithCancel(ctx)
	chA, _ := b.Subscribe(firstCtx, "gmbox3", "device-A")
	_, _ = b.Subscribe(ctx, "gmbox3", "device-B") // B keeps the blob held (it never acks)
	_ = b.Publish("gmbox3", NewMessage("m1", []byte("x"), time.Minute))
	<-chA
	b.Ack("gmbox3", "m1", "device-A")
	done()

	chA2, _ := b.Subscribe(ctx, "gmbox3", "device-A")
	select {
	case got := <-chA2:
		t.Fatalf("an acked blob must not redeliver to its consumer, got %q", got.ID)
	case <-time.After(50 * time.Millisecond):
		// silence: correct
	}
}

// A legacy (no consumer id) client cannot delete a blob out from under a registered consumer, and a
// purely legacy mailbox keeps the old first-ack-drops semantics.
func TestLegacyAckSemantics(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := New(ctx, time.Minute).(*inProcess)
	defer b.Close()

	// Mixed mailbox: a registered consumer + a legacy subscriber. The legacy ack is ignored.
	chR, _ := b.Subscribe(ctx, "mixed", "device-A")
	chL, _ := b.Subscribe(ctx, "mixed", "")
	_ = b.Publish("mixed", NewMessage("m1", []byte("x"), time.Minute))
	<-chR
	<-chL
	b.Ack("mixed", "m1", "")
	b.mu.Lock()
	held := len(b.pending["mixed"])
	b.mu.Unlock()
	if held != 1 {
		t.Fatalf("a legacy ack must not drop a registered consumer's blob, found %d held", held)
	}

	// Purely legacy mailbox: the old semantics (ack drops the held blob).
	_ = b.Publish("legacy", NewMessage("m2", []byte("y"), time.Minute))
	b.Ack("legacy", "m2", "")
	b.mu.Lock()
	held = len(b.pending["legacy"])
	b.mu.Unlock()
	if held != 0 {
		t.Fatalf("a legacy ack on a legacy mailbox must drop the blob, found %d held", held)
	}
}

// The consumer registry is bounded and expiring: past the cap the stalest registration is evicted,
// and a consumer silent past retention stops holding blobs (the sweep re-evaluates the drops).
func TestConsumerRegistryBoundedAndExpiring(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := New(ctx, time.Minute).(*inProcess)
	defer b.Close()

	// Keep every subscription OPEN so the subject has live subscribers and is not pruned; register more
	// than the per-subject cap. The first cap-many are fresh, so the eviction floor refuses the extras,
	// holding the registry at exactly the cap.
	subCtx, done := context.WithCancel(ctx)
	defer done()
	for i := 0; i < maxConsumersPerSubject+8; i++ {
		_, _ = b.Subscribe(subCtx, "capped", "consumer-"+strconv.Itoa(i))
	}
	b.mu.Lock()
	n := len(b.consumers["capped"])
	b.mu.Unlock()
	if n != maxConsumersPerSubject {
		t.Fatalf("expected the registry capped at %d, found %d", maxConsumersPerSubject, n)
	}

	// Expiry: a blob held only for a long-gone consumer is released once that consumer expires.
	chA, _ := b.Subscribe(ctx, "expiring", "device-A")
	ghostCtx, ghostGone := context.WithCancel(ctx)
	_, _ = b.Subscribe(ghostCtx, "expiring", "device-ghost")
	ghostGone()
	_ = b.Publish("expiring", NewMessage("m1", []byte("x"), time.Hour))
	<-chA
	b.Ack("expiring", "m1", "device-A")
	b.mu.Lock()
	held := len(b.pending["expiring"])
	b.consumers["expiring"]["device-ghost"] = b.now().Add(-consumerRetention - time.Minute)
	b.mu.Unlock()
	if held != 1 {
		t.Fatalf("the ghost consumer must hold the blob until it expires, found %d held", held)
	}
	b.sweep()
	b.mu.Lock()
	held = len(b.pending["expiring"])
	b.mu.Unlock()
	if held != 0 {
		t.Fatalf("expiring the ghost must release the fully-acked blob, found %d held", held)
	}
}

// BH-R3: the eviction floor protects recently-active consumers. A newcomer to a full subject whose
// slots are ALL fresh is simply not tracked (no live cursor is kicked); if the stalest slot is past
// the floor, it IS evicted to make room.
func TestEvictionFloorProtectsLiveConsumers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := New(ctx, time.Minute).(*inProcess)
	defer b.Close()

	// Fill the subject to the per-subject cap with fresh registrations.
	b.mu.Lock()
	now := b.now()
	reg := make(map[string]time.Time)
	for i := 0; i < maxConsumersPerSubject; i++ {
		reg["live-"+string(rune('A'+i%26))+string(rune('0'+i/26))] = now
	}
	b.consumers["gm"] = reg
	b.mu.Unlock()

	// A newcomer: all slots are fresh (within the floor), so it is NOT tracked and no live slot is lost.
	b.mu.Lock()
	b.registerConsumer("gm", "newcomer")
	trackedAfterFresh := len(b.consumers["gm"])
	_, newcomerTracked := b.consumers["gm"]["newcomer"]
	b.mu.Unlock()
	if trackedAfterFresh != maxConsumersPerSubject || newcomerTracked {
		t.Fatalf("a newcomer must not evict live cursors; size=%d newcomerTracked=%v", trackedAfterFresh, newcomerTracked)
	}

	// Now make one slot stale (past the floor): a newcomer evicts THAT one and is tracked.
	b.mu.Lock()
	b.consumers["gm"]["live-A0"] = now.Add(-2 * consumerEvictionFloor)
	b.registerConsumer("gm", "newcomer2")
	_, staleGone := b.consumers["gm"]["live-A0"]
	_, newcomer2Tracked := b.consumers["gm"]["newcomer2"]
	b.mu.Unlock()
	if staleGone || !newcomer2Tracked {
		t.Fatalf("a stale slot must be evicted for a newcomer; staleGone=%v newcomer2Tracked=%v", !staleGone, newcomer2Tracked)
	}
}

// BH-S1: a consumer registration silent past consumerRetention is swept, releasing a blob the
// remaining consumers already acked (the stale device no longer pins it).
func TestConsumerRetentionReleasesHeldBlobs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := New(ctx, time.Minute).(*inProcess)
	defer b.Close()

	chA, _ := b.Subscribe(ctx, "ret", "device-A")
	goneCtx, gone := context.WithCancel(ctx)
	_, _ = b.Subscribe(goneCtx, "ret", "device-stale")
	gone()
	_ = b.Publish("ret", NewMessage("m1", []byte("x"), time.Hour))
	<-chA
	b.Ack("ret", "m1", "device-A") // A acked; device-stale never will
	b.mu.Lock()
	held := len(b.pending["ret"])
	b.consumers["ret"]["device-stale"] = b.now().Add(-consumerRetention - time.Minute) // gone too long
	b.mu.Unlock()
	if held != 1 {
		t.Fatalf("the stale consumer must hold the blob until its retention lapses, held=%d", held)
	}
	b.sweep()
	b.mu.Lock()
	held = len(b.pending["ret"])
	_, stillReg := b.consumers["ret"]["device-stale"]
	b.mu.Unlock()
	if held != 0 || stillReg {
		t.Fatalf("expiring the stale consumer must release the acked blob; held=%d stillRegistered=%v", held, stillReg)
	}
}

// BH-Z (review fix): the global subject cap REFUSES a new mailbox rather than evicting an existing one,
// so it can never drop a held commit (no fork) and does no scan under the lock (no freeze).
func TestGlobalSubjectCapRefusesInsteadOfEvicting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := New(ctx, time.Minute).(*inProcess)
	defer b.Close()

	// A mailbox with a held commit for a returning device (a subscriber keeps it alive).
	keepCtx, keep := context.WithCancel(ctx)
	defer keep()
	chK, _ := b.Subscribe(keepCtx, "important", "device-A")
	_ = b.Publish("important", NewMessage("commit", []byte("x"), time.Hour))
	<-chK

	b.mu.Lock()
	// Fill the registry to the cap with unrelated tracked subjects.
	for i := 0; i < maxTrackedSubjects-1; i++ {
		b.consumers["filler-"+strconv.Itoa(i)] = map[string]time.Time{"c": b.now()}
	}
	atCap := len(b.consumers)
	// A brand-new mailbox at the cap is simply NOT tracked (refused), and NOTHING existing is evicted.
	b.registerConsumer("newcomer", "device-Z")
	_, newcomerTracked := b.consumers["newcomer"]
	_, importantKept := b.consumers["important"]
	importantHeld := len(b.pending["important"])
	b.mu.Unlock()
	if newcomerTracked {
		t.Fatal("a new mailbox at the global cap must be refused, not tracked")
	}
	if !importantKept || importantHeld != 1 {
		t.Fatalf("the cap must never evict an existing mailbox or drop its held commit; kept=%v held=%d", importantKept, importantHeld)
	}
	_ = atCap
}

// BH-Z (review fix): a disconnected mailbox with nothing held drops its consumer registry at once
// (so a churn attack cannot accumulate lingering registrations), while a mailbox that still HOLDS a
// commit keeps its registry so the crashed device can still be redelivered on return.
func TestIdleConsumerRegistryIsPrunedButHeldOnesSurvive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := New(ctx, time.Minute).(*inProcess)
	defer b.Close()

	// Junk: subscribe then disconnect with nothing ever published. The registry entry must be gone.
	junkCtx, junkGone := context.WithCancel(ctx)
	_, _ = b.Subscribe(junkCtx, "junk", "attacker")
	junkGone()
	// Give detach() a moment (it runs in a goroutine on ctx.Done).
	for i := 0; i < 100; i++ {
		b.mu.Lock()
		_, present := b.consumers["junk"]
		b.mu.Unlock()
		if !present {
			break
		}
		time.Sleep(time.Millisecond)
	}
	b.mu.Lock()
	_, junkPresent := b.consumers["junk"]
	b.mu.Unlock()
	if junkPresent {
		t.Fatal("an idle, disconnected mailbox must not linger in the registry")
	}

	// A crashed device WITH a held commit: its registry survives so it can be redelivered on return.
	crashCtx, crash := context.WithCancel(ctx)
	chA, _ := b.Subscribe(crashCtx, "held", "device-A")
	_ = b.Publish("held", NewMessage("commit", []byte("x"), time.Hour))
	<-chA
	crash() // device-A crashes WITHOUT acking
	for i := 0; i < 50; i++ {
		time.Sleep(time.Millisecond)
	}
	b.mu.Lock()
	_, heldRegKept := b.consumers["held"]
	heldPending := len(b.pending["held"])
	b.mu.Unlock()
	if !heldRegKept || heldPending != 1 {
		t.Fatalf("a mailbox with a held commit must keep its registry for redelivery; kept=%v held=%d", heldRegKept, heldPending)
	}
	chA2, _ := b.Subscribe(ctx, "held", "device-A")
	select {
	case got := <-chA2:
		if got.ID != "commit" {
			t.Fatalf("expected the held commit redelivered, got %q", got.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("the held commit was not redelivered to the returning device")
	}
}

// Pending for one mailbox is bounded: past maxPendingPerSubject the oldest blob is dropped, so a
// publisher to a mailbox with no subscriber cannot exhaust memory.
func TestPendingBounded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := New(ctx, time.Minute).(*inProcess)
	defer b.Close()

	for i := 0; i < maxPendingPerSubject+50; i++ {
		_ = b.Publish("mailbox-P", NewMessage("id", []byte("x"), time.Minute))
	}
	b.mu.Lock()
	n := len(b.pending["mailbox-P"])
	b.mu.Unlock()
	if n != maxPendingPerSubject {
		t.Fatalf("expected pending capped at %d, found %d", maxPendingPerSubject, n)
	}
}
