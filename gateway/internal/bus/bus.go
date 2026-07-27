// Package bus is the message bus seam (ADR-002). The in-process implementation routes
// opaque ciphertext blobs by an opaque recipient mailbox subject, holds undelivered blobs
// in memory with a TTL, and drops them on delivery acknowledgement.
//
// PER-CONSUMER RETENTION (the contested-crash fix): a mailbox can have several consumers
// (every device of every member subscribes to the same group mailbox). A blob used to vanish
// the moment it was pushed to any attached subscriber, so a device that crashed after delivery
// but BEFORE it durably processed the blob could never see it again — a losing committer then
// self-confirmed its own stale commit onto a private epoch (a permanent fork). Now a subscriber
// may present a stable, opaque consumer id; the bus registers it and holds every blob until ALL
// registered consumers of the subject have acked it (or the TTL expires), and re-subscribing
// re-flushes whatever THAT consumer has not acked. Clients ack only after durable processing,
// so this gives at-least-once delivery per consumer; duplicate deliveries are handled by the
// recipient's own replay protection. A subscriber with no consumer id (a legacy client) keeps
// the old first-ack-drops semantics.
//
// The interface deliberately mirrors a NATS-style subject model so this implementation can
// be swapped for a real NATS/JetStream client when the system outgrows one node, without
// touching call sites.
//
// HARD INVARIANT (brief §4.1): the bus only ever sees opaque bytes. It never holds keys and
// can never read content. `Message.Payload` is end-to-end ciphertext.
//
// METADATA, stated plainly: while a mailbox is active the consumer registry is a stored association
// (opaque consumer id -> subject), but pruneConsumerRegistry drops it the moment the mailbox goes
// fully idle (no live subscriber AND no held blob), so a device's association does not linger the
// full consumerRetention once its mailbox drains; a still-held blob or a co-subscriber keeps it, and
// consumerRetention (2h) is only the upper bound. The client sends a per-mailbox SECRET-KEYED tag
// (not the raw bootstrap key), so two mailboxes of the same device carry unrelated ids: a snapshot of
// the registry cannot be read as a device-to-conversation map. A LIVE observer still correlates a
// device's mailboxes from its own simultaneous subscriptions on one connection. Documented in
// honest-limits.
package bus

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Message is the opaque unit the bus routes. Nothing here is interpretable by the server.
type Message struct {
	// ID is a random client-generated identifier, used for dedup and delete-on-delivery.
	ID string
	// Payload is end-to-end ciphertext. The bus never inspects it.
	Payload []byte
	// expiresAt is the transport TTL backstop for an undelivered blob. Always set via NewMessage
	// (a zero/absent client TTL is defaulted and oversized ones are clamped), so every held blob is
	// eventually reaped and no "keep forever" entry can be created.
	expiresAt time.Time
}

const (
	// DefaultTTL bounds an undelivered blob when the client sends no (or a zero) TTL. It is a
	// transport backstop, not a delivery guarantee: hold-until-seen must not grow without bound, so
	// every held message expires. Mirrors the control-path TTL used by the ws layer.
	DefaultTTL = 10 * time.Minute
	// MaxTTL caps a client-requested TTL so a single client cannot pin memory indefinitely.
	MaxTTL = 24 * time.Hour
	// maxPendingPerSubject caps undelivered blobs held for one mailbox; past this the OLDEST is
	// dropped, so a client publishing to a mailbox with no (or a slow) subscriber cannot exhaust
	// memory. A backstop far above any realistic offline-delivery backlog.
	maxPendingPerSubject = 1024
	// maxConsumersPerSubject caps the registered-consumer set per mailbox (a real mailbox has one
	// consumer per member device); past this the STALEST registration is evicted, so an attacker
	// cannot register unbounded consumers to pin every blob on a subject. Sized for a realistically
	// large group (BH-R1); a conversation with more member devices than this loses the redelivery
	// guarantee for its least-recently-seen devices (disclosed in honest-limits).
	maxConsumersPerSubject = 128
	// consumerEvictionFloor protects a RECENTLY ACTIVE consumer from being evicted to make room for a
	// newcomer (BH-R3): an attacker cannot churn fresh registrations to knock a live device's delivery
	// cursor out. If every slot is within the floor (a genuinely oversized active group), the newcomer
	// is simply not tracked (it still gets live traffic; it only loses crash-redelivery) rather than
	// kicking a live member.
	consumerEvictionFloor = 90 * time.Second
	// consumerRetention is how long a consumer registration outlives its last subscribe/ack (BH-S1,
	// shortened from 24h): the crash-restore redelivery it protects is a seconds-scale reload, and the
	// blobs are independently TTL-bounded, so a shorter registry retention bounds memory without
	// weakening the fork fix. A device absent longer stops holding blobs.
	consumerRetention = 2 * time.Hour
	// maxTrackedSubjects is a global backstop on the number of mailboxes the consumer registry tracks
	// (BH-S1): at the cap, registerConsumer REFUSES to start tracking a new mailbox rather than evicting
	// an existing one, so the cap can never drop a held commit (no fork) and does no scan under the lock
	// (no freeze). Combined with pruneConsumerRegistry (idle mailboxes are dropped at once), a churn
	// attack cannot fill it; reaching it requires that many mailboxes to genuinely hold blobs or live
	// subscribers, bounded by the pending/TTL and connection caps. Far above any real active count.
	maxTrackedSubjects = 100000
)

// Bus is the seam. A future NATS-backed implementation satisfies the same interface.
type Bus interface {
	// Publish routes msg to the given opaque subject (a recipient mailbox). The message is
	// delivered to every attached subscriber and, when the subject has registered consumers,
	// HELD until all of them ack it or the TTL expires (so an absent consumer sees it on its
	// next subscribe). With no registered consumers it is held only until a subscriber attaches
	// (the legacy semantics).
	Publish(subject string, msg Message) error
	// Subscribe attaches a delivery channel for a subject. A non-empty consumer id registers a
	// stable per-device cursor: held messages this consumer has not acked are re-flushed to it.
	// Cancelling ctx detaches the channel; the registration survives only while the mailbox still has a
	// held blob or another subscriber (else it is pruned at once), and at most consumerRetention.
	Subscribe(ctx context.Context, subject string, consumer string) (<-chan Message, error)
	// Ack marks a held message processed by the given consumer; the message is dropped once
	// every registered consumer has acked it. An empty consumer id (legacy) drops the message
	// outright when the subject has no registered consumers, and is ignored otherwise.
	Ack(subject string, id string, consumer string)
	// AckAcross acks id for every (subject, consumer) pair in one lock section (a connection acks an
	// id across all of its mailboxes, since the Ack frame carries no routing key).
	AckAcross(pairs []SubjectConsumer, id string)
	// Close stops the bus and releases resources.
	Close() error
}

// SubjectConsumer pairs a mailbox subject with the consumer cursor a connection holds for it.
type SubjectConsumer struct {
	Subject  string
	Consumer string
}

var ErrClosed = errors.New("bus: closed")

// held is a pending message plus the consumers that have durably processed it.
type held struct {
	msg     Message
	ackedBy map[string]struct{}
}

// inProcess is the M0 single-node implementation.
type inProcess struct {
	mu          sync.Mutex
	subscribers map[string][]chan Message       // subject -> active delivery channels
	pending     map[string][]*held              // subject -> held blobs, TTL-bounded
	consumers   map[string]map[string]time.Time // subject -> consumer id -> last seen
	closed      bool
	now         func() time.Time
}

// New returns an in-process Bus. ttlSweep is how often expired pending blobs are reaped.
func New(ctx context.Context, ttlSweep time.Duration) Bus {
	b := &inProcess{
		subscribers: make(map[string][]chan Message),
		pending:     make(map[string][]*held),
		consumers:   make(map[string]map[string]time.Time),
		now:         time.Now,
	}
	go b.reaper(ctx, ttlSweep)
	return b
}

func (b *inProcess) Publish(subject string, msg Message) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return ErrClosed
	}
	delivered := false
	if subs := b.subscribers[subject]; len(subs) > 0 {
		// Deliver to all currently attached subscribers for this mailbox.
		for _, ch := range subs {
			select {
			case ch <- msg:
				delivered = true
			default:
				// Slow consumer (its 16-slot channel is full): it will pick the blob up from the
				// held queue on its next subscribe; the hold below covers it.
			}
		}
	}
	// Hold the blob whenever the subject has registered consumers (they ack it away once every
	// one of them has durably processed it), or when nothing received it live (legacy semantics:
	// held until a subscriber attaches or the TTL expires).
	if len(b.consumers[subject]) > 0 || !delivered {
		b.hold(subject, msg)
	}
	return nil
}

// hold appends msg to the subject's held queue, dropping the oldest blob past
// maxPendingPerSubject so a mailbox with no (or a slow) consumer cannot grow without bound.
func (b *inProcess) hold(subject string, msg Message) {
	q := b.pending[subject]
	if len(q) >= maxPendingPerSubject {
		q = q[1:] // drop oldest
	}
	b.pending[subject] = append(q, &held{msg: msg, ackedBy: make(map[string]struct{})})
}

// registerConsumer records/refreshes a consumer id for a subject, evicting the stalest registration
// past the per-subject cap (never a recently-active one) so the registry stays bounded without letting
// a registration flood knock a live cursor out.
func (b *inProcess) registerConsumer(subject, consumer string) {
	now := b.now()
	reg := b.consumers[subject]
	if reg == nil {
		// Global backstop: at the cap, REFUSE to start tracking a new mailbox rather than evicting an
		// existing one. This is O(1) (no scan under the global lock) and, crucially, never deletes a
		// held commit, so it cannot manufacture the very fork this batch prevents. The newcomer still
		// gets live delivery and its held-blob flush; it only forgoes cross-disconnect redelivery until
		// the registry drains. The registry is kept small by pruneConsumerRegistry (empty, unsubscribed
		// mailboxes are dropped at once), so an attacker cannot fill it with lingering junk to force
		// this state; reaching the cap requires that many mailboxes to genuinely hold blobs or live
		// subscribers, which is bounded by the pending/TTL and connection caps.
		if len(b.consumers) >= maxTrackedSubjects {
			return
		}
		reg = make(map[string]time.Time)
		b.consumers[subject] = reg
	}
	if _, known := reg[consumer]; !known && len(reg) >= maxConsumersPerSubject {
		stalest, when := "", time.Time{}
		for id, seen := range reg {
			if stalest == "" || seen.Before(when) {
				stalest, when = id, seen
			}
		}
		if now.Sub(when) < consumerEvictionFloor {
			return // every slot is recently active: do not evict a live cursor for this newcomer
		}
		delete(reg, stalest)
	}
	reg[consumer] = now
}

// pruneConsumerRegistry drops a subject's consumer registry the moment it serves no purpose: no live
// subscriber AND no held blobs waiting for anyone. Called wherever those can reach zero (detach, after
// a drop, in the sweep). This keeps the registry naturally bounded by real load and stops a churn
// attack from accumulating lingering registrations to inflate the global count.
func (b *inProcess) pruneConsumerRegistry(subject string) {
	if len(b.subscribers[subject]) == 0 && len(b.pending[subject]) == 0 {
		delete(b.consumers, subject)
	}
}

func (b *inProcess) Subscribe(ctx context.Context, subject string, consumer string) (<-chan Message, error) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil, ErrClosed
	}
	var flush []Message
	if consumer != "" {
		// A registered consumer: re-flush every held blob it has not acked, WITHOUT deleting the
		// queue (other consumers' cursors are independent). This is the redelivery that lets a
		// crashed device see a commit it received but never durably processed.
		b.registerConsumer(subject, consumer)
		for _, h := range b.pending[subject] {
			if _, acked := h.ackedBy[consumer]; !acked {
				flush = append(flush, h.msg)
			}
		}
	} else if len(b.consumers[subject]) == 0 {
		// Legacy subscriber on a purely legacy subject: the old flush-and-forget semantics.
		for _, h := range b.pending[subject] {
			flush = append(flush, h.msg)
		}
		delete(b.pending, subject)
	} else {
		// Legacy subscriber on a subject with registered consumers: deliver the held blobs but do
		// NOT delete them (the registered consumers still own their cursors). Its acks are ignored,
		// so it may see duplicates on re-subscribe until the registered consumers drain the queue;
		// the recipient's replay protection makes that benign. Transitional only (clients update).
		for _, h := range b.pending[subject] {
			flush = append(flush, h.msg)
		}
	}
	// Size the channel for the WHOLE flush (plus live headroom) and load it UNDER the lock, before
	// the channel joins the subscriber list. Three invariants hang on this:
	//  - completeness: nothing drains the channel until Subscribe returns, so a fixed 16-slot buffer
	//    would silently truncate a re-flush at 16 blobs and defer the rest to the NEXT reconnect —
	//    which is exactly long enough for the restore backstop to fork a crashed committer;
	//  - ordering: held blobs are enqueued before any racing Publish can acquire the lock, so a
	//    returning consumer always sees its backlog BEFORE new live traffic (per-subject FIFO);
	//  - shutdown: Close holds the same lock, so it can never close the channel mid-flush.
	// The fills cannot block (fresh channel, capacity >= len(flush)), and memory stays bounded by
	// maxPendingPerSubject + the live headroom.
	ch := make(chan Message, len(flush)+16)
	for _, m := range flush {
		ch <- m
	}
	b.subscribers[subject] = append(b.subscribers[subject], ch)
	b.mu.Unlock()

	go func() {
		<-ctx.Done()
		b.detach(subject, ch)
	}()
	return ch, nil
}

func (b *inProcess) detach(subject string, ch chan Message) {
	b.mu.Lock()
	defer b.mu.Unlock()
	subs := b.subscribers[subject]
	for i, c := range subs {
		if c == ch {
			b.subscribers[subject] = append(subs[:i], subs[i+1:]...)
			close(ch)
			break
		}
	}
	if len(b.subscribers[subject]) == 0 {
		delete(b.subscribers, subject)
	}
	// A disconnected subject with nothing held has no reason to keep a consumer registry: drop it so a
	// churn attack cannot accumulate lingering registrations to fill the global cap.
	b.pruneConsumerRegistry(subject)
}

func (b *inProcess) Ack(subject string, id string, consumer string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.ackLocked(subject, id, consumer)
}

// AckAcross acks message id for every (subject, consumer) pair in ONE lock section. A client Ack frame
// carries no routing key, so the connection acks the id across all of its subscribed mailboxes; doing
// that as N separate Ack() calls would take the global lock N times per frame (acks are rate-limit
// exempt, so that was the one unbounded shared-lock path). This coalesces it to a single acquisition.
func (b *inProcess) AckAcross(pairs []SubjectConsumer, id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	for _, p := range pairs {
		b.ackLocked(p.Subject, id, p.Consumer)
	}
}

// ackLocked is the body of Ack; the caller holds b.mu.
func (b *inProcess) ackLocked(subject string, id string, consumer string) {
	reg := b.consumers[subject]
	if consumer == "" {
		// Legacy ack: only meaningful on a purely legacy subject, where it drops the blob outright
		// (the old semantics). With registered consumers present it is ignored, so a legacy client
		// can never delete a blob out from under a registered consumer's cursor.
		if len(reg) == 0 {
			b.dropMessage(subject, id)
		}
		return
	}
	// An ack proves liveness: refresh (or re-create, if the sweep expired the registry between the
	// subscribe and this ack) the registration rather than writing into a possibly-nil map.
	b.registerConsumer(subject, consumer)
	// Mark EVERY held entry with this id (no early break): a client retransmit can hold the same
	// blob twice, and one ack must cover both or the duplicate pins memory until the TTL.
	for _, h := range b.pending[subject] {
		if h.msg.ID == id {
			h.ackedBy[consumer] = struct{}{}
		}
	}
	b.dropFullyAcked(subject)
	b.pruneConsumerRegistry(subject) // the ack may have emptied the queue; drop an idle registry
}

// dropMessage removes one held blob by id (legacy ack path).
func (b *inProcess) dropMessage(subject, id string) {
	q := b.pending[subject]
	rest := q[:0]
	for _, h := range q {
		if h.msg.ID != id {
			rest = append(rest, h)
		}
	}
	if len(rest) == 0 {
		delete(b.pending, subject)
	} else {
		b.pending[subject] = rest
	}
}

// dropFullyAcked removes every held blob that ALL currently registered consumers have acked.
// The registry is never empty here (called from a registered ack / after consumer expiry with a
// re-check), and an empty registry deliberately drops nothing: a blob published before its first
// consumer ever registered must wait for that first subscribe, not vanish.
func (b *inProcess) dropFullyAcked(subject string) {
	reg := b.consumers[subject]
	if len(reg) == 0 {
		return
	}
	q := b.pending[subject]
	rest := q[:0]
	for _, h := range q {
		all := true
		for id := range reg {
			if _, ok := h.ackedBy[id]; !ok {
				all = false
				break
			}
		}
		if !all {
			rest = append(rest, h)
		}
	}
	if len(rest) == 0 {
		delete(b.pending, subject)
	} else {
		b.pending[subject] = rest
	}
}

func (b *inProcess) reaper(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			b.sweep()
		}
	}
}

func (b *inProcess) sweep() {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	for subject, msgs := range b.pending {
		kept := msgs[:0]
		for _, h := range msgs {
			if h.msg.expiresAt.After(now) {
				kept = append(kept, h)
			}
		}
		if len(kept) == 0 {
			delete(b.pending, subject)
		} else {
			b.pending[subject] = kept
		}
	}
	// Expire consumer registrations that have gone silent (revoked / wiped devices must not pin
	// blobs), then re-evaluate the drop condition: losing a straggler may complete the all-acked
	// set for blobs the remaining consumers already processed.
	for subject, reg := range b.consumers {
		for id, seen := range reg {
			if now.Sub(seen) > consumerRetention {
				delete(reg, id)
			}
		}
		if len(reg) == 0 {
			delete(b.consumers, subject)
			continue
		}
		b.dropFullyAcked(subject)
		b.pruneConsumerRegistry(subject) // drop a registry left idle (no subscriber, no pending)
	}
}

func (b *inProcess) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return ErrClosed
	}
	b.closed = true
	for subject, subs := range b.subscribers {
		for _, ch := range subs {
			close(ch)
		}
		delete(b.subscribers, subject)
	}
	b.pending = make(map[string][]*held)
	b.consumers = make(map[string]map[string]time.Time)
	return nil
}

// NewMessage builds a Message with a bounded TTL backstop measured from now. A zero/absent TTL
// becomes DefaultTTL and any value above MaxTTL is clamped, so an undelivered blob is ALWAYS reaped
// (a client cannot create a zero-expiry "keep forever" entry that grows pending without bound).
func NewMessage(id string, payload []byte, ttl time.Duration) Message {
	switch {
	case ttl <= 0:
		ttl = DefaultTTL
	case ttl > MaxTTL:
		ttl = MaxTTL
	}
	return Message{ID: id, Payload: payload, expiresAt: time.Now().Add(ttl)}
}
