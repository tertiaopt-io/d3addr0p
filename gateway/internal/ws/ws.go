// Package ws is the WebSocket gateway endpoint (M1 slice 3). It terminates client connections
// and moves protobuf frames between clients and the in-process bus.
//
// HARD INVARIANT (brief §4.1): the gateway only ever handles opaque ciphertext envelopes and
// public handshake material. It never holds keys and never sees plaintext. Every Envelope's
// `payload` is end-to-end ciphertext; the gateway forwards it byte-for-byte and never inspects
// or transforms it. Sealed sender means there is no sender field at all.
package ws

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	"github.com/deaddrop/gateway/internal/bus"
	pb "github.com/deaddrop/gateway/internal/wire/deaddrop/v1"
)

// controlTTL bounds how long an undelivered handshake frame is held in memory.
const controlTTL = 10 * time.Minute

// maxSubjectsPerConn caps how many distinct mailboxes one connection may subscribe to. Each
// subscription spawns a forwarding goroutine and a buffered channel, freed only on close, so an
// unbounded count is a cheap resource-exhaustion DoS. A multi-device client needs its bootstrap
// mailbox plus one per open conversation, so this ceiling is far above any real usage.
const maxSubjectsPerConn = 512

// maxConsumerIDBytes bounds the opaque per-mailbox consumer id a client may register (a real
// client sends its 64-hex-char bootstrap key; the cap leaves headroom without letting a client
// pin large server-side registry entries).
const maxConsumerIDBytes = 128

// readFramingOverhead is added to MaxPayloadBytes when setting the per-message read limit, to cover
// the protobuf ClientFrame framing (field tags + routing_key + message_id) that wraps the payload.
const readFramingOverhead = 4096

type Handler struct {
	Bus             bus.Bus
	MaxPayloadBytes int
	// AllowedOrigins: empty means same-origin only (production default behind Apache); a
	// comma-separated pattern list, or "*" to skip the Origin check (DEV ONLY, see config).
	AllowedOrigins string
	// PingInterval keeps the connection warm through idle-timeout proxies (Cloudflare closes an
	// idle WebSocket after ~100s). Zero disables keepalive.
	PingInterval time.Duration
	// MaxConns caps concurrent WebSocket connections so one source cannot exhaust the relay by
	// opening sockets. Zero disables the cap.
	MaxConns int
	// PubRate caps how many messages ONE connection may publish/relay per second (token bucket,
	// burst 2x), so a runaway or hostile client cannot saturate the bus. Zero disables the cap.
	PubRate float64
	// SubjectRate caps how many messages per second may land in ONE recipient mailbox across ALL
	// connections (token bucket, burst 2x): the mailbox-flood guard. Zero disables the cap.
	SubjectRate float64
	// CtrlRate caps Subscribe frames per second on ONE connection (token bucket, burst 4x), a backstop
	// against subscription flooding (each subscribe spawns a goroutine + channel). Sized so a reconnect
	// that re-subscribes to every open mailbox at once fits inside the burst. Acks are exempt (cheap,
	// safe to drop). Zero disables the cap.
	CtrlRate float64
	// MaxConnsPerIP caps concurrent connections from ONE client IP. Zero disables it. DANGEROUS to
	// enable unless the origin is firewalled so only the trusted proxy can reach it AND ClientIPHeader
	// names a header that proxy sets from the real peer: otherwise the key is client-spoofable and the
	// cap becomes a denial-of-service lever (an attacker spoofs a victim's IP to exhaust its quota).
	// Off by default for exactly that reason; the eviction floor and global caps carry the load.
	MaxConnsPerIP int
	// ClientIPHeader names the request header carrying the real client IP (e.g. "CF-Connecting-IP")
	// when the gateway sits behind a trusted proxy. Empty uses the direct peer address, which behind a
	// reverse proxy is the proxy itself (so a per-IP cap would count all clients as one). Only trust
	// this header when the origin is firewalled to the proxy.
	ClientIPHeader string

	active int32 // current live connections (atomic), compared against MaxConns

	subjLimOnce sync.Once
	subjLim     *subjectLimiter

	ipMu    sync.Mutex     // guards ipConns
	ipConns map[string]int // per-client-IP live connection counts (only used when MaxConnsPerIP > 0)
}

// subjectLimiterShared lazily builds the ONE per-recipient limiter every connection shares.
func (h *Handler) subjectLimiterShared() *subjectLimiter {
	h.subjLimOnce.Do(func() {
		if h.SubjectRate > 0 {
			h.subjLim = newSubjectLimiter(h.SubjectRate)
		}
	})
	return h.subjLim
}

func (h *Handler) acceptOptions() *websocket.AcceptOptions {
	switch {
	case h.AllowedOrigins == "":
		return nil // coder/websocket default: same-origin only
	case h.AllowedOrigins == "*":
		return &websocket.AcceptOptions{InsecureSkipVerify: true}
	default:
		return &websocket.AcceptOptions{OriginPatterns: strings.Split(h.AllowedOrigins, ",")}
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Bound concurrent connections before the upgrade so a flood of sockets cannot exhaust the relay.
	if h.MaxConns > 0 {
		if int(atomic.AddInt32(&h.active, 1)) > h.MaxConns {
			atomic.AddInt32(&h.active, -1)
			http.Error(w, "gateway at capacity", http.StatusServiceUnavailable)
			return
		}
		defer atomic.AddInt32(&h.active, -1)
	}
	// Optional per-IP cap (BH-R3; off unless configured, see MaxConnsPerIP). Bounds how many sockets a
	// single client may hold, so one host cannot monopolize the relay under the global cap.
	if h.MaxConnsPerIP > 0 {
		ip := h.clientIP(r)
		if !h.acquireIP(ip) {
			http.Error(w, "too many connections from your address", http.StatusServiceUnavailable)
			return
		}
		defer h.releaseIP(ip)
	}
	c, err := websocket.Accept(w, r, h.acceptOptions())
	if err != nil {
		return
	}
	defer c.CloseNow()
	// Cap per-message reads at the configured payload size plus framing overhead, so an oversized
	// frame is answered with a TOO_LARGE reply on the publish path instead of tearing the whole
	// connection down at the transport layer (coder/websocket defaults to a 32 KiB read limit).
	if h.MaxPayloadBytes > 0 {
		c.SetReadLimit(int64(h.MaxPayloadBytes) + readFramingOverhead)
	}

	conn := &connection{ws: c, bus: h.Bus, max: h.MaxPayloadBytes, pingInterval: h.PingInterval, subjects: map[string]string{}, subjLim: h.subjectLimiterShared()}
	if h.PubRate > 0 {
		conn.pubLim = &bucket{rate: h.PubRate, burst: h.PubRate * 2}
	}
	if h.CtrlRate > 0 {
		// Burst 4x: a reconnect re-subscribes to every open mailbox at once (up to maxSubjectsPerConn),
		// so the burst must comfortably exceed that or a heavy user's restore would be throttled.
		conn.ctrlLim = &bucket{rate: h.CtrlRate, burst: h.CtrlRate * 4}
	}
	conn.run(r.Context())
}

// clientIP resolves the key for the per-IP cap: the configured trusted header if set, else the direct
// peer host. See ClientIPHeader for the trust caveat.
func (h *Handler) clientIP(r *http.Request) string {
	if h.ClientIPHeader != "" {
		if v := r.Header.Get(h.ClientIPHeader); v != "" {
			return v
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// acquireIP reserves a per-IP connection slot, returning false when the IP is at MaxConnsPerIP.
func (h *Handler) acquireIP(ip string) bool {
	h.ipMu.Lock()
	defer h.ipMu.Unlock()
	if h.ipConns == nil {
		h.ipConns = make(map[string]int)
	}
	if h.ipConns[ip] >= h.MaxConnsPerIP {
		return false
	}
	h.ipConns[ip]++
	return true
}

// releaseIP frees a per-IP slot, dropping the map entry at zero so the map cannot grow without bound.
func (h *Handler) releaseIP(ip string) {
	h.ipMu.Lock()
	defer h.ipMu.Unlock()
	if h.ipConns[ip] <= 1 {
		delete(h.ipConns, ip)
	} else {
		h.ipConns[ip]--
	}
}

type connection struct {
	ws  *websocket.Conn
	bus bus.Bus
	max int

	writeMu sync.Mutex // coder/websocket writes are not concurrency-safe
	// A multi-device client subscribes to several mailboxes on one connection: its bootstrap mailbox
	// (for Welcomes) plus the per-epoch group mailbox of each conversation (ADR-022 P4). The bus fans
	// a publish out to every subscriber of a mailbox, so group delivery needs only N subscriptions.
	subMu sync.Mutex
	// subject -> the consumer id it was subscribed with ("" for a legacy client). The consumer id is a
	// per-mailbox secret-keyed tag from the client (not the raw bootstrap key), keying this device's
	// delivery cursor on the bus (hold-until-all-ack + redelivery) without linking its mailboxes.
	subjects     map[string]string
	pingInterval time.Duration

	// Flood control (see ratelimit.go): pubLim caps this connection's publish/relay rate; ctrlLim caps
	// its Subscribe+Ack rate (BH-S1, a generous backstop against control-frame flooding, sized so a
	// legitimate reconnect burst of many subscribes never trips it). Both are touched only by the
	// read-loop goroutine, so they need no lock. subjLim is the shared per-recipient cap.
	pubLim  *bucket
	ctrlLim *bucket
	subjLim *subjectLimiter
}

// allowCtrl bounds Subscribe frames on this connection (BH-S1; acks are exempt). The bucket is sized so
// a normal reconnect (which subscribes to every open mailbox at once) fits inside the burst; it only
// trips on pathological flooding, replying RATE_LIMIT and dropping the frame.
func (c *connection) allowCtrl() bool {
	if c.ctrlLim == nil {
		return true
	}
	if !c.ctrlLim.allow(time.Now()) {
		c.sendError(pb.ErrorCode_ERROR_CODE_RATE_LIMIT, "too many control frames; slow down")
		return false
	}
	return true
}

// allowSend enforces both rate layers for one outbound message to `subject`, replying RATE_LIMIT and
// dropping the frame when either bucket is dry. The sender may retry after backing off; nothing about
// the envelope is inspected or logged.
func (c *connection) allowSend(subject string) bool {
	now := time.Now()
	if c.pubLim != nil && !c.pubLim.allow(now) {
		c.sendError(pb.ErrorCode_ERROR_CODE_RATE_LIMIT, "sending too fast; slow down")
		return false
	}
	if !c.subjLim.allow(subject, now) {
		c.sendError(pb.ErrorCode_ERROR_CODE_RATE_LIMIT, "recipient is receiving too fast; slow down")
		return false
	}
	return true
}

// keepAlive pings the peer periodically so an idle connection is not closed by a proxy in between
// (Cloudflare drops idle WebSockets). The browser auto-responds with a pong; a failed ping also
// detects a dead connection. coder/websocket serializes control frames internally, so this is safe
// alongside the data writes guarded by writeMu.
func (c *connection) keepAlive(ctx context.Context) {
	if c.pingInterval <= 0 {
		return
	}
	t := time.NewTicker(c.pingInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := c.ws.Ping(pctx)
			cancel()
			if err != nil {
				return // dead connection; the read loop will also unwind
			}
		}
	}
}

func (c *connection) run(ctx context.Context) {
	go c.keepAlive(ctx)
	for {
		typ, data, err := c.ws.Read(ctx)
		if err != nil {
			return
		}
		if typ != websocket.MessageBinary {
			c.sendError(pb.ErrorCode_ERROR_CODE_MALFORMED, "frames must be binary protobuf")
			continue
		}
		var frame pb.ClientFrame
		if err := proto.Unmarshal(data, &frame); err != nil {
			c.sendError(pb.ErrorCode_ERROR_CODE_MALFORMED, "unparseable frame")
			continue
		}
		switch body := frame.Body.(type) {
		case *pb.ClientFrame_Subscribe:
			if !c.allowCtrl() {
				continue
			}
			c.subscribe(ctx, body.Subscribe.GetRoutingKey(), body.Subscribe.GetConsumerId())
		case *pb.ClientFrame_Publish:
			c.publish(body.Publish)
		case *pb.ClientFrame_Ack:
			// Acks are NOT rate-limited: they are cheap map ops, a dropped ack merely re-holds the blob
			// (safe), and a reconnect emits an ack per re-flushed held blob, so sharing the subscribe
			// bucket would throttle a heavy restore (and its RATE_LIMIT would spuriously grow the client's
			// publish pacing). Subscribes, which spawn a goroutine + channel each, carry the ctrl limit.
			c.ackAll(string(body.Ack.GetMessageId()))
		case *pb.ClientFrame_SendOffer:
			c.relay(body.SendOffer.GetToRoutingKey(), body.SendOffer.GetConversationId(),
				&pb.ServerFrame{Body: &pb.ServerFrame_DeliverOffer{DeliverOffer: body.SendOffer}})
		case *pb.ClientFrame_SendAccept:
			c.relay(body.SendAccept.GetToRoutingKey(), body.SendAccept.GetConversationId(),
				&pb.ServerFrame{Body: &pb.ServerFrame_DeliverAccept{DeliverAccept: body.SendAccept}})
		default:
			c.sendError(pb.ErrorCode_ERROR_CODE_MALFORMED, "empty frame")
		}
	}
}

func (c *connection) subscribe(ctx context.Context, routingKey string, consumerID string) {
	if routingKey == "" {
		c.sendError(pb.ErrorCode_ERROR_CODE_MALFORMED, "empty routing key")
		return
	}
	if len(consumerID) > maxConsumerIDBytes {
		// Bound what a client can register (the id keys a server-side map entry). A real client
		// sends its bootstrap key (64 hex chars); anything oversized is malformed, not truncated.
		c.sendError(pb.ErrorCode_ERROR_CODE_MALFORMED, "consumer id too long")
		return
	}
	c.subMu.Lock()
	if _, ok := c.subjects[routingKey]; ok {
		c.subMu.Unlock()
		return // already subscribed to this mailbox; idempotent (re-subscribe is a no-op)
	}
	if len(c.subjects) >= maxSubjectsPerConn {
		c.subMu.Unlock() // enforced inside subMu so concurrent frames cannot race past the cap
		c.sendError(pb.ErrorCode_ERROR_CODE_RATE_LIMIT, "too many subscriptions")
		return
	}
	c.subjects[routingKey] = consumerID
	c.subMu.Unlock()

	ch, err := c.bus.Subscribe(ctx, routingKey, consumerID)
	if err != nil {
		c.subMu.Lock()
		delete(c.subjects, routingKey)
		c.subMu.Unlock()
		c.sendError(pb.ErrorCode_ERROR_CODE_INTERNAL, "subscribe failed")
		return
	}
	go func() {
		// Each bus message is an already-marshaled ServerFrame; forward verbatim. One goroutine per
		// subscribed mailbox, all serialized on writeMu.
		for msg := range ch {
			c.writeMu.Lock()
			err := c.ws.Write(ctx, websocket.MessageBinary, msg.Payload)
			c.writeMu.Unlock()
			if err != nil {
				return
			}
		}
	}()
}

// ackAll drops a delivered message, by id, from every mailbox this connection is subscribed to.
// LIMITATION: the Ack frame carries no routing key, so the id is matched across all of this
// connection's subjects. In steady state mailboxes are opaque exporter-derived secrets that only
// their members can subscribe to, so this is safe; during bootstrap (a device's published signature
// key is a public, subscribable mailbox) a peer could evict a pending handshake blob by id. That is
// the already-documented sealed-sender bootstrap residual. A full fix carries the routing key in the
// Ack frame (a wire-schema change) and acks only that subject if it is in c.subjects.
func (c *connection) ackAll(id string) {
	c.subMu.Lock()
	pairs := make([]bus.SubjectConsumer, 0, len(c.subjects))
	for s, consumer := range c.subjects {
		pairs = append(pairs, bus.SubjectConsumer{Subject: s, Consumer: consumer})
	}
	c.subMu.Unlock()
	// One lock section on the bus per Ack frame (not one per subject), so acks (which are rate-limit
	// exempt) cannot amplify into up to maxSubjectsPerConn global-lock acquisitions per frame.
	c.bus.AckAcross(pairs, id)
}

func (c *connection) publish(env *pb.Envelope) {
	if env == nil || env.GetRoutingKey() == "" {
		c.sendError(pb.ErrorCode_ERROR_CODE_MALFORMED, "missing envelope or routing key")
		return
	}
	if c.max > 0 && len(env.GetPayload()) > c.max {
		c.sendError(pb.ErrorCode_ERROR_CODE_TOO_LARGE, "payload exceeds max")
		return
	}
	if !c.allowSend(env.GetRoutingKey()) {
		return // over the per-connection or per-recipient rate: dropped with a RATE_LIMIT reply
	}
	// Wrap the opaque envelope into a delivery frame; the gateway never reads env.Payload.
	frame := &pb.ServerFrame{Body: &pb.ServerFrame_Deliver{Deliver: env}}
	b, err := proto.Marshal(frame)
	if err != nil {
		c.sendError(pb.ErrorCode_ERROR_CODE_INTERNAL, "marshal failed")
		return
	}
	ttl := time.Duration(env.GetTtlSeconds()) * time.Second
	if err := c.bus.Publish(env.GetRoutingKey(), bus.NewMessage(string(env.GetMessageId()), b, ttl)); err != nil {
		c.sendError(pb.ErrorCode_ERROR_CODE_INTERNAL, "publish failed")
		return
	}
	c.send(&pb.ServerFrame{Body: &pb.ServerFrame_Receipt{Receipt: &pb.Receipt{MessageId: env.GetMessageId()}}})
}

func (c *connection) relay(toRoutingKey, id string, frame *pb.ServerFrame) {
	if toRoutingKey == "" {
		c.sendError(pb.ErrorCode_ERROR_CODE_MALFORMED, "missing recipient")
		return
	}
	if !c.allowSend(toRoutingKey) {
		return // handshake relays ride the same flood-control buckets as publishes
	}
	b, err := proto.Marshal(frame)
	if err != nil {
		c.sendError(pb.ErrorCode_ERROR_CODE_INTERNAL, "marshal failed")
		return
	}
	if err := c.bus.Publish(toRoutingKey, bus.NewMessage(id, b, controlTTL)); err != nil {
		c.sendError(pb.ErrorCode_ERROR_CODE_INTERNAL, "relay failed")
	}
}

func (c *connection) send(frame *pb.ServerFrame) {
	b, err := proto.Marshal(frame)
	if err != nil {
		return
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = c.ws.Write(context.Background(), websocket.MessageBinary, b)
}

func (c *connection) sendError(code pb.ErrorCode, detail string) {
	c.send(&pb.ServerFrame{Body: &pb.ServerFrame_Error{Error: &pb.Error{Code: code, Detail: detail}}})
}
