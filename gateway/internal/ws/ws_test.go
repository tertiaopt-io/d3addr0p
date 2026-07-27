package ws

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	"github.com/deaddrop/gateway/internal/bus"
	pb "github.com/deaddrop/gateway/internal/wire/deaddrop/v1"
)

func dial(t *testing.T, url string) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return c
}

func writeFrame(t *testing.T, c *websocket.Conn, f *pb.ClientFrame) {
	t.Helper()
	b, err := proto.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Write(ctx, websocket.MessageBinary, b); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func readFrame(t *testing.T, c *websocket.Conn) *pb.ServerFrame {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, data, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var sf pb.ServerFrame
	if err := proto.Unmarshal(data, &sf); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return &sf
}

// Proves the ciphertext-only transport: an opaque payload published by one client is delivered
// byte-for-byte to a subscribed client, and the sender gets a receipt. The gateway never has a
// way to read or alter the payload (acceptance: server-blindness, §10).
func TestCiphertextOnlyDelivery(t *testing.T) {
	ctx := context.Background()
	b := bus.New(ctx, 50*time.Millisecond)
	defer b.Close()
	srv := httptest.NewServer(&Handler{Bus: b, MaxPayloadBytes: 65536})
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"

	recv := dial(t, wsURL)
	defer recv.CloseNow()
	send := dial(t, wsURL)
	defer send.CloseNow()

	writeFrame(t, recv, &pb.ClientFrame{
		Body: &pb.ClientFrame_Subscribe{Subscribe: &pb.Subscribe{RoutingKey: "mailbox-bob"}},
	})

	// Opaque ciphertext; the gateway must move these exact bytes with no interpretation.
	ciphertext := []byte{0xCA, 0xFE, 0x00, 0x11, 0x22, 0xFF, 0x00, 0x42}
	writeFrame(t, send, &pb.ClientFrame{
		Body: &pb.ClientFrame_Publish{Publish: &pb.Envelope{
			MessageId:  []byte("m1"),
			RoutingKey: "mailbox-bob",
			Payload:    ciphertext,
			TtlSeconds: 60,
		}},
	})

	// Sender receives a receipt.
	if r := readFrame(t, send).GetReceipt(); r == nil || string(r.GetMessageId()) != "m1" {
		t.Fatalf("expected receipt for m1, got %+v", r)
	}

	// Recipient receives the delivery with the exact opaque payload.
	deliver := readFrame(t, recv).GetDeliver()
	if deliver == nil {
		t.Fatal("expected a delivery")
	}
	if string(deliver.GetPayload()) != string(ciphertext) {
		t.Fatalf("payload altered in transit: got %x want %x", deliver.GetPayload(), ciphertext)
	}
}

// Multi-device (ADR-022 P4): one connection subscribes to several mailboxes (a conversation's group
// mailbox plus its own bootstrap mailbox) and receives delivery on all of them, and an ack across a
// multi-subscription connection does not disrupt delivery. This is what lets every device of a user
// receive group traffic on a single connection.
func TestOneConnectionReceivesFromManyMailboxes(t *testing.T) {
	ctx := context.Background()
	b := bus.New(ctx, 50*time.Millisecond)
	defer b.Close()
	srv := httptest.NewServer(&Handler{Bus: b, MaxPayloadBytes: 65536})
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"

	recv := dial(t, wsURL)
	defer recv.CloseNow()
	send := dial(t, wsURL)
	defer send.CloseNow()

	for _, k := range []string{"group-epoch-1", "bootstrap-A"} {
		writeFrame(t, recv, &pb.ClientFrame{Body: &pb.ClientFrame_Subscribe{Subscribe: &pb.Subscribe{RoutingKey: k}}})
	}
	time.Sleep(100 * time.Millisecond) // let both subscriptions attach to the bus

	publish := func(mailbox, id string, payload []byte) {
		writeFrame(t, send, &pb.ClientFrame{Body: &pb.ClientFrame_Publish{Publish: &pb.Envelope{
			MessageId: []byte(id), RoutingKey: mailbox, Payload: payload, TtlSeconds: 60,
		}}})
		readFrame(t, send) // drain the sender's receipt
	}
	publish("group-epoch-1", "g1", []byte("group-message"))
	publish("bootstrap-A", "w1", []byte("welcome-bytes"))

	got := map[string]bool{}
	for i := 0; i < 2; i++ {
		d := readFrame(t, recv).GetDeliver()
		if d == nil {
			t.Fatal("expected a delivery on the multi-subscription connection")
		}
		got[string(d.GetPayload())] = true
	}
	if !got["group-message"] || !got["welcome-bytes"] {
		t.Fatalf("one connection did not receive from both mailboxes: %v", got)
	}
	// Acking across the connection's subjects is accepted and does not disrupt the connection.
	writeFrame(t, recv, &pb.ClientFrame{Body: &pb.ClientFrame_Ack{Ack: &pb.Ack{MessageId: []byte("g1")}}})
	publish("group-epoch-1", "g2", []byte("still-flowing"))
	if d := readFrame(t, recv).GetDeliver(); d == nil || string(d.GetPayload()) != "still-flowing" {
		t.Fatalf("delivery broke after an ack on a multi-subscription connection")
	}
}

// Structural sealed-sender / no-PII proof: the Envelope wire type has no sender or identity
// field, so the gateway cannot learn who sent a message even in principle (§5.2, §10).
func TestEnvelopeHasNoSenderField(t *testing.T) {
	allowed := map[string]bool{
		"message_id": true, "routing_key": true, "payload": true, "ttl_seconds": true,
	}
	fields := (&pb.Envelope{}).ProtoReflect().Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		name := string(fields.Get(i).Name())
		if !allowed[name] {
			t.Fatalf("Envelope has unexpected field %q; the wire type must not carry sender/PII", name)
		}
	}
}

// A handshake offer is relayed to the recipient mailbox (slice 2 frames are functional on the
// wire). The relayed material is public key-exchange data, not ciphertext (ADR-009 residual).
func TestOfferRelay(t *testing.T) {
	ctx := context.Background()
	b := bus.New(ctx, 50*time.Millisecond)
	defer b.Close()
	srv := httptest.NewServer(&Handler{Bus: b, MaxPayloadBytes: 65536})
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"

	bob := dial(t, wsURL)
	defer bob.CloseNow()
	alice := dial(t, wsURL)
	defer alice.CloseNow()

	writeFrame(t, bob, &pb.ClientFrame{
		Body: &pb.ClientFrame_Subscribe{Subscribe: &pb.Subscribe{RoutingKey: "mailbox-bob"}},
	})
	writeFrame(t, alice, &pb.ClientFrame{
		Body: &pb.ClientFrame_SendOffer{SendOffer: &pb.KeyExchangeOffer{
			FromSignatureKey: []byte{0xAA},
			KeyPackage:       []byte{0xBB, 0xCC},
			ConversationId:   "conv-1",
			ToRoutingKey:     "mailbox-bob",
		}},
	})

	offer := readFrame(t, bob).GetDeliverOffer()
	if offer == nil || offer.GetConversationId() != "conv-1" {
		t.Fatalf("expected relayed offer for conv-1, got %+v", offer)
	}
}

// TestFullHandshakeAndMessage drives the WHOLE two-client path through one gateway over real
// WebSockets: Alice offers, Bob accepts, Alice sends an opaque ciphertext message to Bob's mailbox,
// Bob receives it byte-for-byte and acks. This is the gateway half of the cross-device flow (the
// client half is exercised in client/src/e2e.test.ts; the MLS crypto in crypto/src/conversation.rs).
// The gateway only ever sees routing keys and opaque bytes; it carries the handshake material and
// the ciphertext without reading either.
func TestFullHandshakeAndMessage(t *testing.T) {
	ctx := context.Background()
	b := bus.New(ctx, 50*time.Millisecond)
	defer b.Close()
	srv := httptest.NewServer(&Handler{Bus: b, MaxPayloadBytes: 65536})
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"

	bob := dial(t, wsURL)
	defer bob.CloseNow()
	alice := dial(t, wsURL)
	defer alice.CloseNow()

	// Each client subscribes to its own sealed-sender mailbox.
	writeFrame(t, bob, &pb.ClientFrame{
		Body: &pb.ClientFrame_Subscribe{Subscribe: &pb.Subscribe{RoutingKey: "mailbox-bob"}},
	})
	writeFrame(t, alice, &pb.ClientFrame{
		Body: &pb.ClientFrame_Subscribe{Subscribe: &pb.Subscribe{RoutingKey: "mailbox-alice"}},
	})

	// 1. Alice -> Bob: key-exchange offer.
	writeFrame(t, alice, &pb.ClientFrame{
		Body: &pb.ClientFrame_SendOffer{SendOffer: &pb.KeyExchangeOffer{
			FromSignatureKey: []byte{0xA1},
			KeyPackage:       []byte{0xA2, 0xA3},
			ConversationId:   "conv-1",
			ToRoutingKey:     "mailbox-bob",
		}},
	})
	if got := readFrame(t, bob).GetDeliverOffer(); got == nil || got.GetConversationId() != "conv-1" {
		t.Fatalf("bob expected offer for conv-1, got %+v", got)
	}

	// 2. Bob -> Alice: accept (carrying his KeyPackage and the MLS Welcome).
	writeFrame(t, bob, &pb.ClientFrame{
		Body: &pb.ClientFrame_SendAccept{SendAccept: &pb.KeyExchangeAccept{
			FromSignatureKey: []byte{0xB1},
			KeyPackage:       []byte{0xB2, 0xB3},
			ConversationId:   "conv-1",
			MlsWelcome:       []byte{0xDE, 0xAD},
			ToRoutingKey:     "mailbox-alice",
		}},
	})
	accept := readFrame(t, alice).GetDeliverAccept()
	if accept == nil || accept.GetConversationId() != "conv-1" {
		t.Fatalf("alice expected accept for conv-1, got %+v", accept)
	}
	if string(accept.GetMlsWelcome()) != string([]byte{0xDE, 0xAD}) {
		t.Fatalf("welcome altered in transit: got %x", accept.GetMlsWelcome())
	}

	// 3. Alice -> Bob: an opaque ciphertext message on the established channel.
	ciphertext := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	writeFrame(t, alice, &pb.ClientFrame{
		Body: &pb.ClientFrame_Publish{Publish: &pb.Envelope{
			MessageId:  []byte("m-1"),
			RoutingKey: "mailbox-bob",
			Payload:    ciphertext,
			TtlSeconds: 60,
		}},
	})
	if r := readFrame(t, alice).GetReceipt(); r == nil || string(r.GetMessageId()) != "m-1" {
		t.Fatalf("alice expected receipt for m-1, got %+v", r)
	}
	deliver := readFrame(t, bob).GetDeliver()
	if deliver == nil || string(deliver.GetPayload()) != string(ciphertext) {
		t.Fatalf("bob got wrong/no delivery: %+v", deliver)
	}

	// 4. Bob acks; the bus stops holding the blob (no resend on reconnect).
	writeFrame(t, bob, &pb.ClientFrame{
		Body: &pb.ClientFrame_Ack{Ack: &pb.Ack{MessageId: deliver.GetMessageId()}},
	})
}

// With keepalive enabled (it pings idle connections so Cloudflare does not drop them), a connection
// survives several ping intervals and still delivers. Run under -race to confirm the ping control
// frames are concurrency-safe alongside the data writes.
func TestKeepalivePingsDoNotDisruptDelivery(t *testing.T) {
	ctx := context.Background()
	b := bus.New(ctx, 50*time.Millisecond)
	defer b.Close()
	srv := httptest.NewServer(&Handler{Bus: b, MaxPayloadBytes: 65536, PingInterval: 30 * time.Millisecond})
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"

	recv := dial(t, wsURL)
	defer recv.CloseNow()
	send := dial(t, wsURL)
	defer send.CloseNow()

	writeFrame(t, recv, &pb.ClientFrame{
		Body: &pb.ClientFrame_Subscribe{Subscribe: &pb.Subscribe{RoutingKey: "mailbox-k"}},
	})

	// Read continuously so the client auto-pongs the server's keepalive pings, and capture the
	// delivery when it arrives.
	got := make(chan []byte, 1)
	errc := make(chan error, 1)
	go func() {
		for {
			typ, data, err := recv.Read(context.Background())
			if err != nil {
				errc <- err
				return
			}
			if typ != websocket.MessageBinary {
				continue
			}
			var sf pb.ServerFrame
			if proto.Unmarshal(data, &sf) == nil && sf.GetDeliver() != nil {
				got <- sf.GetDeliver().GetPayload()
				return
			}
		}
	}()

	time.Sleep(120 * time.Millisecond) // > 3 ping intervals while recv is reading (auto-pongs)

	ciphertext := []byte{0xAB, 0xCD, 0xEF}
	writeFrame(t, send, &pb.ClientFrame{
		Body: &pb.ClientFrame_Publish{Publish: &pb.Envelope{
			MessageId: []byte("k1"), RoutingKey: "mailbox-k", Payload: ciphertext, TtlSeconds: 60,
		}},
	})

	select {
	case p := <-got:
		if string(p) != string(ciphertext) {
			t.Fatalf("payload altered: %x", p)
		}
	case err := <-errc:
		t.Fatalf("recv read error (keepalive disrupted the connection?): %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("delivery never arrived")
	}
}

// BH-R3: the per-IP connection cap admits up to MaxConnsPerIP and refuses the next, and a release
// frees a slot for the SAME IP (and does not leak the map entry at zero).
func TestPerIPConnectionCap(t *testing.T) {
	h := &Handler{MaxConnsPerIP: 2}
	for i := 0; i < 2; i++ {
		if !h.acquireIP("1.2.3.4") {
			t.Fatal("the first two connections from an IP must be admitted")
		}
	}
	if h.acquireIP("1.2.3.4") {
		t.Fatal("a third connection from the same IP must be refused")
	}
	if !h.acquireIP("5.6.7.8") {
		t.Fatal("a different IP has its own quota")
	}
	h.releaseIP("1.2.3.4")
	if !h.acquireIP("1.2.3.4") {
		t.Fatal("releasing a slot must free capacity for the same IP")
	}
	// Draining an IP to zero must delete its map entry (no unbounded growth).
	h.releaseIP("5.6.7.8")
	h.ipMu.Lock()
	_, present := h.ipConns["5.6.7.8"]
	h.ipMu.Unlock()
	if present {
		t.Fatal("an IP drained to zero must not linger in the map")
	}
}

// clientIP prefers the configured trusted header, falling back to the direct peer host.
func TestClientIPResolution(t *testing.T) {
	h := &Handler{ClientIPHeader: "CF-Connecting-IP"}
	r := httptest.NewRequest("GET", "/ws", nil)
	r.RemoteAddr = "127.0.0.1:55555"
	r.Header.Set("CF-Connecting-IP", "203.0.113.9")
	if got := h.clientIP(r); got != "203.0.113.9" {
		t.Fatalf("expected the trusted header IP, got %q", got)
	}
	r.Header.Del("CF-Connecting-IP")
	if got := h.clientIP(r); got != "127.0.0.1" {
		t.Fatalf("expected the peer host fallback, got %q", got)
	}
}
