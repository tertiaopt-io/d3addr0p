import { describe, it, expect } from 'vitest';
import { LiveChannel, type LiveDeps, parseContact, formatContact, fingerprintOf } from './live.js';
import type { Transport, TransportHandlers } from './transport.js';
import type { ConversationLike } from './session.js';
import type { ChannelSummary, WorkerEvent } from './app.js';

/*
 * LiveChannel orchestration: two LiveChannels (Alice, Bob) wired through an in-memory fake gateway
 * complete the contact -> offer -> accept -> message flow, and the right worker events fire on each
 * side. The MLS crypto is faked here (proven natively in crypto/src/conversation.rs and over a real
 * socket in the two-tab browser test); this exercises the worker-side wiring of Session + Transport
 * + the push-event channel deterministically in Node.
 */

const enc = new TextEncoder();
const dec = new TextDecoder();
const ALICE = 'a'.repeat(64);
const BOB = 'b'.repeat(64);

// A FakeConversation that learns its peer during the handshake (createAndAdd parses the peer's
// KeyPackage; joinFromWelcome parses the creator's hex from the Welcome).
class FakeConversation implements ConversationLike {
  private peerHex = '';
  constructor(private readonly selfHex: string) {}
  signaturePublicKeyHex(): string {
    return this.selfHex;
  }
  keyPackage(): Uint8Array {
    return enc.encode(`${this.selfHex}-kp`);
  }
  createAndAdd(peerKeyPackage: Uint8Array): Uint8Array {
    this.peerHex = dec.decode(peerKeyPackage).replace('-kp', '');
    return enc.encode(`welcome-${this.selfHex}`);
  }
  joinFromWelcome(welcome: Uint8Array): void {
    this.peerHex = dec.decode(welcome).replace('welcome-', '');
  }
  encrypt(plaintext: Uint8Array): Uint8Array {
    return plaintext;
  }
  decrypt(ciphertext: Uint8Array): Uint8Array {
    return ciphertext;
  }
  peerSignatureKeyHex(): string {
    return this.peerHex;
  }
  selfMailbox(): string {
    return `${this.selfHex}-mbox`;
  }
  peerMailbox(): string {
    return `${this.peerHex}-mbox`;
  }
  mailboxTag(subject: string): string {
    return 'ctag-' + subject;
  }
  wipe(): void {}
}

interface Conn {
  readonly handlers: TransportHandlers;
  subject: string;
}

// In-memory gateway: routes offers/accepts by toRoutingKey and envelopes by routingKey, exactly
// like the Go gateway, but synchronously and without the wire codec.
class FakeGateway {
  private readonly conns: Conn[] = [];
  register(handlers: TransportHandlers): Transport {
    const conn: Conn = { handlers, subject: '' };
    this.conns.push(conn);
    const fake = {
      setConsumerIdResolver: () => {},
      subscribe: (k: string) => {
        conn.subject = k;
      },
      publish: (env: { routingKey: string }) => {
        this.to(env.routingKey)?.handlers.onDeliver(env as never);
      },
      ack: () => {},
      sendOffer: (offer: { toRoutingKey: string }) => {
        this.to(offer.toRoutingKey)?.handlers.onOffer(offer as never);
      },
      sendAccept: (accept: { toRoutingKey: string }) => {
        this.to(accept.toRoutingKey)?.handlers.onAccept(accept as never);
      },
      close: () => {},
    };
    return fake as unknown as Transport;
  }
  private to(key: string): Conn | undefined {
    return this.conns.find((c) => c.subject === key);
  }
}

interface PersistedMessage {
  readonly meta: { messageId: string; conversationId: string; direction: 'in' | 'out'; lifetime: { kind: string } };
  readonly text: string;
}

function makeChannel(
  gw: FakeGateway,
  selfHex: string,
  persistence?: import('./live.js').LivePersistence,
): { channel: LiveChannel; events: WorkerEvent[]; saved: ChannelSummary[]; persisted: PersistedMessage[] } {
  const events: WorkerEvent[] = [];
  const saved: ChannelSummary[] = [];
  const persisted: PersistedMessage[] = [];
  const deps: LiveDeps = {
    connect: (_url, handlers) => gw.register(handlers),
    makeConversation: () => new FakeConversation(selfHex),
    pushEvent: (event, payload) => {
      events.push({ event, payload });
    },
    schedule: () => 0,
    cancel: () => {},
    sealConversation: () => new Uint8Array(0),
    restoreConversation: () => {
      throw new Error('restore not used in this test');
    },
  };
  const channel = new LiveChannel(
    deps,
    (s) => {
      saved.push(s);
      return Promise.resolve();
    },
    (meta, plaintext) => {
      persisted.push({ meta, text: dec.decode(plaintext) });
      return Promise.resolve();
    },
    persistence,
  );
  return { channel, events, saved, persisted };
}

function eventOf(events: readonly WorkerEvent[], kind: string): WorkerEvent | undefined {
  return events.find((e) => e.event === kind);
}

describe('contact string', () => {
  it('round-trips and rejects malformed input', () => {
    const c = formatContact(ALICE);
    expect(c).toBe(`deaddrop:1:${ALICE}:${ALICE}`);
    expect(parseContact(c)).toEqual({ routingKey: ALICE, sigKeyHex: ALICE });
    expect(() => parseContact('not-a-contact')).toThrow();
    expect(() => parseContact('deaddrop:2:x:y')).toThrow();
    expect(() => parseContact('deaddrop:1::y')).toThrow();
  });
});

describe('LiveChannel end-to-end through a fake gateway', () => {
  it('connect, offer, accept, send, and receive with the right events on each side', async () => {
    const gw = new FakeGateway();
    const alice = makeChannel(gw, ALICE);
    const bob = makeChannel(gw, BOB);

    const aliceConn = await alice.channel.connectGateway('ws://test/ws');
    const bobConn = await bob.channel.connectGateway('ws://test/ws');
    expect(aliceConn.selfContact).toBe(formatContact(ALICE));
    expect(eventOf(alice.events, 'connection')?.payload).toEqual({ state: 'live' });

    // Alice offers to Bob's contact; Bob sees an incoming offer.
    const waiting = alice.channel.offerToContact(bobConn.selfContact);
    expect(waiting.secure).toBe(false);
    expect(waiting.conversationId).not.toBeNull();
    const offerEv = eventOf(bob.events, 'offer');
    expect(offerEv).toBeDefined();
    const offerPayload = offerEv?.payload as { conversationId: string; peerFingerprint: string };
    expect(offerPayload.peerFingerprint).toBe(fingerprintOf(ALICE));

    // Bob accepts; he saves a secure channel and Alice's offerer side completes via 'established'.
    await bob.channel.acceptKeyExchange(offerPayload.conversationId);
    expect(bob.saved.some((s) => s.status === 'secure')).toBe(true);
    const establishedEv = eventOf(alice.events, 'established');
    expect(establishedEv).toBeDefined();
    const established = establishedEv?.payload as { conversationId: string };
    expect(established.conversationId).toBe(offerPayload.conversationId);

    // Alice sends a message; she persists her own (armed) copy, Bob persists the received copy
    // (unarmed, to start its countdown when he views it) and the 'inbound-message' event fires.
    const aliceConvId = waiting.conversationId ?? '';
    await alice.channel.sendMessage(aliceConvId, 'meet at dawn');
    expect(alice.persisted).toHaveLength(1);
    expect(alice.persisted[0]?.meta.direction).toBe('out');
    expect(alice.persisted[0]?.meta.conversationId).toBe(aliceConvId);
    expect(alice.persisted[0]?.text).toBe('meet at dawn');

    // Microtask: Bob's persist-then-ack-then-event chain settles after the await above.
    await Promise.resolve();
    const inbound = eventOf(bob.events, 'inbound-message');
    expect(inbound).toBeDefined();
    expect((inbound?.payload as { conversationId: string }).conversationId).toBe(offerPayload.conversationId);
    expect(bob.persisted).toHaveLength(1);
    expect(bob.persisted[0]?.meta.direction).toBe('in');
    expect(bob.persisted[0]?.text).toBe('meet at dawn');
  });

  it('rejects a send on a channel that is not established', async () => {
    const gw = new FakeGateway();
    const alice = makeChannel(gw, ALICE);
    await alice.channel.connectGateway('ws://test/ws');
    await expect(alice.channel.sendMessage('nope', 'hi')).rejects.toThrow();
  });

  // Layer 1: a persisted identity is restored on reconnect, so the contact/mailbox is stable across
  // logins rather than minted fresh each time.
  it('restores a persisted identity so the contact is stable across reconnects', async () => {
    const gw = new FakeGateway();
    let saved: ConversationLike | null = null;
    const persistence = {
      loadSelf: () => Promise.resolve(saved),
      saveSelf: (conv: ConversationLike) => {
        saved = conv;
        return Promise.resolve();
      },
    };
    // First login: creates a fresh ALICE identity and persists it.
    const first = makeChannel(gw, ALICE, persistence);
    const c1 = await first.channel.connectGateway('ws://test/ws');
    expect(c1.selfContact).toBe(formatContact(ALICE));
    expect(saved).not.toBeNull();

    // Second login: the factory would mint a BOB identity, but loadSelf restores the saved ALICE
    // one, so the contact is unchanged.
    const second = makeChannel(gw, BOB, persistence);
    const c2 = await second.channel.connectGateway('ws://test/ws');
    expect(c2.selfContact).toBe(c1.selfContact);
  });
});
