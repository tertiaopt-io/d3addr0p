import { describe, it, expect } from 'vitest';
import {
  Session,
  HandshakeError,
  frameMessage,
  frameRevoke,
  frameControl,
  parseFrame,
  deriveTtlSeconds,
  DEFAULT_LIFETIME,
  padToBucket,
  unpadFromBucket,
  PAD_BUCKETS,
  CONTROL_BUDDY_ICON,
  CONTROL_PROFILE,
  type ConversationLike,
  type Identity,
} from './session.js';

const ALICE_HEX = 'a'.repeat(64);
const BOB_HEX = 'b'.repeat(64);
const MALLORY_HEX = 'c'.repeat(64);
const enc = new TextEncoder();
const dec = new TextDecoder();

function identity(hex: string, label: string): Identity {
  return { signatureKeyHex: hex, keyPackage: enc.encode(`${label}-kp`), label };
}

/**
 * Minimal in-memory fake of the wasm Conversation. encrypt/decrypt are identity (the real
 * MLS crypto is proven by the Rust tests); `peerHex` is mutable so a test can simulate a
 * mid-conversation key substitution.
 */
class FakeConversation implements ConversationLike {
  peerHex: string;
  constructor(
    private readonly selfHex: string,
    peerHex: string,
  ) {
    this.peerHex = peerHex;
  }
  signaturePublicKeyHex(): string {
    return this.selfHex;
  }
  keyPackage(): Uint8Array {
    return enc.encode(`${this.selfHex}-kp`);
  }
  createAndAdd(_peerKeyPackage: Uint8Array): Uint8Array {
    return enc.encode('welcome');
  }
  joinFromWelcome(_welcome: Uint8Array): void {}
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

function establishedPair(): {
  alice: Session;
  bob: Session;
  aliceConv: FakeConversation;
  bobConv: FakeConversation;
} {
  const aliceConv = new FakeConversation(ALICE_HEX, BOB_HEX);
  const bobConv = new FakeConversation(BOB_HEX, ALICE_HEX);
  // Bob is the offerer (MLS joiner); Alice is the accepter (MLS creator).
  const bob = new Session(identity(BOB_HEX, 'bob'), 'conv-1', () => bobConv);
  const alice = new Session(identity(ALICE_HEX, 'alice'), 'conv-1', () => aliceConv);

  const offer = bob.makeOffer('mailbox-alice');
  alice.onOfferReceived(offer);
  const accept = alice.acceptOffer('mailbox-bob');
  bob.onAcceptReceived(accept);
  return { alice, bob, aliceConv, bobConv };
}

describe('Session (M1)', () => {
  it('reaches established only after the full mutual handshake', () => {
    const { alice, bob } = establishedPair();
    expect(alice.canSend()).toBe(true);
    expect(bob.canSend()).toBe(true);
  });

  it('forbids sending before establishment', () => {
    const bob = new Session(identity(BOB_HEX, 'bob'), 'conv-1', () => new FakeConversation(BOB_HEX, ALICE_HEX));
    bob.makeOffer('mailbox-alice');
    expect(() =>
      bob.sendMessage(enc.encode('too early'), { kind: 'burn-on-read' }, 60),
    ).toThrow(HandshakeError);
  });

  it('carries a message end to end with its lifetime', () => {
    const { alice, bob } = establishedPair();
    const env = alice.sendMessage(enc.encode('meet at the dead drop'), { kind: 'duration', seconds: 30 }, 60);
    // Sealed sender: addressed to Bob's derived inbound mailbox, not a static handle.
    expect(env.routingKey).toBe(`${BOB_HEX}-mbox`);
    const received = bob.receiveMessage(env);
    if (received.type !== 'message') {
      throw new Error('expected a message');
    }
    expect(dec.decode(received.plaintext)).toBe('meet at the dead drop');
    expect(received.lifetime).toEqual({ kind: 'duration', seconds: 30 });
  });

  it('applies the per-conversation default lifetime when no override is given', () => {
    const { alice, bob } = establishedPair();
    alice.setDefaultLifetime({ kind: 'duration', seconds: 5 });
    const env = alice.sendMessage(enc.encode('uses default'));
    const received = bob.receiveMessage(env);
    if (received.type !== 'message') {
      throw new Error('expected a message');
    }
    expect(received.lifetime).toEqual({ kind: 'duration', seconds: 5 });
    // ttl backstop is derived from the lifetime (floored at one day).
    expect(env.ttlSeconds).toBe(86400);
  });

  it('addresses messages to the peer derived mailbox and exposes its own inbound mailbox', () => {
    const { alice, bob } = establishedPair();
    // Alice publishes to Bob's inbound mailbox; Bob subscribes to that same mailbox.
    const env = alice.sendMessage(enc.encode('hi'));
    expect(env.routingKey).toBe(bob.inboundMailbox());
    // Each side's inbound mailbox is distinct (per-party sealed sender).
    expect(alice.inboundMailbox()).not.toBe(bob.inboundMailbox());
  });

  it('sends and receives a revoke command over the MLS channel', () => {
    const { alice, bob } = establishedPair();
    const env = alice.sendRevoke('target-message-id');
    const received = bob.receiveMessage(env);
    expect(received).toEqual({ type: 'revoke', targetMessageId: 'target-message-id' });
  });

  it('rejects a conversation-id mismatch', () => {
    const alice = new Session(identity(ALICE_HEX, 'alice'), 'conv-1', () => new FakeConversation(ALICE_HEX, BOB_HEX));
    const wrongOffer = {
      fromSignatureKey: new Uint8Array([0xbb]),
      keyPackage: enc.encode('kp'),
      conversationId: 'conv-OTHER',
      toRoutingKey: 'mailbox-alice',
    };
    expect(() => alice.onOfferReceived(wrongOffer)).toThrow(HandshakeError);
  });

  it('blocks at setup if the MLS roster key disagrees with the accepted key (§5.7)', () => {
    // Bob accepts Alice's key, but his Conversation reports a DIFFERENT peer key (substitution).
    const bobConv = new FakeConversation(BOB_HEX, MALLORY_HEX);
    const aliceConv = new FakeConversation(ALICE_HEX, BOB_HEX);
    const bob = new Session(identity(BOB_HEX, 'bob'), 'conv-1', () => bobConv);
    const alice = new Session(identity(ALICE_HEX, 'alice'), 'conv-1', () => aliceConv);

    const offer = bob.makeOffer('mailbox-alice');
    alice.onOfferReceived(offer);
    const accept = alice.acceptOffer('mailbox-bob');
    // Bob's roster key (MALLORY) != accepted key (ALICE) -> cross-check throws.
    expect(() => bob.onAcceptReceived(accept)).toThrow(HandshakeError);
    expect(bob.canSend()).toBe(false);
  });

  it('drops the plaintext if the peer key changes mid-conversation (does not surface it)', () => {
    const { alice, bob, bobConv } = establishedPair();
    const env = alice.sendMessage(enc.encode('secret'), { kind: 'burn-on-read' }, 60);
    // Server substitutes the peer key after establishment.
    bobConv.peerHex = MALLORY_HEX;
    expect(() => bob.receiveMessage(env)).toThrow(HandshakeError);
    expect(bob.canSend()).toBe(false);
  });
});

describe('message framing (§3.2)', () => {
  it('round-trips every lifetime kind inside the payload', () => {
    const pt = enc.encode('payload');
    for (const lifetime of [
      { kind: 'burn-on-read' } as const,
      { kind: 'duration', seconds: 86400 } as const,
      { kind: 'until-revoked' } as const,
    ]) {
      const parsed = parseFrame(frameMessage(pt, lifetime));
      if (parsed.type !== 'message') {
        throw new Error('expected a message');
      }
      expect(dec.decode(parsed.plaintext)).toBe('payload');
      expect(parsed.lifetime).toEqual(lifetime);
    }
  });

  it('round-trips a revoke frame distinctly from a message frame', () => {
    const parsed = parseFrame(frameRevoke('msg-42'));
    expect(parsed).toEqual({ type: 'revoke', targetMessageId: 'msg-42' });
  });

  it('derives transport ttl from lifetime (floored for duration, 7d otherwise)', () => {
    expect(deriveTtlSeconds({ kind: 'duration', seconds: 10 })).toBe(86400);
    expect(deriveTtlSeconds({ kind: 'duration', seconds: 100000 })).toBe(100000);
    expect(deriveTtlSeconds({ kind: 'burn-on-read' })).toBe(604800);
    expect(DEFAULT_LIFETIME).toEqual({ kind: 'duration', seconds: 86400 });
  });
});

describe('fixed-size padding (P2)', () => {
  it('pads different-length messages to the SAME bucket size (length hidden)', () => {
    const tiny = padToBucket(enc.encode('a'));
    const small = padToBucket(enc.encode('a much longer but still small message'));
    expect(tiny.length).toBe(PAD_BUCKETS[0]);
    expect(small.length).toBe(PAD_BUCKETS[0]);
    expect(tiny.length).toBe(small.length); // an observer cannot tell them apart by length
  });

  it('round-trips the exact bytes through pad/unpad', () => {
    const unit = PAD_BUCKETS[0] ?? 1;
    for (const n of [0, 1, 500, 508, 4096, 70000]) {
      const data = new Uint8Array(n).map((_, i) => i & 0xff);
      const padded = padToBucket(data);
      expect(padded.length % unit).toBe(0); // always a whole-bucket multiple
      expect([...unpadFromBucket(padded)]).toEqual([...data]);
    }
  });

  it('rejects malformed padding', () => {
    expect(() => unpadFromBucket(new Uint8Array(2))).toThrow();
  });
});

describe('control frames (forward-compatible identity distribution)', () => {
  it('round-trips a versioned control frame with its sub-type, version, and payload', () => {
    const payload = enc.encode('{"bio":"at the lighthouse"}');
    const parsed = parseFrame(frameControl(CONTROL_PROFILE, 1, payload));
    expect(parsed).toEqual({ type: 'control', controlType: CONTROL_PROFILE, version: 1, payload });
  });

  it('decodes an UNKNOWN control sub-type as a control frame (the higher layer drops it, never throws)', () => {
    const parsed = parseFrame(frameControl(0x7f, 9, enc.encode('future')));
    if (parsed.type !== 'control') {
      throw new Error('expected a control frame');
    }
    expect(parsed.controlType).toBe(0x7f); // a peer on a newer version can ship a sub-type we ignore
    expect(parsed.version).toBe(9);
  });

  it('drops an unknown FRAME TYPE instead of throwing (a newer peer cannot wedge us)', () => {
    expect(parseFrame(new Uint8Array([0xfe, 1, 2, 3]))).toEqual({ type: 'ignored' });
  });

  it('drops an unknown lifetime kind instead of throwing', () => {
    expect(parseFrame(new Uint8Array([0, 0x7e, 0, 0]))).toEqual({ type: 'ignored' }); // FRAME_MESSAGE, bogus kind
  });

  it('drops a truncated control frame', () => {
    expect(parseFrame(new Uint8Array([2]))).toEqual({ type: 'ignored' }); // FRAME_CONTROL with no sub-type/version
  });

  it('keeps an emoji/initials icon control frame inside the smallest padding bucket (no size signal)', () => {
    // An emoji/initials icon plus the 3-byte control header must fit the 512-byte bucket so it is
    // indistinguishable on the wire from an ordinary text message (the larger image bucket is the
    // only path that emits a detectable size, which is disclosed in honest-limits).
    const icon = enc.encode(JSON.stringify({ kind: 'emoji', v: '\u{1F47B}', bg: '#2a52d6' }));
    const padded = padToBucket(frameControl(CONTROL_BUDDY_ICON, 1, icon));
    expect(padded.length).toBe(PAD_BUCKETS[0]);
  });
});
