/**
 * 1:1 conversation Session (M1). Composes the gated Handshake (handshake.ts) with the wasm
 * MLS Conversation, and maps application messages onto the Envelope transport.
 *
 * Layering: this module is bundler- and wasm-agnostic. It depends on a `ConversationLike`
 * surface that is injected (the real wasm `Conversation` class in production, a fake in tests).
 * Private key material NEVER reaches this layer: it only ever handles hex public keys, public
 * KeyPackages, Welcomes, and ciphertext. The real MLS crypto is verified by the Rust native
 * tests in crypto/src/conversation.rs.
 *
 * Group-formation roles (matches the proto and crypto core): the ACCEPTER creates the MLS
 * group (it holds both KeyPackages first) and emits the Welcome; the OFFERER joins from it.
 *
 * HONEST LIMIT (ADR-009): there is no out-of-band verification, so establishment is
 * trust-on-first-use; a hostile server could substitute keys. The §5.7 cross-check below
 * detects a key that disagrees with the accepted one and blocks, but it cannot stop a
 * consistent MITM where the server substituted both sides from the start.
 */

import { Handshake, HandshakeError, type PeerKey } from './handshake.js';
import type { Lifetime } from './index.js';

/** Opaque local identity. `signatureKeyHex` is the binding identity (ADR-008); label is local-only. */
export interface Identity {
  readonly signatureKeyHex: PeerKey;
  readonly keyPackage: Uint8Array;
  readonly label: string;
}

/**
 * The injected wasm `Conversation` surface. The real implementation is the wasm-bindgen class
 * from crypto/pkg; nothing here returns private key material.
 */
export interface ConversationLike {
  signaturePublicKeyHex(): string;
  keyPackage(): Uint8Array;
  createAndAdd(peerKeyPackage: Uint8Array): Uint8Array; // returns the MLS Welcome
  joinFromWelcome(welcome: Uint8Array): void;
  encrypt(plaintext: Uint8Array): Uint8Array;
  decrypt(ciphertext: Uint8Array): Uint8Array;
  peerSignatureKeyHex(): string;
  selfMailbox(): string; // our opaque inbound routing key (sealed sender, rotates per epoch)
  peerMailbox(): string; // where we publish to reach the peer
  mailboxTag(subject: string): string; // secret-keyed per-mailbox delivery-cursor tag (see group.ts)
  wipe(): void;
}

export type ConversationFactory = (label: string) => ConversationLike;

// Plain-data shapes the transport layer marshals to/from the generated protobuf types. Field
// names mirror the proto.
export interface OfferMsg {
  readonly fromSignatureKey: Uint8Array;
  readonly keyPackage: Uint8Array;
  readonly conversationId: string;
  readonly toRoutingKey: string;
}
export interface AcceptMsg {
  readonly fromSignatureKey: Uint8Array;
  readonly keyPackage: Uint8Array;
  readonly conversationId: string;
  readonly mlsWelcome: Uint8Array;
  readonly toRoutingKey: string;
}
export interface EnvelopeMsg {
  readonly messageId: Uint8Array;
  readonly routingKey: string;
  readonly payload: Uint8Array;
  readonly ttlSeconds: number;
}

/** What an inbound MLS payload decodes to: a user message (with its lifetime) or a revoke command.
 * Control and ignored frames are kept OUT of this type so a `{type:'message'}` consumer never has to
 * reason about them; `parseFrame` returns the wider `ParsedFrame`. */
export type IncomingFrame =
  | { readonly type: 'message'; readonly plaintext: Uint8Array; readonly lifetime: Lifetime }
  | { readonly type: 'revoke'; readonly targetMessageId: string };

/** A versioned application control frame that rides the encrypted stream alongside messages (buddy
 * icon, profile). Forward-compatible: a peer that does not recognize `controlType`/`version` drops it
 * rather than failing, so adding a control sub-type later never wedges an older peer. */
export type ControlFrame = {
  readonly type: 'control';
  readonly controlType: number;
  readonly version: number;
  readonly payload: Uint8Array;
};

/** A frame we deliberately drop: an unknown frame type, a truncated control frame, or an unknown
 * lifetime kind. It is RETURNED, never thrown, so one bad or future-versioned frame from a peer
 * cannot wedge the receive loop (security review). */
export type IgnoredFrame = { readonly type: 'ignored' };

/** Everything `parseFrame` can yield. */
export type ParsedFrame = IncomingFrame | ControlFrame | IgnoredFrame;

/** Default per-conversation lifetime until the user changes it (ADR-015 seed). */
export const DEFAULT_LIFETIME: Lifetime = { kind: 'duration', seconds: 86400 };

export class Session {
  private readonly handshake = new Handshake();
  private conv: ConversationLike | null = null;
  private pendingPeerKeyPackage: Uint8Array | null = null;
  private defaultLifetime: Lifetime = DEFAULT_LIFETIME;

  constructor(
    private readonly me: Identity,
    readonly conversationId: string,
    private readonly make: ConversationFactory,
  ) {}

  /** Set the per-conversation default lifetime applied when a message has no explicit override. */
  setDefaultLifetime(lifetime: Lifetime): void {
    this.defaultLifetime = lifetime;
  }

  getDefaultLifetime(): Lifetime {
    return this.defaultLifetime;
  }

  state(): ReturnType<Handshake['current']> {
    return this.handshake.current();
  }

  canSend(): boolean {
    return this.handshake.canSendMessage();
  }

  // --- offerer flow (offerer is the MLS joiner) ---

  makeOffer(toRoutingKey: string): OfferMsg {
    this.handshake.sendOffer(this.conversationId);
    return {
      fromSignatureKey: hexToBytes(this.me.signatureKeyHex),
      keyPackage: this.me.keyPackage,
      conversationId: this.conversationId,
      toRoutingKey,
    };
  }

  onAcceptReceived(accept: AcceptMsg): void {
    if (accept.conversationId !== this.conversationId) {
      throw new HandshakeError('conversation id mismatch');
    }
    const conv = this.make(this.me.label);
    conv.joinFromWelcome(accept.mlsWelcome);
    this.conv = conv;
    this.handshake.receiveAccept(bytesToHex(accept.fromSignatureKey));
    this.crossCheckPeerKey(conv);
  }

  // --- accepter flow (accepter is the MLS creator) ---

  onOfferReceived(offer: OfferMsg): void {
    if (offer.conversationId !== this.conversationId) {
      throw new HandshakeError('conversation id mismatch');
    }
    this.handshake.receiveOffer(this.conversationId, bytesToHex(offer.fromSignatureKey));
    this.pendingPeerKeyPackage = offer.keyPackage;
  }

  acceptOffer(toRoutingKey: string): AcceptMsg {
    if (this.pendingPeerKeyPackage === null) {
      throw new HandshakeError('no offer to accept');
    }
    const conv = this.make(this.me.label);
    const welcome = conv.createAndAdd(this.pendingPeerKeyPackage);
    this.conv = conv;
    this.handshake.accept();
    this.crossCheckPeerKey(conv);
    return {
      fromSignatureKey: hexToBytes(this.me.signatureKeyHex),
      keyPackage: this.me.keyPackage,
      conversationId: this.conversationId,
      mlsWelcome: welcome,
      toRoutingKey,
    };
  }

  // --- application messages (hard-gated) ---

  /**
   * Send a user message. `lifetime` defaults to the per-conversation default; the effective
   * lifetime rides INSIDE the encrypted payload (§3.2). `ttlSeconds` (transport backstop for
   * undelivered ciphertext) is derived from the lifetime when not given.
   */
  sendMessage(plaintext: Uint8Array, lifetime?: Lifetime, ttlSeconds?: number): EnvelopeMsg {
    const effective = lifetime ?? this.defaultLifetime;
    const framed = frameMessage(plaintext, effective);
    return this.emit(framed, ttlSeconds ?? deriveTtlSeconds(effective));
  }

  /**
   * Send a cooperative revoke command for one of our own messages. It rides the MLS channel as
   * an ordinary application message, so the server never learns which message is revoked (P2/P6).
   * A well-behaved recipient destroys its stored copy. Honest limit: it cannot recall a copy the
   * recipient already screenshotted or exported.
   */
  sendRevoke(targetMessageId: string): EnvelopeMsg {
    return this.emit(frameRevoke(targetMessageId), SEVEN_DAYS_SECONDS);
  }

  /** Our opaque inbound mailbox (sealed sender, §5.2): the transport subscribes to this. It is
   * derived from the MLS exporter secret and rotates each epoch. Only valid once established. */
  inboundMailbox(): string {
    return this.requireConv().selfMailbox();
  }

  private emit(framed: Uint8Array, ttlSeconds: number): EnvelopeMsg {
    this.handshake.assertCanSend();
    const conv = this.requireConv();
    // Sealed sender (§5.2): address the peer's epoch-rotating opaque mailbox, recomputed each send
    // so it tracks epoch rotation. The server sees an unpredictable subject, not an identity or a
    // stable pair, and no sender field. Pad to a fixed-size bucket BEFORE encryption so on-wire
    // ciphertext length leaks nothing; the padding lives inside the MLS ciphertext.
    return {
      messageId: randomBytes(16),
      routingKey: conv.peerMailbox(),
      payload: conv.encrypt(padToBucket(framed)),
      ttlSeconds,
    };
  }

  receiveMessage(env: EnvelopeMsg): ParsedFrame {
    this.handshake.assertCanSend();
    const conv = this.requireConv();
    // MLS must decrypt to identify the sender, so the plaintext is materialized first; we then
    // cross-check the peer key and refuse to SURFACE it if the key changed (security review).
    const padded = conv.decrypt(env.payload);
    this.handshake.observePeerKey(conv.peerSignatureKeyHex());
    if (!this.handshake.canSendMessage()) {
      padded.fill(0); // best-effort zeroize the JS copy; never return it
      throw new HandshakeError('peer key changed; message dropped');
    }
    return parseFrame(unpadFromBucket(padded));
  }

  wipe(): void {
    this.conv?.wipe();
    this.conv = null;
    this.pendingPeerKeyPackage = null;
  }

  private crossCheckPeerKey(conv: ConversationLike): void {
    // The MLS roster's peer key must agree with the key we accepted (§5.7). A disagreement
    // blocks the conversation rather than proceeding on a substituted key.
    this.handshake.observePeerKey(conv.peerSignatureKeyHex());
    if (!this.handshake.canSendMessage()) {
      throw new HandshakeError('peer key cross-check failed');
    }
  }

  private requireConv(): ConversationLike {
    if (this.conv === null) {
      throw new HandshakeError('no active conversation');
    }
    return this.conv;
  }
}

// --- message framing: a top-level frame type, then (for messages) the lifetime, all inside
//     the encrypted payload (§3.2). The server never sees frame type, lifetime, or revoke target.

const FRAME_MESSAGE = 0;
const FRAME_REVOKE = 1;
const FRAME_CONTROL = 2;

/** Application control-frame sub-types carried inside a FRAME_CONTROL frame. Forward-compatible: the
 * receiver drops an unknown sub-type. */
export const CONTROL_BUDDY_ICON = 1;
export const CONTROL_PROFILE = 2;
/** File-transfer signaling (WebRTC SDP/ICE) rides this sub-type; the file BYTES go peer-to-peer (N7). */
export const CONTROL_FILE = 3;
/** Audio/video call signaling (WebRTC SDP/ICE) rides this sub-type; the MEDIA goes peer-to-peer (P2). */
export const CONTROL_CALL = 4;
/** Away-configuration sync between YOUR OWN devices (most recent change wins). It rides the conversation
 * like the other identity frames, but a recipient adopts it ONLY when its authenticated sender is one of
 * the recipient's own devices (from_own_account); a peer drops it (it is never stored as a peer's bio). */
export const CONTROL_AWAY = 5;
/** Buddy-list sync between YOUR OWN devices. The buddy list is your contact graph, so it NEVER rides a
 * peer conversation; it is published ONLY to the hidden self-group (a group of your own devices), and a
 * recipient adopts it ONLY when its authenticated sender is one of its own devices (from_own_account).
 * A peer that somehow received it drops it. Per-buddy last-writer-wins (adds and removes both carry a
 * version, so the most recent change to each buddy converges on every device). */
export const CONTROL_BUDDIES = 6;
/** Buddy-GROUP-list sync between YOUR OWN devices. The named groups your buddies are filed under are part
 * of your contact graph, so like CONTROL_BUDDIES this NEVER rides a peer conversation: it is published
 * ONLY to the hidden self-group, and a recipient adopts it ONLY when its authenticated sender is one of
 * its own devices (from_own_account). It carries the group list (with tombstones) so an EMPTY group you
 * create, and a group you delete, both converge across your devices. Per-group last-writer-wins. */
export const CONTROL_GROUPS = 7;

const KIND_BURN = 0;
const KIND_DURATION = 1;
const KIND_UNTIL_REVOKED = 2;

const DELIVERY_FLOOR_SECONDS = 86400; // 1 day: undelivered ciphertext lingers at least this long
export const SEVEN_DAYS_SECONDS = 604800;

/** Transport TTL backstop for undelivered ciphertext, derived from the message lifetime. */
export function deriveTtlSeconds(lifetime: Lifetime): number {
  return lifetime.kind === 'duration'
    ? Math.max(lifetime.seconds, DELIVERY_FLOOR_SECONDS)
    : SEVEN_DAYS_SECONDS;
}

export function frameMessage(plaintext: Uint8Array, lifetime: Lifetime): Uint8Array {
  if (lifetime.kind === 'duration') {
    const out = new Uint8Array(6 + plaintext.length);
    out[0] = FRAME_MESSAGE;
    out[1] = KIND_DURATION;
    new DataView(out.buffer).setUint32(2, lifetime.seconds, false);
    out.set(plaintext, 6);
    return out;
  }
  const out = new Uint8Array(2 + plaintext.length);
  out[0] = FRAME_MESSAGE;
  out[1] = lifetime.kind === 'burn-on-read' ? KIND_BURN : KIND_UNTIL_REVOKED;
  out.set(plaintext, 2);
  return out;
}

export function frameRevoke(targetMessageId: string): Uint8Array {
  const id = new TextEncoder().encode(targetMessageId);
  const out = new Uint8Array(1 + id.length);
  out[0] = FRAME_REVOKE;
  out.set(id, 1);
  return out;
}

/** Build a versioned control frame: [FRAME_CONTROL, controlType, version, ...payload]. The payload is
 * opaque to this layer; the identity layer (controller) defines each sub-type's bytes. */
export function frameControl(controlType: number, version: number, payload: Uint8Array): Uint8Array {
  const out = new Uint8Array(3 + payload.length);
  out[0] = FRAME_CONTROL;
  out[1] = controlType & 0xff;
  out[2] = version & 0xff;
  out.set(payload, 3);
  return out;
}

export function parseFrame(framed: Uint8Array): ParsedFrame {
  const frameType = framed[0];
  if (frameType === FRAME_REVOKE) {
    return { type: 'revoke', targetMessageId: new TextDecoder().decode(framed.slice(1)) };
  }
  if (frameType === FRAME_CONTROL) {
    if (framed.length < 3) {
      return { type: 'ignored' }; // truncated control frame: drop
    }
    return { type: 'control', controlType: framed[1] ?? 0, version: framed[2] ?? 0, payload: framed.slice(3) };
  }
  if (frameType !== FRAME_MESSAGE) {
    return { type: 'ignored' }; // unknown frame type from a newer peer: drop, never throw (forward-compat)
  }
  const kind = framed[1];
  if (kind === KIND_DURATION) {
    const seconds = new DataView(framed.buffer, framed.byteOffset, framed.byteLength).getUint32(2, false);
    return { type: 'message', plaintext: framed.slice(6), lifetime: { kind: 'duration', seconds } };
  }
  if (kind === KIND_BURN) {
    return { type: 'message', plaintext: framed.slice(2), lifetime: { kind: 'burn-on-read' } };
  }
  if (kind === KIND_UNTIL_REVOKED) {
    return { type: 'message', plaintext: framed.slice(2), lifetime: { kind: 'until-revoked' } };
  }
  return { type: 'ignored' }; // unknown lifetime kind: drop, never throw
}

// --- fixed-size padding (P2 / §5.2): hide message length on the wire ---

/** Bucket sizes (bytes) a padded payload is rounded up to. Length leaks only which bucket. */
export const PAD_BUCKETS: readonly number[] = [512, 4096, 32768, 262144];

/** Pad `data` to the next bucket with a 4-byte big-endian length prefix. Oversize payloads (rare)
 * round up to a whole-bucket multiple so length still only leaks coarsely. */
export function padToBucket(data: Uint8Array): Uint8Array {
  const need = data.length + 4;
  const largest = PAD_BUCKETS[PAD_BUCKETS.length - 1] ?? 512;
  let size = PAD_BUCKETS.find((b) => b >= need);
  if (size === undefined) {
    size = Math.ceil(need / largest) * largest;
  }
  const out = new Uint8Array(size);
  new DataView(out.buffer).setUint32(0, data.length, false);
  out.set(data, 4);
  return out;
}

/** Recover the original bytes from a padded bucket. */
export function unpadFromBucket(padded: Uint8Array): Uint8Array {
  if (padded.length < 4) {
    throw new Error('padding too short');
  }
  const len = new DataView(padded.buffer, padded.byteOffset, padded.byteLength).getUint32(0, false);
  if (len + 4 > padded.length) {
    throw new Error('bad padding length');
  }
  return padded.slice(4, 4 + len);
}

// --- small helpers ---

function bytesToHex(b: Uint8Array): string {
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

export { HandshakeError } from './handshake.js';
