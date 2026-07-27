/**
 * Live conversation channel (M4): drives the real gateway transport for one device. It holds the
 * single WebSocket Transport, the per-conversation Session plus its wasm Conversation, and turns
 * inbound gateway frames into UI events. Its browser-only dependencies are injected (the WebSocket
 * connect(), the wasm Conversation factory, the timer hooks, and a pushEvent sink to the main
 * thread), so this module stays gate-clean and is unit-tested with fakes.
 *
 * Bootstrap routing (sealed sender plus trust-on-first-use, ADR-009): before a group exists there
 * is no epoch mailbox, so each device subscribes to a stable bootstrap routing key derived from its
 * signature public key, and advertises that key in its contact string. The initiator addresses its
 * offer to the peer's bootstrap key; the accepter addresses its accept back to the offerer's
 * signature key carried in the offer. After establishment both sides re-subscribe to the
 * epoch-rotating mailbox.
 *
 * Persistence (M4+): sent and received messages are handed to an injected persist sink (the
 * controller seals them into the crypto-erasable keyvault). The durable history is the source of
 * truth for a conversation view; this module no longer keeps message text in memory. An inbound
 * delivery is acked to the gateway only AFTER it is durably stored, so an undelivered message stays
 * held by the gateway until the recipient logs in and stores it (hold-until-seen at the network
 * layer). The destruction countdown for an inbound message starts when the recipient opens the
 * conversation (hold-until-seen at the device layer); see controller.openChannel.
 */

import {
  Session,
  type Identity,
  type ConversationLike,
  type OfferMsg,
  type AcceptMsg,
  type EnvelopeMsg,
} from './session.js';
import type { Transport, TransportHandlers } from './transport.js';
import type { LogEntry, TransmitModel, ChannelSummary } from './app.js';
import type { Lifetime } from './index.js';

/** Browser-only dependencies injected by the worker host (kept out of this gated module). */
export interface LiveDeps {
  connect(url: string, handlers: TransportHandlers): Transport;
  makeConversation(label: string): ConversationLike;
  pushEvent(kind: string, payload: unknown): void;
  /** Timer hooks for the lifetime manager (setTimeout/clearTimeout in the worker). */
  schedule(delayMs: number, cb: () => void): unknown;
  cancel(handle: unknown): void;
  /** AEAD-seal a Conversation's full state under the raw MSK (wasm Conversation.exportSealed). */
  sealConversation(conv: ConversationLike, msk: Uint8Array): Uint8Array;
  /** Reconstruct a Conversation from sealed bytes under the raw MSK (wasm Conversation.fromSealed). */
  restoreConversation(msk: Uint8Array, sealed: Uint8Array): ConversationLike;
}

/** Persist one sent/received message into the crypto-erasable keyvault (wired to the controller). */
export type PersistMessage = (
  meta: { messageId: string; conversationId: string; direction: 'in' | 'out'; lifetime: Lifetime },
  plaintext: Uint8Array,
) => Promise<void>;

/**
 * Durable identity persistence (wired to the controller, which holds the MSK and the sealed-session
 * store). loadSelf restores our long-lived signer-bearing Conversation so a device's contact and
 * bootstrap mailbox are STABLE across logins; saveSelf persists it on first creation. Layer 1
 * persists only the identity (the signer), not group/ratchet state, so it carries no forward-secrecy
 * residual.
 */
export interface LivePersistence {
  loadSelf(): Promise<ConversationLike | null>;
  saveSelf(conv: ConversationLike): Promise<void>;
}

const enc = new TextEncoder();
const CONTACT_TAG = 'deaddrop';
const CONTACT_VERSION = '1';

/** A short, human-readable fingerprint of a signature key for recognition (first 4 bytes). */
export function fingerprintOf(sigHex: string): string {
  return [0, 2, 4, 6].map((i) => sigHex.slice(i, i + 2).toUpperCase()).join('·');
}

function shortName(sigHex: string): string {
  return sigHex.slice(0, 6).toUpperCase();
}

interface Contact {
  readonly routingKey: string;
  readonly sigKeyHex: string;
}

/** The copy-pasteable contact string a peer shares out of band. */
export function formatContact(sigHex: string): string {
  return `${CONTACT_TAG}:${CONTACT_VERSION}:${sigHex}:${sigHex}`;
}

export function parseContact(s: string): Contact {
  const parts = s.trim().split(':');
  if (parts.length !== 4 || parts[0] !== CONTACT_TAG || parts[1] !== CONTACT_VERSION) {
    throw new Error('that does not look like a DEAD DROP contact');
  }
  const routingKey = parts[2] ?? '';
  const sigKeyHex = parts[3] ?? '';
  if (routingKey.length === 0 || sigKeyHex.length === 0) {
    throw new Error('that contact is incomplete');
  }
  return { routingKey, sigKeyHex };
}

function bytesToHex(b: Uint8Array): string {
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
}

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function systemEntry(text: string): LogEntry {
  return { kind: 'system', text: `» ${text}` };
}

interface ActiveSession {
  readonly session: Session;
  readonly conversationId: string;
  readonly peerSigHex: string; // pinned (TOFU) for the offerer; observed for the accepter
  readonly peerLabel: string;
  established: boolean;
}

export class LiveChannel {
  private transport: Transport | null = null;
  private conv: ConversationLike | null = null;
  private identity: Identity | null = null;
  private selfRoutingKey = '';
  private readonly sessions = new Map<string, ActiveSession>();

  constructor(
    private readonly deps: LiveDeps,
    private readonly persistChannel: (summary: ChannelSummary) => Promise<void>,
    private readonly persistMessage: PersistMessage,
    private readonly persistence?: LivePersistence,
  ) {}

  /** Our copy-pasteable contact string, once connected. */
  selfContact(): string | undefined {
    return this.identity !== null ? formatContact(this.identity.signatureKeyHex) : undefined;
  }

  selfFingerprint(): string {
    return this.identity !== null ? fingerprintOf(this.identity.signatureKeyHex) : 'pending';
  }

  /** Open the gateway WebSocket and subscribe to our stable bootstrap mailbox so an incoming offer
   * reaches us. Our identity is RESTORED from durable storage when present (so the contact and
   * mailbox are stable across logins) and otherwise created fresh and persisted. */
  async connectGateway(url: string): Promise<{ ok: boolean; selfContact: string }> {
    const restored = this.persistence !== undefined ? await this.persistence.loadSelf() : null;
    const conv = restored ?? this.deps.makeConversation('me');
    const identity: Identity = {
      signatureKeyHex: conv.signaturePublicKeyHex(),
      keyPackage: conv.keyPackage(),
      label: 'me',
    };
    this.conv = conv;
    this.identity = identity;
    this.selfRoutingKey = identity.signatureKeyHex;
    if (restored === null && this.persistence !== undefined) {
      await this.persistence.saveSelf(conv);
    }
    this.transport = this.deps.connect(url, this.handlers());
    // Secret-keyed per-mailbox delivery-cursor tag (see transport.ts); conv is the wasm session set above.
    this.transport.setConsumerIdResolver((subject) => conv.mailboxTag(subject));
    this.transport.subscribe(this.selfRoutingKey);
    this.deps.pushEvent('connection', { state: 'live' });
    return { ok: true, selfContact: formatContact(identity.signatureKeyHex) };
  }

  /** Initiator: address an offer to the pasted contact and return a waiting conversation view. */
  offerToContact(contactStr: string): TransmitModel {
    const contact = parseContact(contactStr);
    const t = this.requireTransport();
    const conversationId = `c-${crypto.randomUUID()}`;
    const session = this.newSession(conversationId);
    const offer = session.makeOffer(contact.routingKey);
    t.sendOffer(offer);
    this.sessions.set(conversationId, {
      session,
      conversationId,
      peerSigHex: contact.sigKeyHex,
      peerLabel: shortName(contact.sigKeyHex),
      established: false,
    });
    return {
      secure: false,
      peer: shortName(contact.sigKeyHex),
      fingerprint: fingerprintOf(contact.sigKeyHex),
      log: [systemEntry('offer sent · waiting for them to accept')],
      compose: '',
      conversationId,
    };
  }

  /** Accepter: complete the mutual accept, re-subscribe to the epoch mailbox, persist the channel. */
  async acceptKeyExchange(conversationId: string): Promise<void> {
    const active = this.sessions.get(conversationId);
    if (active === undefined) {
      throw new Error('no pending offer for this channel');
    }
    const t = this.requireTransport();
    // Address the accept to the offerer's bootstrap key (the key carried in their offer), which is
    // the mailbox they are still subscribed to until they establish and rotate.
    const accept = active.session.acceptOffer(active.peerSigHex);
    t.sendAccept(accept);
    t.subscribe(active.session.inboundMailbox());
    active.established = true;
    await this.persist(active);
    this.deps.pushEvent('connection', { state: 'secure' });
  }

  /** Send a plaintext message on an established channel and persist our copy (armed immediately). */
  async sendMessage(conversationId: string, text: string): Promise<void> {
    const active = this.sessions.get(conversationId);
    if (active === undefined || !active.established) {
      throw new Error('this channel is not open yet');
    }
    const lifetime = active.session.getDefaultLifetime();
    const env = active.session.sendMessage(enc.encode(text));
    this.requireTransport().publish(env);
    await this.persistMessage(
      { messageId: bytesToHex(env.messageId), conversationId, direction: 'out', lifetime },
      enc.encode(text),
    );
  }

  private handlers(): TransportHandlers {
    return {
      onOffer: (offer) => {
        this.onOffer(offer);
      },
      onAccept: (accept) => {
        this.onAccept(accept);
      },
      onDeliver: (env) => {
        this.onDeliver(env);
      },
      onReceipt: () => {
        /* delivery receipt: nothing to surface in M4 */
      },
      onError: (code, detail) => {
        this.deps.pushEvent('error', { code, detail });
      },
      onClose: () => {
        this.deps.pushEvent('connection', { state: 'offline' });
      },
    };
  }

  private onOffer(offer: OfferMsg): void {
    const peerSigHex = bytesToHex(offer.fromSignatureKey);
    const session = this.newSession(offer.conversationId);
    try {
      session.onOfferReceived(offer);
    } catch (e) {
      this.deps.pushEvent('error', { code: -1, detail: errMsg(e) });
      return;
    }
    this.sessions.set(offer.conversationId, {
      session,
      conversationId: offer.conversationId,
      peerSigHex,
      peerLabel: shortName(peerSigHex),
      established: false,
    });
    this.deps.pushEvent('offer', {
      conversationId: offer.conversationId,
      peer: shortName(peerSigHex),
      peerFingerprint: fingerprintOf(peerSigHex),
    });
  }

  private onAccept(accept: AcceptMsg): void {
    const active = this.sessions.get(accept.conversationId);
    if (active === undefined) {
      return;
    }
    // Trust-on-first-use enforcement: the accepter's key must equal the one in the contact we used.
    if (bytesToHex(accept.fromSignatureKey) !== active.peerSigHex) {
      this.deps.pushEvent('error', { code: -1, detail: 'peer key did not match the contact you used' });
      return;
    }
    try {
      active.session.onAcceptReceived(accept);
    } catch (e) {
      this.deps.pushEvent('error', { code: -1, detail: errMsg(e) });
      return;
    }
    this.requireTransport().subscribe(active.session.inboundMailbox());
    active.established = true;
    void this.persist(active);
    this.deps.pushEvent('connection', { state: 'secure' });
    this.deps.pushEvent('established', { conversationId: active.conversationId });
  }

  private onDeliver(env: EnvelopeMsg): void {
    const active = [...this.sessions.values()].find((a) => a.established);
    if (active === undefined) {
      return;
    }
    let frame;
    try {
      frame = active.session.receiveMessage(env);
    } catch (e) {
      this.deps.pushEvent('error', { code: -1, detail: errMsg(e) });
      return;
    }
    if (frame.type !== 'message') {
      // A revoke command rides the same channel; ack it (the lifetime manager applies it elsewhere).
      this.requireTransport().ack(env.messageId);
      return;
    }
    const messageId = bytesToHex(env.messageId);
    const conversationId = active.conversationId;
    // Ack only AFTER the message is durably stored, so an undelivered message stays held by the
    // gateway until the recipient is logged in and has saved it (hold-until-seen, network layer).
    void this.persistMessage({ messageId, conversationId, direction: 'in', lifetime: frame.lifetime }, frame.plaintext)
      .then(() => {
        this.requireTransport().ack(env.messageId);
        this.deps.pushEvent('inbound-message', { conversationId });
      })
      .catch((e) => {
        this.deps.pushEvent('error', { code: -1, detail: errMsg(e) });
      });
  }

  private newSession(conversationId: string): Session {
    const identity = this.identity;
    const conv = this.conv;
    if (identity === null || conv === null) {
      throw new Error('connect to the gateway first');
    }
    return new Session(identity, conversationId, () => conv);
  }

  private persist(a: ActiveSession): Promise<void> {
    const summary: ChannelSummary = {
      id: a.conversationId,
      peer: a.peerLabel,
      fingerprint: fingerprintOf(a.peerSigHex),
      status: 'secure',
      preview: 'secure channel open',
      unread: 0,
    };
    return this.persistChannel(summary).catch(() => {
      /* persistence is best-effort here; a locked vault must not break the live channel */
    });
  }

  private requireTransport(): Transport {
    if (this.transport === null) {
      throw new Error('connect to the gateway first');
    }
    return this.transport;
  }
}
