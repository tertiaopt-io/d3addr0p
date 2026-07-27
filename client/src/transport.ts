/**
 * Client transport (M3): routes protobuf frames between the Session and the gateway WebSocket.
 *
 * The routing/dispatch logic here is transport-agnostic and fully tested: it depends on an
 * injected `Socket` (the real browser WebSocket in production, a fake in tests) and an injected
 * `WireCodec` (the real protobuf codec over the generated wire types in production, a fake in
 * tests). The irreducible browser glue — opening a WebSocket and the protobuf codec — lives in a
 * separate, gate-excluded adapter (wsadapter.ts), so this module stays gated and verifiable.
 *
 * The transport only ever moves opaque envelopes and public handshake material; it never sees
 * keys or plaintext (the Session/crypto core hold those).
 */

import type { EnvelopeMsg, OfferMsg, AcceptMsg } from './session.js';

/** A decoded inbound frame from the gateway. */
export type IncomingServerFrame =
  | { readonly type: 'deliver'; readonly envelope: EnvelopeMsg }
  | { readonly type: 'receipt'; readonly messageId: Uint8Array }
  | { readonly type: 'error'; readonly code: number; readonly detail: string }
  | { readonly type: 'offer'; readonly offer: OfferMsg }
  | { readonly type: 'accept'; readonly accept: AcceptMsg };

/** Marshals outbound client frames to bytes and decodes inbound bytes to a typed server frame. */
export interface WireCodec {
  encodeSubscribe(routingKey: string, consumerId: string): Uint8Array;
  encodePublish(envelope: EnvelopeMsg): Uint8Array;
  encodeAck(messageId: Uint8Array): Uint8Array;
  encodeOffer(offer: OfferMsg): Uint8Array;
  encodeAccept(accept: AcceptMsg): Uint8Array;
  decodeServerFrame(bytes: Uint8Array): IncomingServerFrame;
}

/** A bidirectional binary socket (a WebSocket in production). */
export interface Socket {
  send(bytes: Uint8Array): void;
  close(): void;
  onMessage(handler: (bytes: Uint8Array) => void): void;
  onClose(handler: () => void): void;
}

/** Callbacks the Session/app layer registers for inbound frames. */
export interface TransportHandlers {
  onDeliver(envelope: EnvelopeMsg): void;
  onReceipt(messageId: Uint8Array): void;
  onOffer(offer: OfferMsg): void;
  onAccept(accept: AcceptMsg): void;
  onError(code: number, detail: string): void;
  onClose?(): void;
}

/** Lowercase hex of a message id, for keying the unconfirmed-frames map. */
function hexId(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

export class Transport {
  constructor(
    private readonly socket: Socket,
    private readonly codec: WireCodec,
    private readonly handlers: TransportHandlers,
  ) {
    this.socket.onMessage((bytes) => {
      this.dispatch(bytes);
    });
    this.socket.onClose(() => {
      this.handlers.onClose?.();
    });
  }

  // Resolves the per-MAILBOX consumer id sent with each subscribe. The id keys this device's delivery
  // cursor on the bus: each blob is held until every consumer of the mailbox acks it, and a re-subscribe
  // redelivers whatever THIS device has not acked, which closes the contested-crash fork (a rival commit
  // received but never durably processed is redelivered after the reload). The owner supplies a resolver
  // that returns a SECRET-KEYED per-mailbox tag (not the raw bootstrap key), so the gateway's registry
  // cannot be snapshotted into a device-to-conversation map. Absent resolver => legacy empty id.
  private consumerIdFor: (routingKey: string) => string = () => '';
  setConsumerIdResolver(resolver: (routingKey: string) => string): void {
    this.consumerIdFor = resolver;
  }

  /** Begin receiving for an opaque recipient mailbox. */
  subscribe(routingKey: string): void {
    this.socket.send(this.codec.encodeSubscribe(routingKey, this.consumerIdFor(routingKey)));
  }

  private readonly publishQueue: EnvelopeMsg[] = [];
  private publishTimer: ReturnType<typeof setTimeout> | null = null;
  // Adaptive pacing. The gateway flood-control bucket (PubRate/s, burst 2x) drops any publish over the
  // limit WITHOUT a receipt and answers with a separate async RATE_LIMIT error. So delivery is confirmed
  // by receipts, never by send() returning. We start at the floor (~18/s), grow the gap on every
  // RATE_LIMIT and retransmit everything still unconfirmed, and ease back toward the floor after a clean
  // streak. This self-tunes below whatever the server's actual rate is (even if it is set below 18/s)
  // without the client needing to know it, and it stops a rate-limited frame (e.g. the new device's buddy
  // list) from being silently lost.
  private static readonly PUBLISH_GAP_FLOOR_MS = 55; // ~18/s: the steady pace on a healthy link
  private static readonly PUBLISH_GAP_CAP_MS = 1000; // slowest we ever pace under sustained limiting
  private static readonly RATE_LIMIT_CODE = 3; // ERROR_CODE_RATE_LIMIT (schema deaddrop.proto)
  private static readonly CLEAN_STREAK_TO_EASE = 8; // receipts in a row before easing the pace back
  private static readonly MAX_UNCONFIRMED = 256; // bound the retry buffer so a never-receipted frame cannot leak
  private currentGapMs = Transport.PUBLISH_GAP_FLOOR_MS;
  private cleanSinceBackoff = 0;
  private retryTimer: ReturnType<typeof setTimeout> | null = null;
  // Frames sent to the socket but not yet confirmed by a gateway receipt. On RATE_LIMIT the still-unconfirmed
  // set is retransmitted. NOTE: the gateway bus does NOT dedup on publish (only Ack is id-keyed) and replay
  // protection is recipient-side MLS, so we retransmit only genuinely-dropped frames (after a short settle
  // so in-flight receipts prune the delivered ones first) to avoid needless duplicate deliveries. Bounded by
  // MAX_UNCONFIRMED (drop-oldest) so a frame the gateway rejects without a receipt (e.g. a non-RATE_LIMIT
  // terminal error) cannot accumulate.
  private readonly unconfirmed = new Map<string, EnvelopeMsg>();

  /** Publish an opaque ciphertext envelope. Paced + retried so a burst never trips flood control and a
   * rate-limited frame is retransmitted rather than lost. */
  publish(envelope: EnvelopeMsg): void {
    this.publishQueue.push(envelope);
    this.drainPublishQueue();
  }

  private drainPublishQueue(): void {
    if (this.publishTimer !== null) {
      return; // already draining: the timer will pick up the newly queued envelope
    }
    const next = this.publishQueue[0];
    if (next === undefined) {
      return;
    }
    try {
      this.socket.send(this.codec.encodePublish(next));
    } catch {
      // The socket dropped mid-burst (a closed WebSocket throws on send). Leave the frame at the head of
      // the queue and stop the pacer instead of letting the throw escape uncaught from the timer callback.
      // connectGateway's reconnect lifts the undrained queue (and unconfirmed frames) via takePending() and
      // re-publishes them on the fresh socket, so a paced-but-unsent frame is not lost.
      return;
    }
    this.publishQueue.shift();
    this.unconfirmed.set(hexId(next.messageId), next); // confirmed by a receipt, not by send() returning
    while (this.unconfirmed.size > Transport.MAX_UNCONFIRMED) {
      // A frame the gateway rejected without a receipt (a non-RATE_LIMIT terminal error) would otherwise
      // strand here forever; drop the oldest so the retry buffer stays bounded.
      const oldest = this.unconfirmed.keys().next().value;
      if (oldest === undefined) {
        break;
      }
      this.unconfirmed.delete(oldest);
    }
    this.publishTimer = setTimeout(() => {
      this.publishTimer = null;
      this.drainPublishQueue();
    }, this.currentGapMs);
  }

  /** A gateway RATE_LIMIT: grow the pace, then after a short settle retransmit whatever is STILL unconfirmed.
   * The settle lets receipts for the accepted frames prune themselves out, so only the genuinely dropped
   * frames are resent (the bus does not dedup, so a needless resend would duplicate at the recipient). One
   * scheduled sweep covers a whole burst of RATE_LIMIT errors. Self-tunes below any server rate. */
  private onRateLimited(): void {
    this.currentGapMs = Math.min(Transport.PUBLISH_GAP_CAP_MS, Math.ceil(this.currentGapMs * 1.5));
    this.cleanSinceBackoff = 0;
    if (this.retryTimer !== null) {
      return; // a retry sweep is already scheduled; it covers this rate-limit burst
    }
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      if (this.unconfirmed.size > 0) {
        const retry = [...this.unconfirmed.values()]; // whatever survived the settle = the dropped frames
        this.unconfirmed.clear();
        this.publishQueue.unshift(...retry); // oldest first, ahead of newly queued frames
      }
      this.drainPublishQueue();
    }, this.currentGapMs);
  }

  /** A clean receipt: the frame landed. After a sustained clean streak, ease the pace back toward the floor
   * so one transient burst does not slow the link forever. */
  private onDelivered(messageId: Uint8Array): void {
    this.unconfirmed.delete(hexId(messageId));
    if (this.currentGapMs > Transport.PUBLISH_GAP_FLOOR_MS && ++this.cleanSinceBackoff >= Transport.CLEAN_STREAK_TO_EASE) {
      this.currentGapMs = Math.max(Transport.PUBLISH_GAP_FLOOR_MS, Math.floor(this.currentGapMs / 1.5));
      this.cleanSinceBackoff = 0;
    }
  }

  /** Hand off any unconfirmed AND not-yet-sent publishes (and stop the pacer), so a reconnect can re-issue
   * them on the fresh transport. Without this a frame that was sent but rate-dropped, or paced-but-undrained
   * when the socket dropped, is lost, and the roster backstop then advances so it is never re-sent. */
  takePending(): EnvelopeMsg[] {
    if (this.publishTimer !== null) {
      clearTimeout(this.publishTimer);
      this.publishTimer = null;
    }
    if (this.retryTimer !== null) {
      clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }
    const pending = [...this.unconfirmed.values(), ...this.publishQueue.splice(0)]; // oldest first for replay
    this.unconfirmed.clear();
    return pending;
  }

  /** Acknowledge delivery so the bus can drop the blob. */
  ack(messageId: Uint8Array): void {
    this.socket.send(this.codec.encodeAck(messageId));
  }

  /** Send a conversation offer (gated handshake). */
  sendOffer(offer: OfferMsg): void {
    this.socket.send(this.codec.encodeOffer(offer));
  }

  /** Send acceptance of a peer's offer. */
  sendAccept(accept: AcceptMsg): void {
    this.socket.send(this.codec.encodeAccept(accept));
  }

  close(): void {
    if (this.publishTimer !== null) {
      clearTimeout(this.publishTimer);
      this.publishTimer = null;
    }
    if (this.retryTimer !== null) {
      clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }
    this.publishQueue.length = 0;
    this.unconfirmed.clear();
    this.socket.close();
  }

  private dispatch(bytes: Uint8Array): void {
    let frame: IncomingServerFrame;
    try {
      frame = this.codec.decodeServerFrame(bytes);
    } catch {
      this.handlers.onError(-1, 'undecodable server frame');
      return;
    }
    switch (frame.type) {
      case 'deliver':
        this.handlers.onDeliver(frame.envelope);
        return;
      case 'receipt':
        this.onDelivered(frame.messageId);
        this.handlers.onReceipt(frame.messageId);
        return;
      case 'offer':
        this.handlers.onOffer(frame.offer);
        return;
      case 'accept':
        this.handlers.onAccept(frame.accept);
        return;
      case 'error':
        if (frame.code === Transport.RATE_LIMIT_CODE) {
          this.onRateLimited(); // back off + retransmit the unconfirmed frames rather than losing them
        }
        this.handlers.onError(frame.code, frame.detail);
        return;
    }
  }
}
