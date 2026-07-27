import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  Transport,
  type Socket,
  type WireCodec,
  type IncomingServerFrame,
  type TransportHandlers,
} from './transport.js';
import type { EnvelopeMsg, OfferMsg, AcceptMsg } from './session.js';

class FakeSocket implements Socket {
  sent: Uint8Array[] = [];
  closed = false;
  failSend = false; // when true, send() throws like a dropped WebSocket
  private msg?: (b: Uint8Array) => void;
  private onClosed?: () => void;
  send(bytes: Uint8Array): void {
    if (this.failSend) {
      throw new Error('connection closed');
    }
    this.sent.push(bytes);
  }
  close(): void {
    this.closed = true;
    this.onClosed?.();
  }
  onMessage(handler: (bytes: Uint8Array) => void): void {
    this.msg = handler;
  }
  onClose(handler: () => void): void {
    this.onClosed = handler;
  }
  deliver(bytes: Uint8Array): void {
    this.msg?.(bytes);
  }
}

/** Fake codec: records outbound calls and round-trips inbound frames via a registry, so the
 * Transport's routing is tested without a real protobuf codec. */
class FakeCodec implements WireCodec {
  outbound: { op: string; arg: unknown }[] = [];
  private frames = new Map<number, IncomingServerFrame>();
  private seq = 0;
  encodeSubscribe(routingKey: string, consumerId: string): Uint8Array {
    this.outbound.push({ op: 'subscribe', arg: { routingKey, consumerId } });
    return new Uint8Array([0]);
  }
  encodePublish(envelope: EnvelopeMsg): Uint8Array {
    this.outbound.push({ op: 'publish', arg: envelope });
    return new Uint8Array([1]);
  }
  encodeAck(messageId: Uint8Array): Uint8Array {
    this.outbound.push({ op: 'ack', arg: messageId });
    return new Uint8Array([2]);
  }
  encodeOffer(offer: OfferMsg): Uint8Array {
    this.outbound.push({ op: 'offer', arg: offer });
    return new Uint8Array([3]);
  }
  encodeAccept(accept: AcceptMsg): Uint8Array {
    this.outbound.push({ op: 'accept', arg: accept });
    return new Uint8Array([4]);
  }
  /** Register an inbound frame; returns the bytes that decode back to it. */
  inboundBytes(frame: IncomingServerFrame): Uint8Array {
    const id = this.seq++;
    this.frames.set(id, frame);
    return new Uint8Array([255, id]);
  }
  decodeServerFrame(bytes: Uint8Array): IncomingServerFrame {
    if (bytes[0] === 255) {
      const f = this.frames.get(bytes[1] ?? -1);
      if (f !== undefined) {
        return f;
      }
    }
    throw new Error('undecodable');
  }
}

class RecordingHandlers implements TransportHandlers {
  delivered: EnvelopeMsg[] = [];
  receipts: Uint8Array[] = [];
  offers: OfferMsg[] = [];
  accepts: AcceptMsg[] = [];
  errors: { code: number; detail: string }[] = [];
  closed = 0;
  onDeliver(e: EnvelopeMsg): void {
    this.delivered.push(e);
  }
  onReceipt(id: Uint8Array): void {
    this.receipts.push(id);
  }
  onOffer(o: OfferMsg): void {
    this.offers.push(o);
  }
  onAccept(a: AcceptMsg): void {
    this.accepts.push(a);
  }
  onError(code: number, detail: string): void {
    this.errors.push({ code, detail });
  }
  onClose(): void {
    this.closed++;
  }
}

const ENV: EnvelopeMsg = {
  messageId: new Uint8Array([1, 2]),
  routingKey: 'mailbox-bob',
  payload: new Uint8Array([0xca, 0xfe]),
  ttlSeconds: 60,
};

let socket: FakeSocket;
let codec: FakeCodec;
let handlers: RecordingHandlers;
let transport: Transport;

beforeEach(() => {
  socket = new FakeSocket();
  codec = new FakeCodec();
  handlers = new RecordingHandlers();
  transport = new Transport(socket, codec, handlers);
});

describe('Transport (M3)', () => {
  it('encodes and sends outbound frames', () => {
    transport.subscribe('mailbox-bob');
    transport.publish(ENV);
    transport.ack(new Uint8Array([1, 2]));
    expect(codec.outbound.map((o) => o.op)).toEqual(['subscribe', 'publish', 'ack']);
    expect(socket.sent).toHaveLength(3);
  });

  it('every subscribe carries the consumer id once set (the per-device delivery cursor)', () => {
    transport.subscribe('mailbox-early'); // before the id is known: a legacy (empty-id) subscribe
    transport.setConsumerIdResolver((subject) => 'tag-' + subject);
    transport.subscribe('mailbox-bob');
    transport.subscribe('gmbox-1');
    const subs = codec.outbound.filter((o) => o.op === 'subscribe').map((o) => o.arg);
    expect(subs).toEqual([
      { routingKey: 'mailbox-early', consumerId: '' }, // before a resolver is set: legacy empty id
      { routingKey: 'mailbox-bob', consumerId: 'tag-mailbox-bob' }, // per-mailbox tag from the resolver
      { routingKey: 'gmbox-1', consumerId: 'tag-gmbox-1' },
    ]);
  });

  it('paces a publish burst so it never trips gateway flood control (first immediate, rest spaced)', () => {
    vi.useFakeTimers();
    try {
      for (let i = 0; i < 5; i++) {
        transport.publish(ENV);
      }
      expect(socket.sent).toHaveLength(1); // the first goes out at once; the other four are queued
      vi.advanceTimersByTime(55);
      expect(socket.sent).toHaveLength(2);
      vi.advanceTimersByTime(55 * 3);
      expect(socket.sent).toHaveLength(5); // all drained, one per ~55ms
      vi.advanceTimersByTime(1000);
      expect(socket.sent).toHaveLength(5); // queue empty: no lingering timer keeps sending
    } finally {
      vi.useRealTimers();
    }
  });

  it('close() drops a queued publish burst and stops the pacing timer', () => {
    vi.useFakeTimers();
    try {
      for (let i = 0; i < 4; i++) {
        transport.publish(ENV);
      }
      expect(socket.sent).toHaveLength(1); // one sent, three queued behind the pacer
      transport.close();
      vi.advanceTimersByTime(1000);
      expect(socket.sent).toHaveLength(1); // the queued three were dropped; no late sends after close
    } finally {
      vi.useRealTimers();
    }
  });

  it('a socket drop mid-burst never throws uncaught and preserves the unsent frames for takePending', () => {
    vi.useFakeTimers();
    try {
      for (let i = 0; i < 4; i++) {
        transport.publish(ENV);
      }
      expect(socket.sent).toHaveLength(1); // first sent, three queued
      socket.failSend = true; // the socket drops
      expect(() => vi.advanceTimersByTime(55)).not.toThrow(); // the paced send fails quietly, no uncaught throw
      expect(socket.sent).toHaveLength(1); // nothing more went to the dead socket
      expect(() => vi.advanceTimersByTime(1000)).not.toThrow(); // and the pacer stopped, not looping on the dead socket
      // All four frames are preserved for replay on the fresh transport: the one sent-but-unreceipted frame
      // (it may have been rate-dropped) plus the three never-sent ones.
      expect(transport.takePending()).toHaveLength(4);
    } finally {
      vi.useRealTimers();
    }
  });

  it('retransmits unconfirmed frames on a gateway RATE_LIMIT, but not ones a receipt already confirmed', () => {
    vi.useFakeTimers();
    try {
      const e = (id: number): EnvelopeMsg => ({ messageId: new Uint8Array([id]), routingKey: 'm', payload: new Uint8Array([0]), ttlSeconds: 60 });
      transport.publish(e(1)); // sent immediately, now unconfirmed
      vi.advanceTimersByTime(55);
      transport.publish(e(2)); // sent on the next drain, now unconfirmed
      vi.advanceTimersByTime(55);
      expect(socket.sent).toHaveLength(2);
      // A receipt confirms frame 1: it must drop out of the retry set.
      socket.deliver(codec.inboundBytes({ type: 'receipt', messageId: new Uint8Array([1]) }));
      expect(handlers.receipts).toHaveLength(1); // the receipt still reaches the app layer
      // The gateway rate-limits (the error does not say which frame): retransmit only the still-unconfirmed
      // frame 2, so the rate-dropped frame is recovered instead of silently lost.
      socket.deliver(codec.inboundBytes({ type: 'error', code: 3, detail: 'sending too fast; slow down' }));
      vi.advanceTimersByTime(2000);
      expect(socket.sent).toHaveLength(3); // e1, e2, then e2 retransmitted; e1 was NOT resent (receipted)
    } finally {
      vi.useRealTimers();
    }
  });

  it('dispatches an inbound delivery to onDeliver with the envelope', () => {
    socket.deliver(codec.inboundBytes({ type: 'deliver', envelope: ENV }));
    expect(handlers.delivered).toEqual([ENV]);
  });

  it('dispatches receipts, offers, accepts, and errors to the right handler', () => {
    const offer: OfferMsg = { fromSignatureKey: new Uint8Array([1]), keyPackage: new Uint8Array([2]), conversationId: 'c', toRoutingKey: 'r' };
    const accept: AcceptMsg = { fromSignatureKey: new Uint8Array([3]), keyPackage: new Uint8Array([4]), conversationId: 'c', mlsWelcome: new Uint8Array([5]), toRoutingKey: 'r' };
    socket.deliver(codec.inboundBytes({ type: 'receipt', messageId: new Uint8Array([7]) }));
    socket.deliver(codec.inboundBytes({ type: 'offer', offer }));
    socket.deliver(codec.inboundBytes({ type: 'accept', accept }));
    socket.deliver(codec.inboundBytes({ type: 'error', code: 2, detail: 'too large' }));
    expect(handlers.receipts).toEqual([new Uint8Array([7])]);
    expect(handlers.offers).toEqual([offer]);
    expect(handlers.accepts).toEqual([accept]);
    expect(handlers.errors).toEqual([{ code: 2, detail: 'too large' }]);
  });

  it('reports an undecodable frame as an error rather than throwing', () => {
    socket.deliver(new Uint8Array([99])); // not a registered frame
    expect(handlers.errors).toEqual([{ code: -1, detail: 'undecodable server frame' }]);
  });

  it('notifies onClose when the socket closes', () => {
    transport.close();
    expect(socket.closed).toBe(true);
    expect(handlers.closed).toBe(1);
  });
});
