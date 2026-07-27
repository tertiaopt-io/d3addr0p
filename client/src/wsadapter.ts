/**
 * Browser WebSocket + protobuf adapter (M3). The irreducible glue under the tested Transport:
 * a real WebSocket and a real protobuf codec over the generated wire types. It is excluded from
 * the typecheck/lint gate because it imports the codegen'd ts-proto module (which is not strict-
 * gate-clean and is regenerated, not committed). Keep this file thin; the routing logic it feeds
 * is unit-tested in transport.ts.
 */

import { ClientFrame, ServerFrame } from './wire/deaddrop/v1/deaddrop.js';
import { Transport, type Socket, type WireCodec, type IncomingServerFrame, type TransportHandlers } from './transport.js';
import type { EnvelopeMsg, OfferMsg, AcceptMsg } from './session.js';

/** A browser WebSocket that buffers sends until the connection is open. Once the socket CLOSES,
 * send throws instead of silently discarding: a WebSocket never reopens, and the spec makes
 * ws.send on a closed socket a silent no-op, which read as false success upstream (a revoke
 * "sent" on a dead link erased the local copy while no recipient ever saw the command). */
export class BrowserSocket implements Socket {
  private readonly ws: WebSocket;
  private readonly backlog: Uint8Array[] = [];
  private open = false;
  private closed = false;
  private msgHandler?: (bytes: Uint8Array) => void;
  private closeHandler?: () => void;

  constructor(url: string) {
    this.ws = new WebSocket(url);
    this.ws.binaryType = 'arraybuffer';
    this.ws.onopen = () => {
      this.open = true;
      for (const b of this.backlog) {
        this.ws.send(b);
      }
      this.backlog.length = 0;
    };
    this.ws.onmessage = (ev: MessageEvent) => {
      this.msgHandler?.(new Uint8Array(ev.data as ArrayBuffer));
    };
    this.ws.onclose = () => {
      this.open = false;
      this.closed = true;
      this.backlog.length = 0; // a closed socket never opens again; queued bytes can never flush
      this.closeHandler?.();
    };
  }

  send(bytes: Uint8Array): void {
    if (this.closed) {
      throw new Error('connection closed');
    }
    if (this.open) {
      this.ws.send(bytes);
    } else {
      this.backlog.push(bytes);
    }
  }
  close(): void {
    this.ws.close();
  }
  onMessage(handler: (bytes: Uint8Array) => void): void {
    this.msgHandler = handler;
  }
  onClose(handler: () => void): void {
    this.closeHandler = handler;
  }
}

/** Protobuf codec over the generated ClientFrame/ServerFrame. */
export class ProtobufCodec implements WireCodec {
  encodeSubscribe(routingKey: string, consumerId: string): Uint8Array {
    return ClientFrame.encode(ClientFrame.fromPartial({ subscribe: { routingKey, consumerId } })).finish();
  }
  encodePublish(e: EnvelopeMsg): Uint8Array {
    return ClientFrame.encode(
      ClientFrame.fromPartial({
        publish: { messageId: e.messageId, routingKey: e.routingKey, payload: e.payload, ttlSeconds: e.ttlSeconds },
      }),
    ).finish();
  }
  encodeAck(messageId: Uint8Array): Uint8Array {
    return ClientFrame.encode(ClientFrame.fromPartial({ ack: { messageId } })).finish();
  }
  encodeOffer(o: OfferMsg): Uint8Array {
    return ClientFrame.encode(
      ClientFrame.fromPartial({
        sendOffer: { fromSignatureKey: o.fromSignatureKey, keyPackage: o.keyPackage, conversationId: o.conversationId, toRoutingKey: o.toRoutingKey },
      }),
    ).finish();
  }
  encodeAccept(a: AcceptMsg): Uint8Array {
    return ClientFrame.encode(
      ClientFrame.fromPartial({
        sendAccept: {
          fromSignatureKey: a.fromSignatureKey,
          keyPackage: a.keyPackage,
          conversationId: a.conversationId,
          mlsWelcome: a.mlsWelcome,
          toRoutingKey: a.toRoutingKey,
        },
      }),
    ).finish();
  }
  decodeServerFrame(bytes: Uint8Array): IncomingServerFrame {
    const f = ServerFrame.decode(bytes);
    if (f.deliver) {
      return {
        type: 'deliver',
        envelope: { messageId: f.deliver.messageId, routingKey: f.deliver.routingKey, payload: f.deliver.payload, ttlSeconds: f.deliver.ttlSeconds },
      };
    }
    if (f.receipt) {
      return { type: 'receipt', messageId: f.receipt.messageId };
    }
    if (f.deliverOffer) {
      return {
        type: 'offer',
        offer: { fromSignatureKey: f.deliverOffer.fromSignatureKey, keyPackage: f.deliverOffer.keyPackage, conversationId: f.deliverOffer.conversationId, toRoutingKey: f.deliverOffer.toRoutingKey },
      };
    }
    if (f.deliverAccept) {
      return {
        type: 'accept',
        accept: {
          fromSignatureKey: f.deliverAccept.fromSignatureKey,
          keyPackage: f.deliverAccept.keyPackage,
          conversationId: f.deliverAccept.conversationId,
          mlsWelcome: f.deliverAccept.mlsWelcome,
          toRoutingKey: f.deliverAccept.toRoutingKey,
        },
      };
    }
    if (f.error) {
      return { type: 'error', code: f.error.code, detail: f.error.detail };
    }
    throw new Error('empty server frame');
  }
}

/** Connect to the gateway and wire a Transport. The url is the wss endpoint (Apache proxies it
 * to the loopback gateway). */
export function connect(url: string, handlers: TransportHandlers): Transport {
  return new Transport(new BrowserSocket(url), new ProtobufCodec(), handlers);
}
