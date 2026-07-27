/**
 * Gated mutual key-exchange-and-accept handshake (ADR-009, M1 slice 2).
 *
 * No message may be sent in a conversation until BOTH parties have exchanged KeyPackages and
 * each has explicitly accepted the other. `assertCanSend()` is the hard gate.
 *
 * HONEST LIMIT (ADR-009 residual 1): this build performs the exchange in-app only, with no
 * out-of-band verification. Acceptance is therefore trust-on-first-use. A hostile or compelled
 * server could substitute keys (MITM) and the accept step would rubber-stamp them. This module
 * does not defend against that; the duress/decoy/wipe controls and a future OOB-verification
 * step do. Do not present `accept()` as proof of a peer's identity.
 */

/** Hex-encoded Ed25519 signature public key. This is the opaque peer identity (no PII). */
export type PeerKey = string;

export type HandshakeState =
  | { readonly kind: 'idle' }
  | { readonly kind: 'offer-sent'; readonly conversationId: string }
  | { readonly kind: 'offer-received'; readonly conversationId: string; readonly theirKey: PeerKey }
  | { readonly kind: 'established'; readonly conversationId: string; readonly theirKey: PeerKey }
  | { readonly kind: 'blocked'; readonly conversationId: string; readonly reason: 'key-changed' };

export class HandshakeError extends Error {}

export class Handshake {
  private state: HandshakeState = { kind: 'idle' };

  current(): HandshakeState {
    return this.state;
  }

  /** We start a conversation by offering our KeyPackage. */
  sendOffer(conversationId: string): void {
    this.requireKind('idle', 'sendOffer');
    this.state = { kind: 'offer-sent', conversationId };
  }

  /** We received a peer's offer (relayed by the service; unverified). */
  receiveOffer(conversationId: string, theirKey: PeerKey): void {
    this.requireKind('idle', 'receiveOffer');
    this.state = { kind: 'offer-received', conversationId, theirKey };
  }

  /**
   * We accept a received offer. Trust-on-first-use: there is no verification argument because
   * this build has no out-of-band check (ADR-009).
   */
  accept(): void {
    if (this.state.kind !== 'offer-received') {
      throw new HandshakeError(`accept() invalid from state "${this.state.kind}"`);
    }
    this.state = {
      kind: 'established',
      conversationId: this.state.conversationId,
      theirKey: this.state.theirKey,
    };
  }

  /** The peer accepted our offer, returning their key. Establishes the conversation. */
  receiveAccept(theirKey: PeerKey): void {
    if (this.state.kind !== 'offer-sent') {
      throw new HandshakeError(`receiveAccept() invalid from state "${this.state.kind}"`);
    }
    this.state = { kind: 'established', conversationId: this.state.conversationId, theirKey };
  }

  /**
   * Observe the peer key seen on an incoming message. If an established peer's key ever
   * changes, block the conversation and require re-establishment (§5.7 key-change alert).
   */
  observePeerKey(key: PeerKey): void {
    if (this.state.kind === 'established' && key !== this.state.theirKey) {
      this.state = { kind: 'blocked', conversationId: this.state.conversationId, reason: 'key-changed' };
    }
  }

  /** The single hard gate: true only when both parties have accepted. */
  canSendMessage(): boolean {
    return this.state.kind === 'established';
  }

  /** Throws unless the conversation is established. Call before every send. */
  assertCanSend(): void {
    if (!this.canSendMessage()) {
      throw new HandshakeError(
        `cannot send: conversation is "${this.state.kind}", both parties must accept first`,
      );
    }
  }

  private requireKind(kind: HandshakeState['kind'], op: string): void {
    if (this.state.kind !== kind) {
      throw new HandshakeError(`${op}() invalid from state "${this.state.kind}"`);
    }
  }
}
