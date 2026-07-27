import { describe, it, expect } from 'vitest';
import { Handshake, HandshakeError } from './handshake.js';

const ALICE = 'a'.repeat(64);
const BOB = 'b'.repeat(64);
const MALLORY = 'c'.repeat(64);

describe('Handshake gate (ADR-009)', () => {
  it('forbids sending before the conversation is established', () => {
    const h = new Handshake();
    expect(h.canSendMessage()).toBe(false);
    expect(() => h.assertCanSend()).toThrow(HandshakeError);

    h.sendOffer('conv-1');
    expect(h.canSendMessage()).toBe(false);
    expect(() => h.assertCanSend()).toThrow(HandshakeError);
  });

  it('allows sending only after mutual accept (offerer side)', () => {
    const h = new Handshake();
    h.sendOffer('conv-1');
    h.receiveAccept(BOB);
    expect(h.canSendMessage()).toBe(true);
    expect(() => h.assertCanSend()).not.toThrow();
  });

  it('allows sending only after mutual accept (accepter side)', () => {
    const h = new Handshake();
    h.receiveOffer('conv-1', ALICE);
    expect(h.canSendMessage()).toBe(false);
    h.accept();
    expect(h.canSendMessage()).toBe(true);
  });

  it('a party that never accepted cannot reach established', () => {
    const h = new Handshake();
    h.receiveOffer('conv-1', ALICE);
    // No accept() called.
    expect(() => h.assertCanSend()).toThrow(HandshakeError);
  });

  it('blocks the conversation if an established peer key changes (§5.7)', () => {
    const h = new Handshake();
    h.sendOffer('conv-1');
    h.receiveAccept(BOB);
    expect(h.canSendMessage()).toBe(true);

    h.observePeerKey(MALLORY); // key substitution after establishment
    expect(h.canSendMessage()).toBe(false);
    expect(h.current().kind).toBe('blocked');
  });

  it('rejects out-of-order transitions', () => {
    const h = new Handshake();
    expect(() => h.accept()).toThrow(HandshakeError);
    expect(() => h.receiveAccept(BOB)).toThrow(HandshakeError);
  });
});
