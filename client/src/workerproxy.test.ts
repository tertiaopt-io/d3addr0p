import { describe, it, expect } from 'vitest';
import { WorkerController, type WorkerTransport } from './workerproxy.js';

interface Request {
  readonly id: number;
  readonly op: string;
  readonly args: readonly unknown[];
}

/** A fake worker transport: dispatches each request to `respond` and posts the reply back. */
class FakeTransport implements WorkerTransport {
  readonly posted: Request[] = [];
  private handler?: (m: unknown) => void;
  constructor(private readonly respond: (op: string, args: readonly unknown[]) => { ok: boolean; result?: unknown; error?: string }) {}
  post(message: unknown): void {
    const req = message as Request;
    this.posted.push(req);
    const reply = this.respond(req.op, req.args);
    queueMicrotask(() => this.handler?.({ id: req.id, ...reply }));
  }
  onMessage(handler: (m: unknown) => void): void {
    this.handler = handler;
  }
}

describe('WorkerController proxy', () => {
  it('round-trips unlock through the transport and resolves the result', async () => {
    const t = new FakeTransport((op) => (op === 'unlock' ? { ok: true, result: { ok: true } } : { ok: true }));
    const c = new WorkerController(t);
    expect(await c.unlock('alice', 'pass')).toEqual({ ok: true });
    expect(t.posted[0]?.op).toBe('unlock');
    expect(t.posted[0]?.args).toEqual(['alice', 'pass']);
  });

  it('sends the auth-secret KDF to the worker, so the ~64 MiB Argon2id never runs on the main thread', async () => {
    const key = new Uint8Array([1, 2, 3, 4]);
    const t = new FakeTransport((op) => (op === 'deriveAuthKey' ? { ok: true, result: key } : { ok: true }));
    const c = new WorkerController(t);
    const salt = new Uint8Array([9, 9]);
    expect(await c.deriveAuthKey('correct horse', salt)).toEqual(key);
    expect(t.posted[0]?.op).toBe('deriveAuthKey');
    expect(t.posted[0]?.args).toEqual(['correct horse', salt]);
  });

  it('resolves listChannels and openChannel results', async () => {
    const channels = [{ id: 'a', peer: 'A', fingerprint: 'x', status: 'secure', preview: '', unread: 0 }];
    const t = new FakeTransport((op) => {
      if (op === 'listChannels') {
        return { ok: true, result: channels };
      }
      if (op === 'openChannel') {
        return { ok: true, result: { secure: true, peer: 'A', fingerprint: null, log: [], compose: '' } };
      }
      return { ok: true };
    });
    const c = new WorkerController(t);
    expect(await c.listChannels()).toEqual(channels);
    expect((await c.openChannel('a')).peer).toBe('A');
  });

  it('rejects when the worker returns an error', async () => {
    const t = new FakeTransport(() => ({ ok: false, error: 'locked' }));
    const c = new WorkerController(t);
    await expect(c.listChannels()).rejects.toThrow('locked');
  });

  it('correlates concurrent calls by id', async () => {
    const t = new FakeTransport((op, args) => ({
      ok: true,
      result: `${op}:${typeof args[0] === 'string' ? args[0] : ''}`,
    }));
    const c = new WorkerController(t);
    const [a, b] = await Promise.all([c.openChannel('one'), c.openChannel('two')]);
    expect(a).toBe('openChannel:one');
    expect(b).toBe('openChannel:two');
  });

  // N-series passthroughs (identity, buddies, block list, presence/notify). Each must forward to its
  // matching worker op with the right args and resolve the worker's reply, or it silently no-ops on the
  // worker path (blank identity, empty buddy list, block does nothing, presence off).
  it('forwards identity ops with the right op name and args', async () => {
    const profile = { icon: null, bio: 'hi', away: { enabled: false, message: '', serverSide: false } };
    const peers = [{ key: 'k1', fingerprint: 'fp', icon: null, bio: '' }];
    const t = new FakeTransport((op) => {
      if (op === 'getIdentity') {
        return { ok: true, result: profile };
      }
      if (op === 'getPeerIdentities') {
        return { ok: true, result: peers };
      }
      return { ok: true };
    });
    const c = new WorkerController(t);
    expect(await c.getIdentity()).toEqual(profile);
    await c.setIdentity(profile);
    expect(await c.getPeerIdentities('conv1')).toEqual(peers);
    expect(t.posted.map((r) => r.op)).toEqual(['getIdentity', 'setIdentity', 'getPeerIdentities']);
    expect(t.posted[1]?.args).toEqual([profile]);
    expect(t.posted[2]?.args).toEqual(['conv1']);
  });

  it('forwards buddy-list ops (including the group) and resolves the updated list', async () => {
    const list = [{ username: 'bob', addedAt: 7, group: 'Family' }];
    const forwarded = new Set(['listBuddies', 'addBuddy', 'removeBuddy', 'setBuddyGroup']);
    const t = new FakeTransport((op) => (forwarded.has(op) ? { ok: true, result: list } : { ok: true }));
    const c = new WorkerController(t);
    expect(await c.listBuddies()).toEqual(list);
    expect(await c.addBuddy('bob', 'Family')).toEqual(list);
    expect(await c.setBuddyGroup('bob', 'Co-Workers')).toEqual(list);
    expect(await c.removeBuddy('bob')).toEqual(list);
    expect(t.posted.map((r) => r.op)).toEqual(['listBuddies', 'addBuddy', 'setBuddyGroup', 'removeBuddy']);
    expect(t.posted[1]?.args).toEqual(['bob', 'Family']);
    expect(t.posted[2]?.args).toEqual(['bob', 'Co-Workers']);
    expect(t.posted[3]?.args).toEqual(['bob']);
  });

  it('forwards group-list ops and resolves the updated group list', async () => {
    const groups = [{ name: 'Family' }];
    const forwarded = new Set(['listGroups', 'addGroup', 'deleteGroup']);
    const t = new FakeTransport((op) => (forwarded.has(op) ? { ok: true, result: groups } : { ok: true }));
    const c = new WorkerController(t);
    expect(await c.listGroups()).toEqual(groups);
    expect(await c.addGroup('Family')).toEqual(groups);
    expect(await c.deleteGroup('Family')).toEqual(groups);
    expect(t.posted.map((r) => r.op)).toEqual(['listGroups', 'addGroup', 'deleteGroup']);
    expect(t.posted[1]?.args).toEqual(['Family']);
    expect(t.posted[2]?.args).toEqual(['Family']);
  });

  it('forwards the buddy-info + conversation-tag ops with the right args', async () => {
    const peers = [{ key: 'aa', fingerprint: 'AA·BB·CC·DD', icon: null, bio: 'hi' }];
    const t = new FakeTransport((op) => (op === 'getBuddyInfo' ? { ok: true, result: peers } : { ok: true }));
    const c = new WorkerController(t);
    await c.tagConversationHandle('c1', 'raven');
    expect(await c.getBuddyInfo('raven')).toEqual(peers);
    expect(t.posted.map((r) => r.op)).toEqual(['tagConversationHandle', 'getBuddyInfo']);
    expect(t.posted[0]?.args).toEqual(['c1', 'raven']);
    expect(t.posted[1]?.args).toEqual(['raven']);
  });

  it('forwards block-list ops with the right args and resolves the result', async () => {
    const blocked = [{ key: 'kk', fingerprint: 'ff' }];
    const t = new FakeTransport((op) => (op === 'listBlocked' || op === 'unblock' ? { ok: true, result: blocked } : { ok: true }));
    const c = new WorkerController(t);
    await c.blockConversation('conv2');
    expect(await c.listBlocked()).toEqual(blocked);
    expect(await c.unblock('kk')).toEqual(blocked);
    expect(t.posted.map((r) => r.op)).toEqual(['blockConversation', 'listBlocked', 'unblock']);
    expect(t.posted[0]?.args).toEqual(['conv2']);
    expect(t.posted[2]?.args).toEqual(['kk']);
  });

  it('forwards revokeMessage with the conversation and message id', async () => {
    const model = { secure: true, peer: 'A', fingerprint: null, log: [], compose: '', conversationId: 'c1' };
    const t = new FakeTransport((op) => (op === 'revokeMessage' ? { ok: true, result: model } : { ok: true }));
    const c = new WorkerController(t);
    expect((await c.revokeMessage('c1', 'm1')).conversationId).toBe('c1');
    expect(t.posted[0]?.op).toBe('revokeMessage');
    expect(t.posted[0]?.args).toEqual(['c1', 'm1']);
  });

  it('forwards presence and notify toggles, threading the boolean through', async () => {
    const t = new FakeTransport((op) => (op === 'getPresenceEnabled' || op === 'getNotifyEnabled' ? { ok: true, result: true } : { ok: true }));
    const c = new WorkerController(t);
    expect(await c.getPresenceEnabled()).toBe(true);
    await c.setPresenceEnabled(false);
    expect(await c.getNotifyEnabled()).toBe(true);
    await c.setNotifyEnabled(false);
    expect(t.posted.map((r) => r.op)).toEqual(['getPresenceEnabled', 'setPresenceEnabled', 'getNotifyEnabled', 'setNotifyEnabled']);
    expect(t.posted[1]?.args).toEqual([false]);
    expect(t.posted[3]?.args).toEqual([false]);
  });
});
