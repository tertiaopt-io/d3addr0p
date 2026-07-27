import { describe, it, expect } from 'vitest';
import {
  CallSession,
  MAX_PENDING_ICE,
  type CallSignal,
  type GetUserMedia,
  type MediaStreamLike,
  type RtcMediaConnectionLike,
} from './callsession.js';

// A fake media + WebRTC pair. A shared World links the caller's and callee's connections so that once
// the callee answers, both sides fire ontrack and reach 'connected', mirroring a real call. The real
// getUserMedia/RTCPeerConnection paths run only in the browser; this proves the signaling state machine.
class FakeTrack {
  enabled = true;
  stopped = false;
  constructor(readonly kind: string) {}
  stop(): void {
    this.stopped = true;
  }
}

class FakeStream {
  constructor(readonly tracks: FakeTrack[]) {}
  getTracks(): readonly FakeTrack[] {
    return this.tracks;
  }
  getAudioTracks(): readonly FakeTrack[] {
    return this.tracks.filter((t) => t.kind === 'audio');
  }
  getVideoTracks(): readonly FakeTrack[] {
    return this.tracks.filter((t) => t.kind === 'video');
  }
}

class World {
  caller: FakePc | null = null;
  callee: FakePc | null = null;
}

class FakePc {
  onicecandidate: ((e: { candidate: unknown }) => void) | null = null;
  ontrack: ((e: { streams: readonly MediaStreamLike[] }) => void) | null = null;
  onconnectionstatechange: (() => void) | null = null;
  connectionState = 'new';
  stream: FakeStream | null = null;
  closed = false;
  constructor(
    private readonly world: World,
    private readonly role: 'caller' | 'callee',
  ) {
    if (role === 'caller') {
      world.caller = this;
    } else {
      world.callee = this;
    }
  }
  createOffer(): Promise<{ type: string; sdp: string }> {
    return Promise.resolve({ type: 'offer', sdp: 'x' });
  }
  createAnswer(): Promise<{ type: string; sdp: string }> {
    return Promise.resolve({ type: 'answer', sdp: 'x' });
  }
  setLocalDescription(d: { type: string }): Promise<void> {
    if (this.role === 'callee' && d.type === 'answer') {
      const caller = this.world.caller;
      const callee = this.world.callee;
      queueMicrotask(() => {
        if (caller !== null && callee !== null) {
          caller.connectionState = 'connected';
          callee.connectionState = 'connected';
          caller.ontrack?.({ streams: callee.stream !== null ? [callee.stream] : [] });
          callee.ontrack?.({ streams: caller.stream !== null ? [caller.stream] : [] });
          caller.onconnectionstatechange?.();
          callee.onconnectionstatechange?.();
        }
      });
    }
    return Promise.resolve();
  }
  private remoteSet = false;
  setRemoteDescription(): Promise<void> {
    this.remoteSet = true;
    return Promise.resolve();
  }
  // Enforce the real invariant: addIceCandidate before a remote description is set rejects. The old fake
  // resolved unconditionally, which hid the ICE-before-setRemoteDescription race.
  addIceCandidate(): Promise<void> {
    if (!this.remoteSet) {
      return Promise.reject(new Error('InvalidStateError: remote description is null'));
    }
    return Promise.resolve();
  }
  addTrack(_track: unknown, stream: FakeStream): { track: unknown } {
    this.stream = stream;
    return { track: _track };
  }
  close(): void {
    this.closed = true;
  }
}

async function flush(): Promise<void> {
  for (let i = 0; i < 12; i++) {
    await new Promise((r) => setTimeout(r, 0));
  }
}

const goodMedia: GetUserMedia = (c) =>
  Promise.resolve(
    new FakeStream(
      c.video ? [new FakeTrack('audio'), new FakeTrack('video')] : [new FakeTrack('audio')],
    ) as unknown as MediaStreamLike,
  );

interface Wire {
  caller?: CallSession;
  callee?: CallSession;
}

/** Build a connected caller/callee pair where the callee auto-accepts. Returns trackers for assertions. */
function makePair(opts: { autoAccept: boolean; media?: GetUserMedia }) {
  const world = new World();
  const media = opts.media ?? goodMedia;
  const wire: Wire = {};
  const states = { caller: [] as string[], callee: [] as string[] };
  const remote = { caller: false, callee: false };
  const local = { caller: null as MediaStreamLike | null, callee: null as MediaStreamLike | null };
  const errors = { caller: [] as string[], callee: [] as string[] };
  let incomingId: string | null = null;

  const caller = new CallSession(() => new FakePc(world, 'caller') as unknown as RtcMediaConnectionLike, media, {
    sendSignal: (s: CallSignal) => void wire.callee?.handleSignal(s),
    onIncoming: () => {},
    onState: (_id, st) => states.caller.push(st),
    onLocalStream: (_id, s) => {
      local.caller = s;
    },
    onRemoteStream: () => {
      remote.caller = true;
    },
    onError: (_id, m) => errors.caller.push(m),
  });
  const callee = new CallSession(() => new FakePc(world, 'callee') as unknown as RtcMediaConnectionLike, media, {
    sendSignal: (s: CallSignal) => void wire.caller?.handleSignal(s),
    onIncoming: (id) => {
      incomingId = id;
      if (opts.autoAccept) {
        void callee.accept(id);
      }
    },
    onState: (_id, st) => states.callee.push(st),
    onLocalStream: (_id, s) => {
      local.callee = s;
    },
    onRemoteStream: () => {
      remote.callee = true;
    },
    onError: (_id, m) => errors.callee.push(m),
  });
  wire.caller = caller;
  wire.callee = callee;
  return { caller, callee, states, remote, local, errors, incomingId: () => incomingId };
}

describe('CallSession (direct P2P audio/video)', () => {
  it('connects a video call end to end: both sides reach connected with the other’s stream', async () => {
    const p = makePair({ autoAccept: true });
    await p.caller.startCall('c1', true);
    await flush();
    expect(p.states.caller).toContain('connected');
    expect(p.states.callee).toContain('connected');
    expect(p.remote.caller).toBe(true);
    expect(p.remote.callee).toBe(true);
  });

  it('rings before any media: the callee is offered the call and only captures media on accept', async () => {
    const p = makePair({ autoAccept: false });
    await p.caller.startCall('c2', false);
    await flush();
    expect(p.states.callee).toContain('ringing');
    expect(p.local.callee).toBeNull(); // no mic/camera grabbed until accept
    expect(p.incomingId()).toBe('c2');
  });

  it('declining tells the caller the call ended', async () => {
    const world = makePair({ autoAccept: false });
    // wire a callee that declines instead of accepting
    await world.caller.startCall('c3', false);
    await flush();
    world.callee.decline('c3');
    await flush();
    expect(world.states.caller).toContain('ended');
  });

  it('hanging up ends the peer and stops local tracks', async () => {
    const p = makePair({ autoAccept: true });
    await p.caller.startCall('c4', true);
    await flush();
    p.caller.hangup('c4');
    await flush();
    expect(p.states.callee).toContain('ended');
    const tracks = (p.local.caller as unknown as FakeStream | null)?.getTracks() ?? [];
    expect(tracks.length).toBeGreaterThan(0);
    expect(tracks.every((t) => t.stopped)).toBe(true);
  });

  it('mute and camera toggles flip the local track enabled flags', async () => {
    const p = makePair({ autoAccept: true });
    await p.caller.startCall('c5', true);
    await flush();
    p.caller.setMicEnabled('c5', false);
    p.caller.setCameraEnabled('c5', false);
    const stream = p.local.caller as unknown as FakeStream;
    expect(stream.getAudioTracks().every((t) => !t.enabled)).toBe(true);
    expect(stream.getVideoTracks().every((t) => !t.enabled)).toBe(true);
  });

  it('reports an error and ends when the mic or camera cannot be opened', async () => {
    const denied: GetUserMedia = () => Promise.reject(new Error('NotAllowedError'));
    const p = makePair({ autoAccept: false, media: denied });
    await p.caller.startCall('c6', true);
    await flush();
    expect(p.errors.caller).toHaveLength(1);
    expect(p.states.caller).toContain('ended');
  });

  it('ignores a malformed or unknown call signal without throwing', async () => {
    const p = makePair({ autoAccept: false });
    await p.caller.handleSignal({ nope: true });
    await p.caller.handleSignal(null);
    await p.caller.handleSignal({ kind: 'call-answer', id: 'nope', sdp: { type: 'answer' } });
    expect(true).toBe(true);
  });

  it('buffers ICE that races setRemoteDescription in accept(), applying it after without ending the call', async () => {
    // setRemoteDescription is held open so an ICE candidate can be delivered while accept() is suspended
    // at it. With the remoteReady gate the candidate is buffered (not applied early, which would reject).
    let releaseSrd: () => void = () => {};
    let remoteSet = false;
    const appliedIce: unknown[] = [];
    const states: string[] = [];
    const pc = {
      createOffer: () => Promise.resolve({ type: 'offer', sdp: 'x' }),
      createAnswer: () => Promise.resolve({ type: 'answer', sdp: 'x' }),
      setLocalDescription: () => Promise.resolve(),
      setRemoteDescription: () =>
        new Promise<void>((res) => {
          releaseSrd = () => {
            remoteSet = true;
            res();
          };
        }),
      addIceCandidate: (c: unknown) => {
        if (!remoteSet) {
          return Promise.reject(new Error('InvalidStateError'));
        }
        appliedIce.push(c);
        return Promise.resolve();
      },
      addTrack: () => ({ track: null }),
      onicecandidate: null,
      ontrack: null,
      onconnectionstatechange: null,
      connectionState: 'new',
      close: () => {},
    };
    const cs = new CallSession(() => pc as unknown as RtcMediaConnectionLike, goodMedia, {
      sendSignal: () => {},
      onIncoming: () => {},
      onState: (_id, s) => states.push(s),
      onLocalStream: () => {},
      onRemoteStream: () => {},
      onError: () => {},
    });
    await cs.handleSignal({ kind: 'call-offer', id: 'c', video: false, sdp: { type: 'offer' } });
    const acceptP = cs.accept('c'); // captures media, then suspends at setRemoteDescription
    await flush();
    await cs.handleSignal({ kind: 'call-ice', id: 'c', candidate: { mid: 0 } }); // races SRD -> must buffer
    expect(states).not.toContain('ended');
    releaseSrd();
    await acceptP;
    await flush();
    expect(appliedIce).toEqual([{ mid: 0 }]); // applied only after the remote description was installed
    expect(states).not.toContain('ended');
  });

  it('stops freshly captured tracks if the call is torn down during the capture await (no mic/camera leak)', async () => {
    let releaseMedia: (s: MediaStreamLike) => void = () => {};
    const stream = new FakeStream([new FakeTrack('audio'), new FakeTrack('video')]);
    const media: GetUserMedia = () => new Promise<MediaStreamLike>((res) => (releaseMedia = res));
    const cs = new CallSession(() => new FakePc(new World(), 'callee') as unknown as RtcMediaConnectionLike, media, {
      sendSignal: () => {},
      onIncoming: (id) => {
        void cs.accept(id); // accept -> awaits the (held) permission prompt
      },
      onState: () => {},
      onLocalStream: () => {},
      onRemoteStream: () => {},
      onError: () => {},
    });
    await cs.handleSignal({ kind: 'call-offer', id: 'c', video: true, sdp: { type: 'offer' } });
    await flush();
    await cs.handleSignal({ kind: 'call-hangup', id: 'c' }); // caller hangs up during the permission prompt
    releaseMedia(stream as unknown as MediaStreamLike); // permission granted late
    await flush();
    expect(stream.getTracks().every((t) => t.stopped)).toBe(true); // captured tracks released, mic/camera freed
  });

  it('caps the pre-accept ICE buffer on calls so a flood cannot grow without bound', async () => {
    let remoteSet = false;
    const appliedIce: unknown[] = [];
    const pc = {
      createOffer: () => Promise.resolve({ type: 'offer', sdp: 'x' }),
      createAnswer: () => Promise.resolve({ type: 'answer', sdp: 'x' }),
      setLocalDescription: () => Promise.resolve(),
      setRemoteDescription: () => {
        remoteSet = true;
        return Promise.resolve();
      },
      addIceCandidate: (c: unknown) => {
        if (!remoteSet) {
          return Promise.reject(new Error('InvalidStateError'));
        }
        appliedIce.push(c);
        return Promise.resolve();
      },
      addTrack: () => ({ track: null }),
      onicecandidate: null,
      ontrack: null,
      onconnectionstatechange: null,
      connectionState: 'new',
      close: () => {},
    };
    const cs = new CallSession(() => pc as unknown as RtcMediaConnectionLike, goodMedia, {
      sendSignal: () => {},
      onIncoming: () => {},
      onState: () => {},
      onLocalStream: () => {},
      onRemoteStream: () => {},
      onError: () => {},
    });
    await cs.handleSignal({ kind: 'call-offer', id: 'c', video: false, sdp: { type: 'offer' } });
    for (let i = 0; i < MAX_PENDING_ICE + 50; i++) {
      await cs.handleSignal({ kind: 'call-ice', id: 'c', candidate: { i } }); // flood while merely ringing
    }
    await cs.accept('c');
    await flush();
    expect(appliedIce.length).toBe(MAX_PENDING_ICE); // excess dropped; buffer cannot grow unbounded
  });
});
