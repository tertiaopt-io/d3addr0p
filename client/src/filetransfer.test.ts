import { describe, it, expect } from 'vitest';
import {
  FileTransfer,
  BlobSink,
  MAX_PENDING_ICE,
  type FileSink,
  type FileSource,
  type RtcConnectionLike,
} from './filetransfer.js';

// A fake WebRTC pair: a shared World lets the sender's data channel link to a channel the receiver
// gets via ondatachannel once the answer is set. The real MLS/WebRTC paths are exercised in the
// browser; this proves the handshake sequence + chunked streaming + reassembly of FileTransfer.
class FakeChannel {
  binaryType = '';
  onopen: (() => void) | null = null;
  onmessage: ((e: { data: unknown }) => void) | null = null;
  onclose: (() => void) | null = null;
  bufferedAmount = 0;
  peer: FakeChannel | null = null;
  send(data: ArrayBuffer | string): void {
    const peer = this.peer;
    if (peer !== null) {
      queueMicrotask(() => peer.onmessage?.({ data }));
    }
  }
  close(): void {
    this.onclose?.();
  }
}

class World {
  senderCh: FakeChannel | null = null;
}

class FakePc {
  onicecandidate: ((e: { candidate: unknown }) => void) | null = null;
  ondatachannel: ((e: { channel: FakeChannel }) => void) | null = null;
  constructor(
    private readonly world: World,
    private readonly role: 'send' | 'recv',
  ) {}
  createDataChannel(): FakeChannel {
    const ch = new FakeChannel();
    this.world.senderCh = ch;
    return ch;
  }
  createOffer(): Promise<{ type: string; sdp: string }> {
    return Promise.resolve({ type: 'offer', sdp: 'x' });
  }
  createAnswer(): Promise<{ type: string; sdp: string }> {
    return Promise.resolve({ type: 'answer', sdp: 'x' });
  }
  private remoteSet = false;
  setRemoteDescription(): Promise<void> {
    this.remoteSet = true;
    return Promise.resolve();
  }
  setLocalDescription(d: { type: string }): Promise<void> {
    if (this.role === 'recv' && d.type === 'answer') {
      const recvCh = new FakeChannel();
      const sendCh = this.world.senderCh;
      if (sendCh !== null) {
        recvCh.peer = sendCh;
        sendCh.peer = recvCh;
        queueMicrotask(() => {
          this.ondatachannel?.({ channel: recvCh });
          sendCh.onopen?.();
        });
      }
    }
    return Promise.resolve();
  }
  // Enforce the real RTCPeerConnection invariant: addIceCandidate before a remote description is set
  // rejects with InvalidStateError. The old fake returned resolve() unconditionally, hiding the race.
  addIceCandidate(): Promise<void> {
    if (!this.remoteSet) {
      return Promise.reject(new Error('InvalidStateError: remote description is null'));
    }
    return Promise.resolve();
  }
  close(): void {}
}

async function flush(): Promise<void> {
  for (let i = 0; i < 12; i++) {
    await new Promise((r) => setTimeout(r, 0));
  }
}

/** A FileSource over an in-memory array, read in slices like a real File. */
function arraySource(bytes: Uint8Array): FileSource {
  return { size: bytes.length, slice: (s, e) => Promise.resolve(bytes.subarray(s, e)) };
}

/**
 * A receiver-side fake connection that fires ondatachannel with the given channel once the answer is
 * set, records applied ICE candidates, and (like a real pc) rejects addIceCandidate before the remote
 * description is installed. Lets a test drive the received data channel and the ICE ordering directly.
 */
function recvPc(channel: FakeChannel, appliedIce: unknown[]): RtcConnectionLike {
  let odc: ((e: { channel: FakeChannel }) => void) | null = null;
  let remoteSet = false;
  return {
    createDataChannel: () => new FakeChannel(),
    createOffer: () => Promise.resolve({ type: 'offer', sdp: 'x' }),
    createAnswer: () => Promise.resolve({ type: 'answer', sdp: 'x' }),
    setLocalDescription: (d: { type: string }) => {
      if (d.type === 'answer') {
        queueMicrotask(() => odc?.({ channel }));
      }
      return Promise.resolve();
    },
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
    onicecandidate: null,
    set ondatachannel(h: ((e: { channel: FakeChannel }) => void) | null) {
      odc = h;
    },
    close: () => {},
  } as unknown as RtcConnectionLike;
}

/** A sink that records every chunk so a test can check byte-exact reassembly. */
class RecordingSink implements FileSink {
  readonly chunks: Uint8Array[] = [];
  closed = false;
  write(chunk: Uint8Array): void {
    this.chunks.push(chunk.slice());
  }
  close(): null {
    this.closed = true;
    return null;
  }
  bytes(): Uint8Array {
    const total = this.chunks.reduce((n, c) => n + c.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const c of this.chunks) {
      out.set(c, off);
      off += c.length;
    }
    return out;
  }
}

describe('FileTransfer (direct P2P, streaming)', () => {
  it('streams a multi-chunk file end to end and reassembles it exactly', async () => {
    const world = new World();
    const sink = new RecordingSink();
    const completed: string[] = [];
    const peers: { sender?: FileTransfer; receiver?: FileTransfer } = {};
    const senderFT = new FileTransfer(() => new FakePc(world, 'send') as unknown as RtcConnectionLike, {
      sendSignal: (s) => {
        void peers.receiver?.handleSignal(s);
      },
      onProgress: () => {},
      onIncoming: () => {},
      onComplete: () => {},
      onError: () => {},
    });
    const receiverFT = new FileTransfer(() => new FakePc(world, 'recv') as unknown as RtcConnectionLike, {
      sendSignal: (s) => {
        void peers.sender?.handleSignal(s);
      },
      onProgress: () => {},
      // Accept every incoming file into the recording sink (the host's accept/decline decision).
      onIncoming: (id) => {
        void receiverFT.accept(id, sink);
      },
      onComplete: (_id, name) => {
        completed.push(name);
      },
      onError: () => {},
    });
    peers.sender = senderFT;
    peers.receiver = receiverFT;

    const data = new Uint8Array(40 * 1024).map((_, i) => (i * 7) & 0xff); // spans several 16KB chunks
    await senderFT.sendFile('t1', 'photo.png', arraySource(data));
    await flush();

    expect(completed).toEqual(['photo.png']);
    expect(sink.closed).toBe(true);
    expect([...sink.bytes()]).toEqual([...data]); // byte-exact reassembly
  });

  it('lets the receiver decline an offer, and the sender hears about it', async () => {
    const errors: string[] = [];
    const peers: { sender?: FileTransfer; receiver?: FileTransfer } = {};
    const senderFT = new FileTransfer(() => new FakePc(new World(), 'send') as unknown as RtcConnectionLike, {
      sendSignal: (s) => {
        void peers.receiver?.handleSignal(s);
      },
      onProgress: () => {},
      onIncoming: () => {},
      onComplete: () => {},
      onError: (_id, m) => errors.push(m),
    });
    const receiverFT = new FileTransfer(() => new FakePc(new World(), 'recv') as unknown as RtcConnectionLike, {
      sendSignal: (s) => {
        void peers.sender?.handleSignal(s);
      },
      onProgress: () => {},
      onIncoming: (id) => {
        receiverFT.decline(id);
      },
      onComplete: () => {},
      onError: () => {},
    });
    peers.sender = senderFT;
    peers.receiver = receiverFT;

    await senderFT.sendFile('t2', 'doc.pdf', arraySource(new Uint8Array(1024)));
    await flush();

    expect(errors).toHaveLength(1);
  });

  it('announces an incoming file with its name and size before any bytes flow', async () => {
    const announced: Array<{ name: string; size: number }> = [];
    const ft = new FileTransfer(() => new FakePc(new World(), 'recv') as unknown as RtcConnectionLike, {
      sendSignal: () => {},
      onProgress: () => {},
      onIncoming: (_id, name, size) => announced.push({ name, size }),
      onComplete: () => {},
      onError: () => {},
    });
    await ft.handleSignal({ kind: 'offer', id: 'inc', name: 'clip.mov', size: 9_000_000, sdp: { type: 'offer' } });
    expect(announced).toEqual([{ name: 'clip.mov', size: 9_000_000 }]);
  });

  it('ignores a malformed or unknown signal without throwing', async () => {
    const ft = new FileTransfer(() => new FakePc(new World(), 'recv') as unknown as RtcConnectionLike, {
      sendSignal: () => {},
      onProgress: () => {},
      onIncoming: () => {},
      onComplete: () => {},
      onError: () => {},
    });
    await ft.handleSignal({ nope: true });
    await ft.handleSignal(null);
    await ft.handleSignal({ kind: 'answer', id: 'unknown', sdp: { type: 'answer' } }); // no such transfer
    expect(true).toBe(true);
  });

  it('BlobSink reassembles written chunks into a single Blob', () => {
    const sink = new BlobSink();
    sink.write(new Uint8Array([1, 2, 3]));
    sink.write(new Uint8Array([4, 5]));
    const blob = sink.close();
    expect(blob.size).toBe(5);
  });

  it('buffers ICE that races setRemoteDescription in accept(), then applies it without aborting', async () => {
    // A pc whose setRemoteDescription is held open, so we can deliver an ICE candidate while accept() is
    // suspended at it. The candidate must be buffered (not applied early, which the fake would reject).
    let releaseSrd: () => void = () => {};
    let remoteSet = false;
    const appliedIce: unknown[] = [];
    const errors: string[] = [];
    const pc = {
      createDataChannel: () => new FakeChannel(),
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
      onicecandidate: null,
      ondatachannel: null,
      close: () => {},
    };
    const ft = new FileTransfer(() => pc as unknown as RtcConnectionLike, {
      sendSignal: () => {},
      onProgress: () => {},
      onIncoming: () => {},
      onComplete: () => {},
      onError: (_id, m) => errors.push(m),
    });
    await ft.handleSignal({ kind: 'offer', id: 'r', name: 'f', size: 100, sdp: { type: 'offer' } });
    const acceptP = ft.accept('r', new RecordingSink()); // suspends at setRemoteDescription
    await Promise.resolve();
    await ft.handleSignal({ kind: 'ice', id: 'r', candidate: { mid: 0 } }); // races SRD -> must buffer
    expect(errors).toHaveLength(0); // not applied early (early apply would reject -> 'transfer setup failed')
    releaseSrd();
    await acceptP;
    await flush();
    expect(appliedIce).toEqual([{ mid: 0 }]); // applied only after the remote description was installed
    expect(errors).toHaveLength(0);
  });

  it('fails the transfer when the sender streams more bytes than the announced size', async () => {
    const channel = new FakeChannel();
    const errors: string[] = [];
    let completed = false;
    const ft = new FileTransfer(() => recvPc(channel, []), {
      sendSignal: () => {},
      onProgress: () => {},
      onIncoming: () => {},
      onComplete: () => {
        completed = true;
      },
      onError: (_id, m) => errors.push(m),
    });
    await ft.handleSignal({ kind: 'offer', id: 'x', name: 'note.txt', size: 10, sdp: { type: 'offer' } });
    await ft.accept('x', new RecordingSink());
    await flush(); // ondatachannel fires -> bindReceive wires channel.onmessage
    channel.onmessage?.({ data: new Uint8Array(16).buffer }); // 16 bytes against an announced 10
    await flush();
    expect(errors.some((e) => /exceeded the announced file size/.test(e))).toBe(true);
    expect(completed).toBe(false);
  });

  it('caps the pre-accept ICE buffer so a flood cannot grow without bound', async () => {
    const channel = new FakeChannel();
    const appliedIce: unknown[] = [];
    const ft = new FileTransfer(() => recvPc(channel, appliedIce), {
      sendSignal: () => {},
      onProgress: () => {},
      onIncoming: () => {},
      onComplete: () => {},
      onError: () => {},
    });
    await ft.handleSignal({ kind: 'offer', id: 'x', name: 'f', size: 1000, sdp: { type: 'offer' } });
    for (let i = 0; i < MAX_PENDING_ICE + 50; i++) {
      await ft.handleSignal({ kind: 'ice', id: 'x', candidate: { i } }); // flood while merely offered
    }
    await ft.accept('x', new RecordingSink());
    await flush();
    // Only the capped number was buffered; the excess was dropped, so a flood cannot grow unbounded.
    expect(appliedIce.length).toBe(MAX_PENDING_ICE);
  });
});
