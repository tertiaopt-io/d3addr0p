/**
 * Direct peer-to-peer file transfer over WebRTC (N7, streaming in P1).
 *
 * The SIGNALING (SDP offer/answer + ICE candidates) rides the existing end-to-end MLS channel as
 * CONTROL_FILE control frames; the FILE BYTES travel peer-to-peer over a WebRTC data channel and NEVER
 * pass through the server. HONEST LIMITS (see honest-limits): a direct connection lets each peer learn
 * the other's real IP address, the one thing sealed sender hides, and it can fail to connect behind a
 * strict NAT because there is no relay.
 *
 * There is NO size cap. To make that safe, the transfer streams: the sender reads the file in slices on
 * demand (it never holds the whole file in memory) and honours data-channel backpressure, and the
 * receiver writes each chunk to an injected sink, which the host points at a save-to-disk stream when
 * the browser supports it, or a Blob otherwise. An incoming file is announced (onIncoming) and only
 * begins once the host calls accept() with a sink, so the user consents and a large file cannot be
 * pushed into memory without the receiver choosing where it lands.
 *
 * The WebRTC primitives are INJECTED (RtcFactory) so this module stays browser-agnostic and is unit-
 * tested with fakes; production wires the real RTCPeerConnection in boot.js. Nothing here touches the
 * network directly or holds key material.
 */

/** A minimal WebRTC SDP description (RTCSessionDescriptionInit-shaped). */
export interface RtcSdp {
  readonly type: string;
  readonly sdp?: string;
}

/** The minimal data-channel surface we use (RTCDataChannel-shaped). */
export interface RtcChannelLike {
  binaryType: string;
  onopen: (() => void) | null;
  onmessage: ((ev: { data: unknown }) => void) | null;
  onclose: (() => void) | null;
  readonly bufferedAmount: number;
  send(data: ArrayBuffer): void;
  send(data: string): void;
  close(): void;
}

/** The minimal RTCPeerConnection surface we use, injected so this module is testable with a fake. */
export interface RtcConnectionLike {
  createDataChannel(label: string): RtcChannelLike;
  createOffer(): Promise<RtcSdp>;
  createAnswer(): Promise<RtcSdp>;
  setLocalDescription(desc: RtcSdp): Promise<void>;
  setRemoteDescription(desc: RtcSdp): Promise<void>;
  addIceCandidate(candidate: unknown): Promise<void>;
  onicecandidate: ((ev: { candidate: unknown }) => void) | null;
  ondatachannel: ((ev: { channel: RtcChannelLike }) => void) | null;
  close(): void;
}

export type RtcFactory = () => RtcConnectionLike;

/** A file-transfer signal carried inside one CONTROL_FILE frame (the JSON payload). */
export type FileSignal =
  | { readonly kind: 'offer'; readonly id: string; readonly name: string; readonly size: number; readonly sdp: RtcSdp }
  | { readonly kind: 'answer'; readonly id: string; readonly sdp: RtcSdp }
  | { readonly kind: 'ice'; readonly id: string; readonly candidate: unknown }
  | { readonly kind: 'decline'; readonly id: string };

/**
 * The source the sender reads from, one slice at a time, so an arbitrarily large file is never loaded
 * into memory whole. A File satisfies this via file.slice(start, end).arrayBuffer().
 */
export interface FileSource {
  readonly size: number;
  slice(start: number, end: number): Promise<Uint8Array>;
}

/**
 * Where a received file is written. The host supplies a save-to-disk stream when the browser supports
 * it (then close() returns null because the file is already on disk), or a Blob accumulator (then
 * close() returns the Blob for the host to offer as a download).
 */
export interface FileSink {
  write(chunk: Uint8Array): void | Promise<void>;
  close(): (Blob | null) | Promise<Blob | null>;
}

/** Side-effects the transfer needs from its host (wired to the controller / groupchannel). */
export interface TransferEvents {
  /** Emit a signal to the peer over the E2E channel (the only thing that touches the server). */
  sendSignal(signal: FileSignal): void;
  /** Bytes transferred so far for a transfer, for a progress bar. */
  onProgress(id: string, done: number, total: number): void;
  /** A peer is offering a file. The host shows accept/decline UI, then calls accept(id, sink) or decline(id). */
  onIncoming(id: string, name: string, size: number): void;
  /** A fully received file is ready: blob is the Blob to download, or null if it was streamed to disk. */
  onComplete(id: string, name: string, blob: Blob | null): void;
  /** A transfer failed or was declined. */
  onError(id: string, message: string): void;
}

const CHUNK_SIZE = 16 * 1024;
const DONE_MARKER = 'done';
/** Pause sending when the channel has this many bytes buffered, and resume once it drains below LOW. */
const BACKPRESSURE_HIGH = 8 * 1024 * 1024;
const BACKPRESSURE_LOW = 1 * 1024 * 1024;
/** Cap on ICE candidates buffered before the remote description is applied, so a peer cannot flood
 * candidates to exhaust memory while a transfer is merely offered. A real connection needs only a few. */
export const MAX_PENDING_ICE = 64;

interface Transfer {
  pc?: RtcConnectionLike;
  ch?: RtcChannelLike;
  readonly name: string;
  readonly size: number;
  // sender side
  source?: FileSource;
  // receiver side
  sink?: FileSink;
  recvGot?: number;
  writeChain?: Promise<void>;
  pendingOffer?: RtcSdp;
  pendingIce: unknown[];
  // True only once setRemoteDescription has resolved. ICE is buffered until then, because applying a
  // candidate before the remote description is installed is invalid and aborts the connection.
  remoteReady: boolean;
}

function parseSignal(value: unknown): FileSignal | null {
  if (typeof value !== 'object' || value === null) {
    return null;
  }
  const o = value as Record<string, unknown>;
  const id = o['id'];
  if (typeof id !== 'string' || id === '') {
    return null;
  }
  if (o['kind'] === 'offer' && typeof o['name'] === 'string' && typeof o['size'] === 'number' && isSdp(o['sdp'])) {
    return { kind: 'offer', id, name: o['name'], size: o['size'], sdp: o['sdp'] };
  }
  if (o['kind'] === 'answer' && isSdp(o['sdp'])) {
    return { kind: 'answer', id, sdp: o['sdp'] };
  }
  if (o['kind'] === 'ice') {
    return { kind: 'ice', id, candidate: o['candidate'] };
  }
  if (o['kind'] === 'decline') {
    return { kind: 'decline', id };
  }
  return null;
}

function isSdp(value: unknown): value is RtcSdp {
  return typeof value === 'object' && value !== null && typeof (value as Record<string, unknown>)['type'] === 'string';
}

/** A FileSink that accumulates chunks and yields a single Blob on close (the fallback when there is no save-to-disk stream). */
export class BlobSink implements FileSink {
  private readonly parts: BlobPart[] = [];
  constructor(private readonly contentType: string = 'application/octet-stream') {}
  write(chunk: Uint8Array): void {
    const buf = new ArrayBuffer(chunk.length);
    new Uint8Array(buf).set(chunk);
    this.parts.push(buf);
  }
  close(): Blob {
    return new Blob(this.parts, { type: this.contentType });
  }
}

export class FileTransfer {
  private readonly transfers = new Map<string, Transfer>();

  constructor(
    private readonly rtc: RtcFactory,
    private readonly ev: TransferEvents,
  ) {}

  /** Send a file to the peer: open a connection + data channel, offer, then stream slices once it opens. */
  async sendFile(id: string, name: string, source: FileSource): Promise<void> {
    const pc = this.rtc();
    const ch = pc.createDataChannel('file');
    ch.binaryType = 'arraybuffer';
    // The sender installs its remote description only when the answer arrives, so it too buffers ICE
    // until then (gated on remoteReady, not on pc, which exists from the start on this side).
    const t: Transfer = { pc, ch, name, size: source.size, source, pendingIce: [], remoteReady: false };
    this.transfers.set(id, t);
    pc.onicecandidate = (e) => {
      if (e.candidate !== null && e.candidate !== undefined) {
        this.ev.sendSignal({ kind: 'ice', id, candidate: e.candidate });
      }
    };
    ch.onopen = () => {
      void this.streamOut(id);
    };
    ch.onclose = () => {
      this.transfers.delete(id);
    };
    try {
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      this.ev.sendSignal({ kind: 'offer', id, name, size: source.size, sdp: offer });
    } catch {
      this.fail(id, 'could not start the transfer');
    }
  }

  /** Handle an inbound CONTROL_FILE signal from the peer. Unknown/malformed signals are ignored. */
  async handleSignal(raw: unknown): Promise<void> {
    const signal = parseSignal(raw);
    if (signal === null) {
      return;
    }
    if (signal.kind === 'offer') {
      // Announce the file and wait for the host to accept (and choose where it lands) before connecting.
      this.transfers.set(signal.id, {
        name: signal.name,
        size: signal.size,
        pendingOffer: signal.sdp,
        pendingIce: [],
        remoteReady: false,
      });
      this.ev.onIncoming(signal.id, signal.name, signal.size);
      return;
    }
    const t = this.transfers.get(signal.id);
    if (t === undefined) {
      return;
    }
    if (signal.kind === 'decline') {
      this.fail(signal.id, 'the other person declined the file');
      return;
    }
    if (signal.kind === 'answer') {
      try {
        await t.pc?.setRemoteDescription(signal.sdp);
      } catch {
        this.fail(signal.id, 'transfer setup failed');
        return;
      }
      t.remoteReady = true;
      await this.drainPendingIce(t);
      return;
    }
    // ICE. Apply only once the remote description is installed; otherwise buffer it (bounded). Gating on
    // remoteReady rather than on pc means a candidate that races setRemoteDescription is never applied
    // too early (which a real RTCPeerConnection rejects), and a flood cannot grow memory without bound.
    if (t.remoteReady && t.pc !== undefined) {
      await this.applyIce(t.pc, signal.candidate);
    } else if (t.pendingIce.length < MAX_PENDING_ICE) {
      t.pendingIce.push(signal.candidate);
    }
  }

  /** Accept an offered file and start receiving it into the given sink. */
  async accept(id: string, sink: FileSink): Promise<void> {
    const t = this.transfers.get(id);
    if (t === undefined || t.pendingOffer === undefined) {
      return;
    }
    const pc = this.rtc();
    t.pc = pc;
    t.sink = sink;
    t.recvGot = 0;
    t.writeChain = Promise.resolve();
    pc.onicecandidate = (e) => {
      if (e.candidate !== null && e.candidate !== undefined) {
        this.ev.sendSignal({ kind: 'ice', id, candidate: e.candidate });
      }
    };
    pc.ondatachannel = (e) => {
      this.bindReceive(id, e.channel);
    };
    try {
      await pc.setRemoteDescription(t.pendingOffer);
      t.remoteReady = true;
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      this.ev.sendSignal({ kind: 'answer', id, sdp: answer });
      await this.drainPendingIce(t);
    } catch {
      this.fail(id, 'could not accept the transfer');
    }
  }

  /** Decline an offered file: tell the peer and forget it. */
  decline(id: string): void {
    const t = this.transfers.get(id);
    if (t === undefined) {
      return;
    }
    this.ev.sendSignal({ kind: 'decline', id });
    t.pc?.close();
    this.transfers.delete(id);
  }

  /** Abort a transfer and free its connection. */
  cancel(id: string): void {
    const t = this.transfers.get(id);
    if (t !== undefined) {
      t.pc?.close();
      this.transfers.delete(id);
    }
  }

  private bindReceive(id: string, ch: RtcChannelLike): void {
    const t = this.transfers.get(id);
    if (t === undefined || t.sink === undefined) {
      return;
    }
    ch.binaryType = 'arraybuffer';
    ch.onmessage = (e) => {
      const tt = this.transfers.get(id);
      if (tt === undefined || tt.sink === undefined) {
        return;
      }
      if (typeof e.data === 'string') {
        if (e.data === DONE_MARKER) {
          const chain = tt.writeChain ?? Promise.resolve();
          void chain
            .then(() => Promise.resolve(tt.sink?.close() ?? null))
            .then((blob) => {
              this.ev.onComplete(id, tt.name, blob ?? null);
              tt.pc?.close();
              this.transfers.delete(id);
            })
            .catch(() => this.fail(id, 'could not save the received file'));
        }
        return;
      }
      const bytes = e.data instanceof ArrayBuffer ? new Uint8Array(e.data) : new Uint8Array(0);
      // Bound the received bytes by the size the user was shown and consented to. A sender that announces
      // a small file then streams more is rejected here, so it cannot fill memory or disk past consent.
      const next = (tt.recvGot ?? 0) + bytes.length;
      if (next > tt.size) {
        this.fail(id, 'the sender exceeded the announced file size');
        return;
      }
      tt.recvGot = next;
      this.ev.onProgress(id, tt.recvGot, tt.size);
      // Serialise writes so an async sink (a disk stream) stores chunks in arrival order.
      tt.writeChain = (tt.writeChain ?? Promise.resolve()).then(() => tt.sink?.write(bytes));
    };
  }

  private async streamOut(id: string): Promise<void> {
    const t = this.transfers.get(id);
    if (t === undefined || t.ch === undefined || t.source === undefined) {
      return;
    }
    const ch = t.ch;
    const source = t.source;
    let sent = 0;
    try {
      for (let off = 0; off < source.size; off += CHUNK_SIZE) {
        // Bail if the transfer was cancelled or failed while we were streaming, so we neither send on a
        // closed channel nor leave the drain loop spinning.
        if (!this.transfers.has(id)) {
          return;
        }
        if (ch.bufferedAmount > BACKPRESSURE_HIGH) {
          await this.drain(id, ch);
        }
        const chunk = await source.slice(off, Math.min(off + CHUNK_SIZE, source.size));
        const buf = new ArrayBuffer(chunk.length);
        new Uint8Array(buf).set(chunk);
        ch.send(buf);
        sent += chunk.length;
        this.ev.onProgress(id, sent, source.size);
      }
      if (this.transfers.has(id)) {
        ch.send(DONE_MARKER);
      }
    } catch {
      this.fail(id, 'the transfer failed while sending');
    }
  }

  /** Resolve once the data channel has drained below the low-water mark (or the transfer is gone), so we
   * never outrun the network and never poll a channel whose transfer was already cancelled. */
  private drain(id: string, ch: RtcChannelLike): Promise<void> {
    return new Promise((resolve) => {
      const check = (): void => {
        if (!this.transfers.has(id) || ch.bufferedAmount <= BACKPRESSURE_LOW) {
          resolve();
        } else {
          setTimeout(check, 50);
        }
      };
      check();
    });
  }

  /** Apply one inbound ICE candidate. A single malformed or duplicate candidate is dropped, never fatal,
   * so one bad candidate (or a hostile one) cannot tear down an otherwise-working connection. */
  private async applyIce(pc: RtcConnectionLike, candidate: unknown): Promise<void> {
    try {
      await pc.addIceCandidate(candidate);
    } catch {
      /* ignore a single bad candidate */
    }
  }

  /** Apply every ICE candidate buffered before the remote description was installed, in arrival order. */
  private async drainPendingIce(t: Transfer): Promise<void> {
    const pc = t.pc;
    const pending = t.pendingIce;
    t.pendingIce = [];
    if (pc === undefined) {
      return;
    }
    for (const candidate of pending) {
      await this.applyIce(pc, candidate);
    }
  }

  private fail(id: string, message: string): void {
    this.cancel(id);
    this.ev.onError(id, message);
  }
}
