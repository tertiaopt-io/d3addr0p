/**
 * Direct peer-to-peer audio/video calls over WebRTC (P2).
 *
 * The SIGNALING (SDP offer/answer + ICE candidates) rides the existing end-to-end MLS channel as
 * CONTROL_CALL control frames; the MEDIA (Opus audio, which is compressed and low-latency by design,
 * and VP8/VP9 video) travels peer-to-peer and is encrypted by WebRTC itself (DTLS-SRTP). Because the
 * DTLS key fingerprints are carried inside the E2E signaling, the server can neither read the media
 * nor sit in the middle of it. HONEST LIMITS (see honest-limits): a direct connection lets each peer
 * learn the other's real IP address, the one thing sealed sender hides, and it can fail to connect
 * behind a strict NAT because there is no relay. Calls are 1:1.
 *
 * The browser primitives are INJECTED (RtcMediaFactory + a getUserMedia function) so this module stays
 * browser-agnostic and is unit-tested with fakes; production wires the real RTCPeerConnection and
 * navigator.mediaDevices.getUserMedia in boot.js. Nothing here touches the network directly.
 */

import type { RtcSdp } from './filetransfer.js';

/** The slice of a MediaStreamTrack we use. */
export interface RtcTrackLike {
  readonly kind: string;
  enabled: boolean;
  stop(): void;
}

/** The slice of a MediaStream we use. */
export interface MediaStreamLike {
  getTracks(): readonly RtcTrackLike[];
  getAudioTracks(): readonly RtcTrackLike[];
  getVideoTracks(): readonly RtcTrackLike[];
}

/** The slice of an RTCRtpSender we use. */
export interface RtcSenderLike {
  readonly track: RtcTrackLike | null;
}

/** The minimal RTCPeerConnection surface a call uses (media, not a data channel). Injected for tests. */
export interface RtcMediaConnectionLike {
  createOffer(): Promise<RtcSdp>;
  createAnswer(): Promise<RtcSdp>;
  setLocalDescription(desc: RtcSdp): Promise<void>;
  setRemoteDescription(desc: RtcSdp): Promise<void>;
  addIceCandidate(candidate: unknown): Promise<void>;
  addTrack(track: RtcTrackLike, stream: MediaStreamLike): RtcSenderLike;
  onicecandidate: ((ev: { candidate: unknown }) => void) | null;
  ontrack: ((ev: { streams: readonly MediaStreamLike[] }) => void) | null;
  onconnectionstatechange: (() => void) | null;
  readonly connectionState: string;
  close(): void;
}

export type RtcMediaFactory = () => RtcMediaConnectionLike;
export type GetUserMedia = (constraints: {
  audio: boolean;
  video: boolean;
  // Prefer a specific camera: 'environment' (rear) for the QR scanner, 'user' (front) otherwise. Optional
  // and advisory ('ideal'), so it falls back gracefully on a device with only one camera (e.g. a laptop).
  facingMode?: 'environment' | 'user';
}) => Promise<MediaStreamLike>;

/** A call signal carried inside one CONTROL_CALL frame (the JSON payload). */
export type CallSignal =
  | { readonly kind: 'call-offer'; readonly id: string; readonly video: boolean; readonly sdp: RtcSdp }
  | { readonly kind: 'call-answer'; readonly id: string; readonly sdp: RtcSdp }
  | { readonly kind: 'call-ice'; readonly id: string; readonly candidate: unknown }
  | { readonly kind: 'call-decline'; readonly id: string }
  | { readonly kind: 'call-hangup'; readonly id: string };

export type CallState = 'calling' | 'ringing' | 'connected' | 'ended';

/** Side-effects a call needs from its host (wired to the controller / groupchannel and the UI). */
export interface CallEvents {
  /** Emit a signal to the peer over the E2E channel (the only thing that touches the server). */
  sendSignal(signal: CallSignal): void;
  /** A peer is ringing us. The host shows accept/decline UI, then calls accept(id) or decline(id). */
  onIncoming(id: string, withVideo: boolean): void;
  /** The call moved to a new state, for the in-call UI. */
  onState(id: string, state: CallState): void;
  /** Our own camera/mic stream is ready, for a local self-view. */
  onLocalStream(id: string, stream: MediaStreamLike): void;
  /** The peer's media arrived, to attach to a video/audio element. */
  onRemoteStream(id: string, stream: MediaStreamLike): void;
  /** The call failed. */
  onError(id: string, message: string): void;
}

interface Call {
  pc?: RtcMediaConnectionLike;
  local?: MediaStreamLike;
  readonly video: boolean;
  readonly role: 'caller' | 'callee';
  pendingOffer?: RtcSdp;
  pendingIce: unknown[];
  // True only once setRemoteDescription has resolved. ICE is buffered until then, because applying a
  // candidate before the remote description is installed is invalid and tears the call down.
  remoteReady: boolean;
  ended: boolean;
}

/** Cap on ICE candidates buffered before the remote description is applied, so a peer cannot flood
 * candidates to exhaust memory while a call is merely ringing. A real connection needs only a few. */
export const MAX_PENDING_ICE = 64;

function parseCallSignal(value: unknown): CallSignal | null {
  if (typeof value !== 'object' || value === null) {
    return null;
  }
  const o = value as Record<string, unknown>;
  const id = o['id'];
  if (typeof id !== 'string' || id === '') {
    return null;
  }
  if (o['kind'] === 'call-offer' && typeof o['video'] === 'boolean' && isSdp(o['sdp'])) {
    return { kind: 'call-offer', id, video: o['video'], sdp: o['sdp'] };
  }
  if (o['kind'] === 'call-answer' && isSdp(o['sdp'])) {
    return { kind: 'call-answer', id, sdp: o['sdp'] };
  }
  if (o['kind'] === 'call-ice') {
    return { kind: 'call-ice', id, candidate: o['candidate'] };
  }
  if (o['kind'] === 'call-decline') {
    return { kind: 'call-decline', id };
  }
  if (o['kind'] === 'call-hangup') {
    return { kind: 'call-hangup', id };
  }
  return null;
}

function isSdp(value: unknown): value is RtcSdp {
  return typeof value === 'object' && value !== null && typeof (value as Record<string, unknown>)['type'] === 'string';
}

export class CallSession {
  private readonly calls = new Map<string, Call>();

  constructor(
    private readonly rtc: RtcMediaFactory,
    private readonly media: GetUserMedia,
    private readonly ev: CallEvents,
  ) {}

  /** Whether a call is currently active (used by the UI to disable a second call button). */
  isActive(): boolean {
    return this.calls.size > 0;
  }

  /** Place a call: capture mic (and camera if video), offer, and ring the peer. */
  async startCall(id: string, withVideo: boolean): Promise<void> {
    if (this.calls.has(id)) {
      return;
    }
    const call: Call = { video: withVideo, role: 'caller', pendingIce: [], remoteReady: false, ended: false };
    this.calls.set(id, call);
    this.ev.onState(id, 'calling');
    const local = await this.capture(id, withVideo);
    if (local === null) {
      return;
    }
    // The call may have been torn down (a decline/hangup arrived) while we waited on the permission
    // prompt. If so, stop the freshly captured tracks so the mic/camera does not stay open, and bail.
    if (this.aborted(id)) {
      this.stopTracks(local);
      return;
    }
    call.local = local;
    this.ev.onLocalStream(id, local);
    const pc = this.rtc();
    call.pc = pc;
    this.wirePc(id, pc);
    for (const track of local.getTracks()) {
      pc.addTrack(track, local);
    }
    try {
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      this.ev.sendSignal({ kind: 'call-offer', id, video: withVideo, sdp: offer });
    } catch {
      this.fail(id, 'could not start the call');
    }
  }

  /** Handle an inbound CONTROL_CALL signal from the peer. Unknown/malformed signals are ignored. */
  async handleSignal(raw: unknown): Promise<void> {
    const signal = parseCallSignal(raw);
    if (signal === null) {
      return;
    }
    if (signal.kind === 'call-offer') {
      if (this.calls.has(signal.id)) {
        return;
      }
      // Ring, but do not touch the mic/camera until the user accepts.
      this.calls.set(signal.id, {
        video: signal.video,
        role: 'callee',
        pendingOffer: signal.sdp,
        pendingIce: [],
        remoteReady: false,
        ended: false,
      });
      this.ev.onState(signal.id, 'ringing');
      this.ev.onIncoming(signal.id, signal.video);
      return;
    }
    const call = this.calls.get(signal.id);
    if (call === undefined) {
      return;
    }
    if (signal.kind === 'call-decline' || signal.kind === 'call-hangup') {
      this.teardown(signal.id);
      this.ev.onState(signal.id, 'ended');
      return;
    }
    if (signal.kind === 'call-answer') {
      try {
        await call.pc?.setRemoteDescription(signal.sdp);
      } catch {
        this.fail(signal.id, 'call setup failed');
        return;
      }
      call.remoteReady = true;
      await this.drainPendingIce(call);
      return;
    }
    // ICE. Apply only once the remote description is installed; otherwise buffer it (bounded). Gating on
    // remoteReady rather than on pc means a candidate that races setRemoteDescription is never applied
    // too early (which a real RTCPeerConnection rejects), and a flood cannot grow memory without bound.
    if (call.remoteReady && call.pc !== undefined) {
      await this.applyIce(call.pc, signal.candidate);
    } else if (call.pendingIce.length < MAX_PENDING_ICE) {
      call.pendingIce.push(signal.candidate);
    }
  }

  /** Accept a ringing call: capture our media and answer. */
  async accept(id: string): Promise<void> {
    const call = this.calls.get(id);
    if (call === undefined || call.pendingOffer === undefined) {
      return;
    }
    const local = await this.capture(id, call.video);
    if (local === null) {
      return;
    }
    // The caller may have hung up while we were on the permission prompt. If so, release the captured
    // mic/camera and bail rather than spinning up a connection nobody is waiting on.
    if (this.aborted(id)) {
      this.stopTracks(local);
      return;
    }
    call.local = local;
    this.ev.onLocalStream(id, local);
    const pc = this.rtc();
    call.pc = pc;
    this.wirePc(id, pc);
    for (const track of local.getTracks()) {
      pc.addTrack(track, local);
    }
    try {
      await pc.setRemoteDescription(call.pendingOffer);
      call.remoteReady = true;
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      this.ev.sendSignal({ kind: 'call-answer', id, sdp: answer });
      await this.drainPendingIce(call);
    } catch {
      this.fail(id, 'could not accept the call');
    }
  }

  /** Decline a ringing call. */
  decline(id: string): void {
    if (!this.calls.has(id)) {
      return;
    }
    this.ev.sendSignal({ kind: 'call-decline', id });
    this.teardown(id);
    this.ev.onState(id, 'ended');
  }

  /** End an active or ringing call from our side. */
  hangup(id: string): void {
    if (!this.calls.has(id)) {
      return;
    }
    this.ev.sendSignal({ kind: 'call-hangup', id });
    this.teardown(id);
    this.ev.onState(id, 'ended');
  }

  /** Mute or unmute our microphone for a call. */
  setMicEnabled(id: string, on: boolean): void {
    for (const track of this.calls.get(id)?.local?.getAudioTracks() ?? []) {
      track.enabled = on;
    }
  }

  /** Turn our camera on or off for a call. */
  setCameraEnabled(id: string, on: boolean): void {
    for (const track of this.calls.get(id)?.local?.getVideoTracks() ?? []) {
      track.enabled = on;
    }
  }

  /** True if the call for this id was torn down (or never existed) while we were awaiting capture. */
  private aborted(id: string): boolean {
    const call = this.calls.get(id);
    return call === undefined || call.ended;
  }

  private stopTracks(stream: MediaStreamLike): void {
    for (const track of stream.getTracks()) {
      track.stop();
    }
  }

  /** Apply one inbound ICE candidate. A single malformed or duplicate candidate is dropped, never fatal,
   * so one bad (or hostile) candidate cannot tear down an otherwise-working call. */
  private async applyIce(pc: RtcMediaConnectionLike, candidate: unknown): Promise<void> {
    try {
      await pc.addIceCandidate(candidate);
    } catch {
      /* ignore a single bad candidate */
    }
  }

  /** Apply every ICE candidate buffered before the remote description was installed, in arrival order. */
  private async drainPendingIce(call: Call): Promise<void> {
    const pc = call.pc;
    const pending = call.pendingIce;
    call.pendingIce = [];
    if (pc === undefined) {
      return;
    }
    for (const candidate of pending) {
      await this.applyIce(pc, candidate);
    }
  }

  private async capture(id: string, withVideo: boolean): Promise<MediaStreamLike | null> {
    try {
      return await this.media({ audio: true, video: withVideo });
    } catch {
      this.fail(id, withVideo ? 'could not access your microphone or camera' : 'could not access your microphone');
      return null;
    }
  }

  private wirePc(id: string, pc: RtcMediaConnectionLike): void {
    pc.onicecandidate = (e) => {
      if (e.candidate !== null && e.candidate !== undefined) {
        this.ev.sendSignal({ kind: 'call-ice', id, candidate: e.candidate });
      }
    };
    pc.ontrack = (e) => {
      const stream = e.streams[0];
      if (stream !== undefined) {
        this.ev.onRemoteStream(id, stream);
      }
      this.ev.onState(id, 'connected');
    };
    pc.onconnectionstatechange = () => {
      const state = pc.connectionState;
      if (state === 'connected') {
        this.ev.onState(id, 'connected');
      } else if (state === 'failed' || state === 'disconnected' || state === 'closed') {
        const call = this.calls.get(id);
        if (call !== undefined && !call.ended) {
          this.teardown(id);
          this.ev.onState(id, 'ended');
        }
      }
    };
  }

  private teardown(id: string): void {
    const call = this.calls.get(id);
    if (call === undefined) {
      return;
    }
    call.ended = true;
    for (const track of call.local?.getTracks() ?? []) {
      track.stop();
    }
    call.pc?.close();
    this.calls.delete(id);
  }

  private fail(id: string, message: string): void {
    this.teardown(id);
    this.ev.onError(id, message);
    this.ev.onState(id, 'ended');
  }
}
