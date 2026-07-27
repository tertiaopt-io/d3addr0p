/**
 * Main-thread proxy to the owning Web Worker (M5 hardening). The worker is the SOLE writer to
 * IndexedDB and the sole holder of the unlocked MSK and the wasm Conversation objects, so secrets
 * stay off the main thread and two tabs cannot race the stores. This proxy implements AppController
 * by posting typed request/response messages to the worker; the worker (worker.js) runs the real
 * controller logic. The proxy is transport-agnostic and unit-tested with a fake transport.
 */

import type {
  AppController,
  BlockedContact,
  Buddy,
  GroupSummary,
  ChannelSummary,
  IdentityProfile,
  KeyExchangeState,
  PeerIdentity,
  BuddyIcon,
  TransmitModel,
  WorkerEvent,
} from './app.js';
import type { DeviceTarget } from './groupchannel.js';
import type { Lifetime } from './index.js';

/** Bidirectional message channel to the worker (the real Worker in production, a fake in tests). */
export interface WorkerTransport {
  post(message: unknown): void;
  onMessage(handler: (message: unknown) => void): void;
}

interface WorkerResponse {
  readonly id: number;
  readonly ok: boolean;
  readonly result?: unknown;
  readonly error?: string;
}

function isResponse(m: unknown): m is WorkerResponse {
  return typeof m === 'object' && m !== null && 'id' in m && 'ok' in m;
}

function isEvent(m: unknown): m is WorkerEvent {
  return typeof m === 'object' && m !== null && 'event' in m;
}

/** Wrap a real Worker as a transport. */
export function workerTransport(worker: Worker): WorkerTransport {
  return {
    post: (message) => worker.postMessage(message),
    onMessage: (handler) => {
      worker.onmessage = (e: MessageEvent) => {
        handler(e.data as unknown);
      };
    },
  };
}

export class WorkerController implements AppController {
  private seq = 0;
  private readonly pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
  private eventHandler: ((ev: WorkerEvent) => void) | null = null;

  constructor(private readonly transport: WorkerTransport) {
    this.transport.onMessage((msg) => {
      this.handle(msg);
    });
  }

  /** Register for unsolicited worker events (incoming offer, established channel, inbound message). */
  onEvent(handler: (ev: WorkerEvent) => void): void {
    this.eventHandler = handler;
  }

  private call<T>(op: string, args: readonly unknown[]): Promise<T> {
    const id = this.seq++;
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, { resolve: (v) => resolve(v as T), reject });
      this.transport.post({ id, op, args });
    });
  }

  private handle(msg: unknown): void {
    if (isEvent(msg)) {
      this.eventHandler?.(msg);
      return;
    }
    if (!isResponse(msg)) {
      return;
    }
    const entry = this.pending.get(msg.id);
    if (entry === undefined) {
      return;
    }
    this.pending.delete(msg.id);
    if (msg.ok) {
      entry.resolve(msg.result);
    } else {
      entry.reject(new Error(typeof msg.error === 'string' ? msg.error : 'worker error'));
    }
  }

  /** Resolves once the worker has loaded the wasm and opened the database. */
  ping(): Promise<true> {
    return this.call('ping', []);
  }

  unlock(username: string, passphrase: string): Promise<{ ok: boolean; created?: boolean; error?: string }> {
    return this.call('unlock', [username, passphrase]);
  }
  verifyPassphrase(username: string, passphrase: string): Promise<boolean> {
    return this.call('verifyPassphrase', [username, passphrase]);
  }
  deviceAuthState(): Promise<{ authorized: boolean; seedHolder: boolean }> {
    return this.call('deviceAuthState', []);
  }
  discardAccount(username: string): Promise<void> {
    return this.call('discardAccount', [username]);
  }
  peerFor(id: string): Promise<string> {
    return this.call('peerFor', [id]);
  }

  listChannels(): Promise<readonly ChannelSummary[]> {
    return this.call('listChannels', []);
  }
  openChannel(id: string): Promise<TransmitModel> {
    return this.call('openChannel', [id]);
  }
  openNoteToSelf(): Promise<TransmitModel> {
    return this.call('openNoteToSelf', []);
  }
  startKeyExchange(): Promise<KeyExchangeState> {
    return this.call('startKeyExchange', []);
  }
  channelKeyExchange(id: string): Promise<KeyExchangeState> {
    return this.call('channelKeyExchange', [id]);
  }
  acceptKeyExchange(conversationId: string): Promise<TransmitModel> {
    return this.call('acceptKeyExchange', [conversationId]);
  }
  connectGateway(wsUrl: string): Promise<{ ok: boolean; selfContact: string; error?: string }> {
    return this.call('connectGateway', [wsUrl]);
  }
  startConversation(targets: readonly DeviceTarget[]): Promise<TransmitModel> {
    return this.call('startConversation', [targets]);
  }
  sendMessage(conversationId: string, text: string, lifetime?: Lifetime): Promise<TransmitModel> {
    return this.call('sendMessage', [conversationId, text, lifetime]);
  }
  revokeMessage(conversationId: string, messageId: string): Promise<TransmitModel> {
    return this.call('revokeMessage', [conversationId, messageId]);
  }
  recoverySecret(): Promise<string | null> {
    return this.call('recoverySecret', []);
  }
  ensureAccountSeed(): Promise<void> {
    return this.call('ensureAccountSeed', []);
  }
  openProvisioningWindow(): Promise<void> {
    return this.call('openProvisioningWindow', []);
  }
  joinDevice(): Promise<void> {
    return this.call('joinDevice', []);
  }
  confirmProvisioning(): Promise<void> {
    return this.call('confirmProvisioning', []);
  }
  closeProvisioning(): Promise<void> {
    return this.call('closeProvisioning', []);
  }
  startQrPairing(): Promise<string> {
    return this.call('startQrPairing', []);
  }
  grantScannedDevice(qrPayload: string): Promise<void> {
    return this.call('grantScannedDevice', [qrPayload]);
  }
  keyPackages(n: number): Promise<string[]> {
    return this.call('keyPackages', [n]);
  }
  isGroupReady(): Promise<boolean> {
    return this.call('isGroupReady', []);
  }
  recoverWithSeed(recoverySeedHex: string, epoch: number): Promise<{ ok: boolean; error?: string }> {
    return this.call('recoverWithSeed', [recoverySeedHex, epoch]);
  }
  syncEpoch(epoch: number): Promise<{ ready: boolean; stale: boolean }> {
    return this.call('syncEpoch', [epoch]);
  }
  certEpoch(): Promise<number> {
    return this.call('certEpoch', []);
  }
  accountFingerprint(): Promise<string> {
    return this.call('accountFingerprint', []);
  }
  addDevice(conversationId: string, target: DeviceTarget): Promise<void> {
    return this.call('addDevice', [conversationId, target]);
  }
  excludeDevice(sigKeyHex: string): Promise<void> {
    return this.call('excludeDevice', [sigKeyHex]);
  }
  // Self-heal (H1). Both payloads are plain data (string arrays and DeviceTarget = string + Uint8Array),
  // so they are structured-clone-safe across postMessage; the claim itself runs on the app side and only
  // the resulting key packages cross here.
  hasMissingSiblings(ownDeviceKeys: readonly string[]): Promise<boolean> {
    return this.call('hasMissingSiblings', [ownDeviceKeys]);
  }
  reconcileSiblings(ownDeviceKeys: readonly string[], candidates: readonly DeviceTarget[]): Promise<void> {
    return this.call('reconcileSiblings', [ownDeviceKeys, candidates]);
  }
  reconcileRemovals(ownDeviceKeys: readonly string[], revokedKeys: readonly string[]): Promise<void> {
    return this.call('reconcileRemovals', [ownDeviceKeys, revokedKeys]);
  }
  reconcileSelf(ownDeviceKeys: readonly string[], candidates: readonly DeviceTarget[]): Promise<void> {
    return this.call('reconcileSelf', [ownDeviceKeys, candidates]);
  }
  selfSiblingState(deviceKey: string): Promise<'member' | 'pending' | 'absent' | 'none'> {
    return this.call('selfSiblingState', [deviceKey]);
  }
  hasSelfGroup(): Promise<boolean> {
    return this.call('hasSelfGroup', []);
  }
  ensureSelfGroup(targets: readonly DeviceTarget[]): Promise<void> {
    return this.call('ensureSelfGroup', [targets]);
  }
  // N-series: identity card, buddy list, block list, and presence/notify toggles. All of these read or
  // write MSK-sealed state that lives in the worker, so the proxy must forward them; otherwise they
  // silently no-op on the worker path (blank identity, empty buddy list, block does nothing, presence
  // off). Every payload here is a plain JSON object (IdentityProfile/Buddy/BlockedContact are strings,
  // numbers, and booleans only), so it is structured-clone-safe across postMessage.
  getIdentity(): Promise<IdentityProfile> {
    return this.call('getIdentity', []);
  }
  setIdentity(profile: IdentityProfile): Promise<void> {
    return this.call('setIdentity', [profile]);
  }
  getPeerIdentities(conversationId: string): Promise<readonly PeerIdentity[]> {
    return this.call('getPeerIdentities', [conversationId]);
  }
  tagConversationHandle(conversationId: string, username: string): Promise<void> {
    return this.call('tagConversationHandle', [conversationId, username]);
  }
  getBuddyInfo(username: string): Promise<readonly PeerIdentity[]> {
    return this.call('getBuddyInfo', [username]);
  }
  buddyIcons(usernames: readonly string[]): Promise<Record<string, BuddyIcon>> {
    return this.call('buddyIcons', [usernames]);
  }
  listBuddies(): Promise<readonly Buddy[]> {
    return this.call('listBuddies', []);
  }
  addBuddy(username: string, group?: string): Promise<readonly Buddy[]> {
    return this.call('addBuddy', [username, group]);
  }
  removeBuddy(username: string): Promise<readonly Buddy[]> {
    return this.call('removeBuddy', [username]);
  }
  setBuddyGroup(username: string, group: string): Promise<readonly Buddy[]> {
    return this.call('setBuddyGroup', [username, group]);
  }
  listGroups(): Promise<readonly GroupSummary[]> {
    return this.call('listGroups', []);
  }
  addGroup(name: string): Promise<readonly GroupSummary[]> {
    return this.call('addGroup', [name]);
  }
  renameGroup(role: 'default' | 'blocked', name: string): Promise<readonly GroupSummary[]> {
    return this.call('renameGroup', [role, name]);
  }
  deleteGroup(name: string): Promise<readonly GroupSummary[]> {
    return this.call('deleteGroup', [name]);
  }
  blockConversation(conversationId: string): Promise<void> {
    return this.call('blockConversation', [conversationId]);
  }

  removeConversation(conversationId: string): Promise<void> {
    return this.call('removeConversation', [conversationId]);
  }
  listBlocked(): Promise<readonly BlockedContact[]> {
    return this.call('listBlocked', []);
  }
  unblock(key: string): Promise<readonly BlockedContact[]> {
    return this.call('unblock', [key]);
  }
  getPresenceEnabled(): Promise<boolean> {
    return this.call('getPresenceEnabled', []);
  }
  setPresenceEnabled(on: boolean): Promise<void> {
    return this.call('setPresenceEnabled', [on]);
  }
  getNotifyEnabled(): Promise<boolean> {
    return this.call('getNotifyEnabled', []);
  }
  setNotifyEnabled(on: boolean): Promise<void> {
    return this.call('setNotifyEnabled', [on]);
  }
  // P2P signaling (file transfer + calls): relay the small WebRTC handshake to the owning worker, which
  // publishes it over the E2E group. The media/file bytes themselves never enter the worker; the
  // RTCPeerConnection lives on the main thread, where the API exists. Fire-and-forget.
  sendFileSignal(conversationId: string, json: string): void {
    void this.call('sendFileSignal', [conversationId, json]);
  }
  sendCallSignal(conversationId: string, json: string): void {
    void this.call('sendCallSignal', [conversationId, json]);
  }
}
