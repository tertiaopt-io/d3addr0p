/**
 * DEAD DROP client entrypoint (M0 skeleton).
 *
 * The client holds all keys and performs ALL cryptography (brief §4.1). No server tier ever
 * sees plaintext or keys. M0 contains no crypto yet; it establishes the strict typecheck
 * gate and the shared vocabulary. Crypto lands at M1 (Gate 4 / Gate 14).
 */

/** Per-message readability lifetime (§3.2). The policy is encoded INSIDE the encrypted
 * payload and enforced by the recipient client after decryption. */
export type Lifetime =
  | { readonly kind: 'burn-on-read' }
  | { readonly kind: 'duration'; readonly seconds: number }
  | { readonly kind: 'until-revoked' };

export const SUGGESTED_DURATIONS_SECONDS: readonly number[] = [5, 30, 300, 3600, 86400];

/**
 * Honest-limit string shown before a user trusts their safety to the app (§A.3).
 * App-facing copy: no em-dashes, no "not X but Y" constructions (§0.7).
 */
export const FIRST_RUN_NOTICE =
  'This app keeps your messages unreadable to the server and to the network. ' +
  'It cannot protect you if your phone is infected with spyware, or if it is taken ' +
  'while unlocked and you are forced to open it. It cannot hide which server you connect ' +
  'to. The retro look is cover, not protection. Disappearing messages reduce exposure, ' +
  'they do not erase a message someone already saw. Detection is made harder, never ' +
  'impossible.';

/**
 * Register the integrity-pinning service worker (ADR-004). Installing the PWA is what lets the
 * app stop re-fetching code from the untrusted origin each load. No-op where unsupported.
 */
export async function registerServiceWorker(): Promise<void> {
  if (!('serviceWorker' in navigator)) {
    return;
  }
  await navigator.serviceWorker.register('/sw.js', { scope: '/' });
}

export function describeLifetime(l: Lifetime): string {
  switch (l.kind) {
    case 'burn-on-read':
      return 'Readable once, then destroyed';
    case 'duration':
      return `Readable for ${l.seconds}s, then destroyed`;
    case 'until-revoked':
      return 'Readable until revoked';
  }
}
