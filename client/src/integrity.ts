/**
 * Bundle integrity verification (ADR-004, M1 slice 5).
 *
 * The PWA is delivered from a server the threat model treats as hostile, so the defense is to
 * PIN a reproducibly-built bundle: every app asset has a known SHA-256, the service worker
 * refuses to cache or run anything whose hash does not match, and the published bundle hash is
 * verified out of band before a user trusts the install (honest-limits point 6).
 *
 * This module is the verification core, unit-tested. The service worker (public/sw.js) applies
 * the same check at install time; keep the two in sync (the SW is generated from this logic at
 * build time once the bundler is wired).
 *
 * HONEST LIMIT: pinning protects updates after the first install. The first load is still
 * trust-on-first-use, and the browser and OS are the trusted base. This raises the cost of a
 * per-target backdoor; it does not reach packaged-client assurance (ADR-004 residual).
 */

export type PinnedManifest = Readonly<Record<string, string>>; // asset path -> lowercase SHA-256 hex

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  // Copy into a fresh ArrayBuffer-backed view so the type is ArrayBuffer (not ArrayBufferLike,
  // which would admit SharedArrayBuffer and is rejected by SubtleCrypto's BufferSource).
  const digest = await crypto.subtle.digest('SHA-256', new Uint8Array(bytes));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Constant-time hex comparison so a mismatch does not leak position via timing. */
export function constantTimeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

export async function verifyAsset(bytes: Uint8Array, expectedSha256Hex: string): Promise<boolean> {
  const actual = await sha256Hex(bytes);
  return constantTimeEqualHex(actual, expectedSha256Hex.toLowerCase());
}

export interface ManifestResult {
  readonly ok: boolean;
  readonly mismatched: readonly string[];
}

/**
 * Verify every pinned asset against its fetched bytes. The install is rejected unless ALL
 * assets match, so a single tampered file fails the whole bundle.
 */
export async function verifyManifest(
  fetched: ReadonlyMap<string, Uint8Array>,
  pinned: PinnedManifest,
): Promise<ManifestResult> {
  const mismatched: string[] = [];
  for (const [path, expected] of Object.entries(pinned)) {
    const bytes = fetched.get(path);
    if (bytes === undefined || !(await verifyAsset(bytes, expected))) {
      mismatched.push(path);
    }
  }
  return { ok: mismatched.length === 0, mismatched };
}
