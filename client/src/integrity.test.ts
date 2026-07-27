import { describe, it, expect } from 'vitest';
import { sha256Hex, constantTimeEqualHex, verifyAsset, verifyManifest } from './integrity.js';

const enc = new TextEncoder();

describe('bundle integrity (ADR-004)', () => {
  it('computes a known SHA-256', async () => {
    // SHA-256("") is well known.
    expect(await sha256Hex(new Uint8Array())).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
  });

  it('verifies a matching asset and rejects a tampered one', async () => {
    const bytes = enc.encode('app.js contents');
    const good = await sha256Hex(bytes);
    expect(await verifyAsset(bytes, good)).toBe(true);

    const tampered = enc.encode('app.js contents (backdoored)');
    expect(await verifyAsset(tampered, good)).toBe(false);
  });

  it('constant-time compare matches exact and rejects different/length', () => {
    expect(constantTimeEqualHex('abcd', 'abcd')).toBe(true);
    expect(constantTimeEqualHex('abcd', 'abce')).toBe(false);
    expect(constantTimeEqualHex('abcd', 'abc')).toBe(false);
  });

  it('fails the whole manifest if any one asset is tampered', async () => {
    const a = enc.encode('index.html');
    const b = enc.encode('app.js');
    const pinned = { 'index.html': await sha256Hex(a), 'app.js': await sha256Hex(b) };

    const allGood = new Map([
      ['index.html', a],
      ['app.js', b],
    ]);
    expect((await verifyManifest(allGood, pinned)).ok).toBe(true);

    const oneBad = new Map([
      ['index.html', a],
      ['app.js', enc.encode('app.js (backdoored)')],
    ]);
    const result = await verifyManifest(oneBad, pinned);
    expect(result.ok).toBe(false);
    expect(result.mismatched).toContain('app.js');
  });

  it('treats a missing asset as a mismatch', async () => {
    const a = enc.encode('index.html');
    const pinned = { 'index.html': await sha256Hex(a), 'missing.js': 'deadbeef' };
    const result = await verifyManifest(new Map([['index.html', a]]), pinned);
    expect(result.ok).toBe(false);
    expect(result.mismatched).toContain('missing.js');
  });
});
