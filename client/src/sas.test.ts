import { describe, it, expect } from 'vitest';
import { renderSas, renderSasHex, sasWord } from './sas.js';

describe('SAS rendering (device-provisioning verification code)', () => {
  it('renders six words deterministically', () => {
    const d = new Uint8Array(32).fill(0xab);
    const s = renderSas(d);
    expect(s.split(' ')).toHaveLength(6);
    expect(renderSas(d)).toBe(s);
  });

  it('different digests render different words', () => {
    expect(renderSas(new Uint8Array(32).fill(1))).not.toBe(renderSas(new Uint8Array(32).fill(2)));
  });

  it('the 2048-token wordlist has no collisions (full 11-bit entropy per word)', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 2048; i++) {
      seen.add(sasWord(i));
    }
    expect(seen.size).toBe(2048);
  });

  it('renders from hex identically to bytes', () => {
    expect(renderSasHex('ab'.repeat(32))).toBe(renderSas(new Uint8Array(32).fill(0xab)));
  });

  it('rejects a too-short digest', () => {
    expect(() => renderSas(new Uint8Array(4))).toThrow();
  });
});
