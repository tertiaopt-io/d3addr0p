import { describe, it, expect } from 'vitest';
import jsQR from './vendor/jsqr.cjs';
import { qrMatrix } from './qr.js';
import { encodeQrPairing } from './provisioning.js';

// Rasterize a string's QR (our hand-rolled encoder) into an RGBA frame with a quiet zone, the way a
// camera would present it, so we can prove the VENDORED jsQR decoder reads what our encoder writes.
function rasterize(text: string, scale = 6, quiet = 4): { data: Uint8ClampedArray; width: number; height: number } {
  const { modules, size } = qrMatrix(text);
  const dim = (size + quiet * 2) * scale;
  const data = new Uint8ClampedArray(dim * dim * 4).fill(255); // opaque white background
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (!modules[r]![c]) {
        continue;
      }
      const x0 = (c + quiet) * scale;
      const y0 = (r + quiet) * scale;
      for (let y = y0; y < y0 + scale; y++) {
        for (let x = x0; x < x0 + scale; x++) {
          const i = (y * dim + x) * 4;
          data[i] = 0;
          data[i + 1] = 0;
          data[i + 2] = 0;
          data[i + 3] = 255;
        }
      }
    }
  }
  return { data, width: dim, height: dim };
}

describe('qrdecode (vendored jsQR camera fallback)', () => {
  it('round-trips a Profile contact link', () => {
    const text = `https://d3addr0p.com/#dd=alice&k=${'a1b2c3d4'.repeat(2)}`;
    const { data, width, height } = rasterize(text);
    const code = jsQR(data, width, height);
    expect(code).not.toBeNull();
    expect(code!.data).toBe(text);
  });

  it('round-trips a ddpair add-device payload', () => {
    const deviceSigKey = new Uint8Array(32).fill(0xab);
    const ephPub = new Uint8Array(32).fill(0xcd);
    const payload = encodeQrPairing(deviceSigKey, ephPub);
    expect(payload.startsWith('ddpair:')).toBe(true);
    const { data, width, height } = rasterize(payload);
    const code = jsQR(data, width, height);
    expect(code).not.toBeNull();
    expect(code!.data).toBe(payload);
  });

  it('returns null for a blank frame with no QR', () => {
    const blank = new Uint8ClampedArray(96 * 96 * 4).fill(255);
    expect(jsQR(blank, 96, 96)).toBeNull();
  });
});
