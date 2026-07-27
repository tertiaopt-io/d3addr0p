import { describe, it, expect } from 'vitest';
import { qrMatrix, qrSvg } from './qr.js';

describe('QR encoder', () => {
  it('picks a version whose size grows with the data length', () => {
    // v1 = 21, v2 = 25, v3 = 29, v4 = 33, v5 = 37.
    expect(qrMatrix('hi').size).toBe(21);
    expect(qrMatrix('a'.repeat(20)).size).toBeGreaterThan(21);
    expect(qrMatrix('https://d3addr0p.com/#dd=raven').size).toBe(25);
    // A realistic contact link (handle up to ~40 chars + fingerprint) stays within v1-5 (<= 106 bytes).
    expect(qrMatrix('https://d3addr0p.com/#dd=' + 'x'.repeat(40) + '&k=AABBCCDDEEFF00112233').size).toBeLessThanOrEqual(37);
  });

  it('is deterministic (same input, same matrix)', () => {
    const a = qrMatrix('https://d3addr0p.com/#dd=alice88&k=5F·A2·91·C4');
    const b = qrMatrix('https://d3addr0p.com/#dd=alice88&k=5F·A2·91·C4');
    expect(a.size).toBe(b.size);
    expect(a.modules).toEqual(b.modules);
  });

  it('places the three finder patterns (7x7 dark ring in each of three corners)', () => {
    const { modules, size } = qrMatrix('hello world');
    const isFinderCorner = (r0: number, c0: number): boolean => {
      // The finder ring's outer border is dark all the way around a 7x7 block.
      for (let i = 0; i < 7; i++) {
        if (!modules[r0]![c0 + i] || !modules[r0 + 6]![c0 + i]) return false;
        if (!modules[r0 + i]![c0]! || !modules[r0 + i]![c0 + 6]) return false;
      }
      // ...with a light gap just inside it.
      return !modules[r0 + 1]![c0 + 1] && !modules[r0 + 5]![c0 + 5];
    };
    expect(isFinderCorner(0, 0)).toBe(true); // top-left
    expect(isFinderCorner(0, size - 7)).toBe(true); // top-right
    expect(isFinderCorner(size - 7, 0)).toBe(true); // bottom-left
  });

  it('throws when the text is too long for a v1-5 code', () => {
    expect(() => qrMatrix('x'.repeat(200))).toThrow();
  });

  it('renders CSP-safe inline SVG: no inline style, a white background, and a black module path', () => {
    const svg = qrSvg('https://d3addr0p.com/#dd=raven', 200);
    expect(svg.startsWith('<svg')).toBe(true);
    expect(svg).not.toContain('style='); // style-src blocks inline styles
    expect(svg).not.toContain('<script'); // never any script in the SVG
    expect(svg).toContain('fill="#ffffff"'); // white quiet-zone background so it scans
    expect(svg).toContain('fill="#000000"'); // dark modules
    expect(svg).toContain('role="img"');
  });
});
