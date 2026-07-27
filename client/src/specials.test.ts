import { describe, it, expect } from 'vitest';
import { substituteSpecials } from './specials.js';

describe('AIM-style special characters (%n / %d / %t)', () => {
  it('substitutes the buddy name, date, and time', () => {
    const at = new Date(2026, 5, 30, 9, 5).getTime(); // local 2026-06-30 09:05
    expect(substituteSpecials('hi %n at %t on %d', { name: 'RAVEN', at })).toBe('hi RAVEN at 9:05 AM on 6/30/2026');
  });

  it('returns text without any token unchanged', () => {
    expect(substituteSpecials('plain 50% off', { name: 'X' })).toBe('plain 50% off');
  });

  it('backslash-escapes marker/percent characters in the name so it cannot inject formatting', () => {
    expect(substituteSpecials('hey %n', { name: 'a*b[c%' })).toBe('hey a\\*b\\[c\\%');
  });

  it('uses a 12-hour clock with correct noon and midnight', () => {
    expect(substituteSpecials('%t', { at: new Date(2026, 0, 1, 0, 0).getTime() })).toBe('12:00 AM');
    expect(substituteSpecials('%t', { at: new Date(2026, 0, 1, 12, 30).getTime() })).toBe('12:30 PM');
    expect(substituteSpecials('%t', { at: new Date(2026, 0, 1, 13, 7).getTime() })).toBe('1:07 PM');
  });

  it('fills an empty name with nothing (missing name is not an error)', () => {
    expect(substituteSpecials('hi %n!', {})).toBe('hi !');
  });
});
