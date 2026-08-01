import { describe, it, expect } from 'vitest';
import { parseBuildVersion, versionFromCacheName, bootVersionFrom, shouldForceUpdate } from './appversion.js';

const V1 = '1234567890abcdef';
const V2 = 'fedcba0987654321';

describe('appversion.parseBuildVersion', () => {
  it('extracts the version from a real build.txt body', () => {
    const txt = `DEAD DROP build\nassets: 41\nbuild-hash: ${'a'.repeat(64)}\ncache: deaddrop-pinned-${V1}\n`;
    expect(parseBuildVersion(txt)).toBe(V1);
  });

  it('returns null for missing, empty, or malformed input', () => {
    expect(parseBuildVersion(null)).toBeNull();
    expect(parseBuildVersion(undefined)).toBeNull();
    expect(parseBuildVersion('')).toBeNull();
    expect(parseBuildVersion('some unrelated 404 page')).toBeNull();
    expect(parseBuildVersion('cache: deaddrop-pinned-XYZ')).toBeNull(); // not 16 hex
  });
});

describe('appversion.versionFromCacheName / bootVersionFrom', () => {
  it('reads the version out of a versioned cache name', () => {
    expect(versionFromCacheName(`deaddrop-pinned-${V1}`)).toBe(V1);
    expect(versionFromCacheName('some-other-cache')).toBeNull();
  });

  it('picks the pinned cache out of the set present at boot, null when none', () => {
    expect(bootVersionFrom([`deaddrop-pinned-${V1}`])).toBe(V1);
    expect(bootVersionFrom(['runtime', `deaddrop-pinned-${V2}`, 'images'])).toBe(V2);
    expect(bootVersionFrom([])).toBeNull(); // first install, nothing cached yet
    expect(bootVersionFrom(['unrelated', 'caches'])).toBeNull();
  });
});

describe('appversion.shouldForceUpdate', () => {
  it('forces an update when the loaded version is older than the latest advertised', () => {
    expect(shouldForceUpdate(V1, V2, null)).toBe(true);
  });

  it('does NOT force an update when already on the latest', () => {
    expect(shouldForceUpdate(V1, V1, null)).toBe(false);
  });

  it('does NOT force an update when either version is unknown (offline / first install / no SW)', () => {
    expect(shouldForceUpdate(null, V2, null)).toBe(false); // no cache yet (first install)
    expect(shouldForceUpdate(V1, null, null)).toBe(false); // build.txt unreachable (offline)
    expect(shouldForceUpdate(null, null, null)).toBe(false);
  });

  it('does NOT loop: a second visit that already tried THIS target does not reload again', () => {
    // First check: stale, no prior attempt -> reload, latch the target.
    expect(shouldForceUpdate(V1, V2, null)).toBe(true);
    // After the forced reload the page is STILL on V1 (update failed): the latch (=V2) suppresses a loop.
    expect(shouldForceUpdate(V1, V2, V2)).toBe(false);
    // But a NEWER deploy (V-different) is not suppressed by a latch aimed at the old target.
    expect(shouldForceUpdate(V1, 'aaaaaaaaaaaaaaaa', V2)).toBe(true);
  });
});
