import { describe, it, expect, afterEach, vi } from 'vitest';
import { requestPersistentStorage } from './persist.js';

// A minimal StorageManager stub; each test installs one via vi.stubGlobal('navigator', ...).
function withStorage(storage: unknown): void {
  vi.stubGlobal('navigator', { storage });
}

describe('requestPersistentStorage', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('grants persistence when not yet persisted', async () => {
    const persist = vi.fn().mockResolvedValue(true);
    const persisted = vi.fn().mockResolvedValue(false);
    withStorage({ persist, persisted });
    await expect(requestPersistentStorage()).resolves.toBe(true);
    expect(persisted).toHaveBeenCalledOnce();
    expect(persist).toHaveBeenCalledOnce();
  });

  it('short-circuits and does NOT re-request when already persisted', async () => {
    const persist = vi.fn().mockResolvedValue(true);
    const persisted = vi.fn().mockResolvedValue(true);
    withStorage({ persist, persisted });
    await expect(requestPersistentStorage()).resolves.toBe(true);
    expect(persist).not.toHaveBeenCalled();
  });

  it('returns false when the browser denies persistence', async () => {
    withStorage({ persist: vi.fn().mockResolvedValue(false), persisted: vi.fn().mockResolvedValue(false) });
    await expect(requestPersistentStorage()).resolves.toBe(false);
  });

  it('returns null when the Storage API is unavailable (older browsers / Worker scope)', async () => {
    withStorage(undefined);
    await expect(requestPersistentStorage()).resolves.toBeNull();
  });

  it('returns null when persist() is missing (persisted-only environments)', async () => {
    withStorage({ persisted: vi.fn().mockResolvedValue(false) });
    await expect(requestPersistentStorage()).resolves.toBeNull();
  });

  it('is non-fatal: swallows a throwing persist() and returns null', async () => {
    withStorage({
      persist: vi.fn().mockRejectedValue(new Error('SecurityError')),
      persisted: vi.fn().mockResolvedValue(false),
    });
    await expect(requestPersistentStorage()).resolves.toBeNull();
  });

  it('works without a persisted() method (calls persist directly)', async () => {
    const persist = vi.fn().mockResolvedValue(true);
    withStorage({ persist });
    await expect(requestPersistentStorage()).resolves.toBe(true);
    expect(persist).toHaveBeenCalledOnce();
  });
});
