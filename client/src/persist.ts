// Best-effort request to keep this origin's storage from being evicted.
//
// The account vault (MskVault, idb.ts) is IndexedDB-only and account recovery is impossible by design,
// so if the browser evicts this origin's storage under pressure the vault and all local history are
// destroyed for good, unless a second authorized device survives or the recovery seed was backed up
// out of band. navigator.storage.persist() marks the origin's storage best-effort non-evictable
// (browsers grant it by engagement heuristics or an explicit grant), which is the one lever the web
// platform offers against that loss.
//
// This must run on the MAIN THREAD: StorageManager.persist() is exposed on Window only, not in Workers,
// even though the vault itself lives in the worker. Persistence is granted per origin, so a main-thread
// grant still covers the worker's IndexedDB. It is always best-effort and non-fatal, and must never
// block or fail an unlock. Returns the granted state, or null when the API is unavailable (older
// browsers, insecure contexts, or a context that does not expose persist()).
export async function requestPersistentStorage(): Promise<boolean | null> {
  try {
    if (typeof navigator === 'undefined' || !navigator.storage || typeof navigator.storage.persist !== 'function') {
      return null;
    }
    // Already granted: nothing to request, and it avoids any first-time permission prompt.
    if (typeof navigator.storage.persisted === 'function' && (await navigator.storage.persisted())) {
      return true;
    }
    return await navigator.storage.persist();
  } catch {
    return null;
  }
}
