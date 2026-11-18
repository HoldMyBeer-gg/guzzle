import { saveApiKey, loadApiKey } from "./tauri";

// Older builds kept a cleartext copy of every API key in localStorage under
// this name. Keys now live only in the OS keychain; this name is kept so the
// leftover copies can be migrated and deleted.
export const legacyStorageKey = (name: string) => `guzzle_apikey_${name}`;

function readLegacy(name: string): string | null {
  try {
    return localStorage.getItem(legacyStorageKey(name));
  } catch {
    return null;
  }
}

function removeLegacy(name: string): void {
  try {
    localStorage.removeItem(legacyStorageKey(name));
  } catch {
    // Storage blocked: nothing was readable there either.
  }
}

/** Save to the OS keychain. Throws if the keychain is unavailable. */
export async function saveKey(name: string, key: string): Promise<void> {
  await saveApiKey(name, key);
  removeLegacy(name);
}

/**
 * Load from the OS keychain. A legacy localStorage key is moved into the
 * keychain and deleted; if the keychain can't take it, it is returned and left
 * in place so the user doesn't lose it.
 */
export async function loadKey(name: string): Promise<string | null> {
  const legacy = readLegacy(name);
  let key: string | null;
  try {
    key = await loadApiKey(name);
  } catch (e) {
    if (legacy === null) throw e;
    key = null;
  }
  if (key) {
    removeLegacy(name);
    return key;
  }
  if (legacy === null) return null;
  try {
    await saveKey(name, legacy);
  } catch {
    // Keychain unavailable: keep the legacy copy rather than destroy it.
  }
  return legacy;
}
