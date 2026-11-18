import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("./tauri", () => ({
  saveApiKey: vi.fn(),
  loadApiKey: vi.fn(),
}));

import { saveApiKey, loadApiKey } from "./tauri";
import { loadKey, saveKey, legacyStorageKey } from "./apiKeyStore";

const mockSave = vi.mocked(saveApiKey);
const mockLoad = vi.mocked(loadApiKey);

beforeEach(() => {
  localStorage.clear();
  mockSave.mockReset();
  mockLoad.mockReset();
});

describe("saveKey", () => {
  it("stores the key in the keychain and never in localStorage", async () => {
    mockSave.mockResolvedValue(undefined);
    await saveKey("claude", "sk-secret");
    expect(mockSave).toHaveBeenCalledWith("claude", "sk-secret");
    expect(localStorage.getItem(legacyStorageKey("claude"))).toBeNull();
    expect(localStorage.length).toBe(0);
  });

  it("throws when the keychain fails and does not fall back to localStorage", async () => {
    mockSave.mockRejectedValue(new Error("no keychain"));
    await expect(saveKey("claude", "sk-secret")).rejects.toThrow(/no keychain/);
    expect(localStorage.length).toBe(0);
  });

  it("removes a legacy cleartext entry after a successful save", async () => {
    localStorage.setItem(legacyStorageKey("claude"), "sk-old");
    mockSave.mockResolvedValue(undefined);
    await saveKey("claude", "sk-new");
    expect(localStorage.getItem(legacyStorageKey("claude"))).toBeNull();
  });
});

describe("loadKey", () => {
  it("returns the keychain key", async () => {
    mockLoad.mockResolvedValue("sk-kc");
    expect(await loadKey("claude")).toBe("sk-kc");
  });

  it("returns null when nothing is stored", async () => {
    mockLoad.mockResolvedValue(null);
    expect(await loadKey("claude")).toBeNull();
  });

  it("migrates a legacy localStorage key into the keychain and deletes it", async () => {
    localStorage.setItem(legacyStorageKey("claude"), "sk-old");
    mockLoad.mockResolvedValue(null);
    mockSave.mockResolvedValue(undefined);
    expect(await loadKey("claude")).toBe("sk-old");
    expect(mockSave).toHaveBeenCalledWith("claude", "sk-old");
    expect(localStorage.getItem(legacyStorageKey("claude"))).toBeNull();
  });

  it("deletes a legacy entry when the keychain already has a key", async () => {
    localStorage.setItem(legacyStorageKey("claude"), "sk-old");
    mockLoad.mockResolvedValue("sk-kc");
    expect(await loadKey("claude")).toBe("sk-kc");
    expect(localStorage.getItem(legacyStorageKey("claude"))).toBeNull();
  });

  it("keeps the legacy entry if migration to the keychain fails", async () => {
    localStorage.setItem(legacyStorageKey("claude"), "sk-old");
    mockLoad.mockRejectedValue(new Error("no keychain"));
    mockSave.mockRejectedValue(new Error("no keychain"));
    expect(await loadKey("claude")).toBe("sk-old");
    expect(localStorage.getItem(legacyStorageKey("claude"))).toBe("sk-old");
  });

  it("propagates keychain errors when there is no legacy key", async () => {
    mockLoad.mockRejectedValue(new Error("no keychain"));
    await expect(loadKey("claude")).rejects.toThrow(/no keychain/);
  });
});
