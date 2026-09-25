import { useEffect, useState } from "react";
import MonacoEditor from "@monaco-editor/react";
import { useSession, PRESET_PROVIDERS, type AiProvider } from "../../store/session";
import { generateHarness, generateHarnessBinary, saveApiKey, loadApiKey, getCachedHarness, saveCachedHarness } from "../../lib/tauri";

interface Props {
  onBack: () => void;
  onNext: () => void;
}

const PROVIDER_LABELS: Record<string, string> = {
  deepseek: "DeepSeek",
  ollama: "Ollama (local)",
  claude: "Claude (Anthropic)",
  openai: "OpenAI",
  custom: "Custom",
};

export default function HarnessEditor({ onBack, onNext }: Props) {
  const {
    functionSignature,
    fileContent,
    filePath,
    harnessSource,
    harnessGenerating,
    resolvedHeaders,
    aiProvider,
    isBinaryMode,
    binaryPath,
    selectedSymbolName,
    companionHeaderContent,
    setHarnessSource,
    setHarnessGenerating,
    setAiProvider,
  } = useSession();

  // Local editable copy of provider config
  const [provider, setProvider] = useState<AiProvider>(aiProvider);
  const [isCustom, setIsCustom] = useState(
    !PRESET_PROVIDERS.some((p) => p.name === aiProvider.name)
  );
  const [error, setError] = useState<string | null>(null);
  const [userEdited, setUserEdited] = useState(false);
  const [fromCache, setFromCache] = useState(false);
  const [cacheChecking, setCacheChecking] = useState(!harnessSource);
  const [savingKey, setSavingKey] = useState(false);
  const [saveKeyError, setSaveKeyError] = useState<string | null>(null);

  const lsKey = (name: string) => `guzzle_apikey_${name}`;

  const loadKey = async (name: string): Promise<string | null> => {
    // Try keychain first, fall back to localStorage
    try {
      const key = await loadApiKey(name);
      if (key) return key;
    } catch (e) {
      console.warn("Keychain unavailable, falling back to localStorage:", e);
    }
    return localStorage.getItem(lsKey(name));
  };

  const saveKey = async (name: string, key: string) => {
    setSavingKey(true);
    setSaveKeyError(null);
    try {
      await saveApiKey(name, key);
    } catch (e) {
      // Keychain unavailable (unsigned dev build, etc.) — fall back to localStorage
      setSaveKeyError(`Keychain unavailable, saved locally instead. (${String(e)})`);
    }
    // Always save to localStorage as backup
    localStorage.setItem(lsKey(name), key);
    setSavingKey(false);
  };

  // Load saved key for current provider on mount / provider name change
  useEffect(() => {
    loadKey(provider.name)
      .then((key) => {
        if (key) setProvider((p) => ({ ...p, api_key: key }));
      })
      .catch((e) => console.warn("Failed to load API key on provider change:", e));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [provider.name]);

  const selectPreset = (name: string) => {
    const preset = PRESET_PROVIDERS.find((p) => p.name === name);
    if (preset) {
      const merged = { ...preset, api_key: provider.api_key }; // keep typed key
      setProvider(merged);
      setIsCustom(false);
      // Load saved key for this preset
      loadKey(name)
        .then((key) => { if (key) setProvider((p) => ({ ...p, api_key: key })); })
        .catch((e) => console.warn("Failed to load API key for preset:", e));
    } else {
      // "custom" option
      setIsCustom(true);
      setProvider((p) => ({ ...p, name: "custom", format: "openai" }));
    }
  };

  const handleSaveKey = async () => {
    if (!provider.api_key) return;
    await saveKey(provider.name, provider.api_key);
  };

  const getContextLines = () => {
    if (!fileContent || !functionSignature) return "";
    const lines = fileContent.split("\n");

    // Collect all #define macros from the whole file so the AI uses the
    // correct constants (e.g. MAX_FIELDS, buffer sizes) instead of guessing.
    const defines = lines
      .filter(l => /^\s*#\s*define\b/.test(l))
      .join("\n");

    const start = Math.max(0, functionSignature.start_line - 15);
    const end = Math.min(lines.length, functionSignature.end_line + 5);
    const surrounding = lines.slice(start, end).join("\n");

    return defines
      ? `// Macro definitions from source file:\n${defines}\n\n// Surrounding code context:\n${surrounding}`
      : surrounding;
  };

  const generate = async () => {
    if (!isBinaryMode && !functionSignature) return;
    if (isBinaryMode && !selectedSymbolName) return;
    const needsKey = provider.format !== "openai" || provider.name !== "ollama";
    if (needsKey && !provider.api_key.trim() && provider.name !== "ollama") {
      setError("Enter an API key for this provider.");
      return;
    }
    setError(null);
    setFromCache(false);
    setHarnessGenerating(true);
    setUserEdited(false);
    // Commit provider to store
    setAiProvider(provider);
    try {
      let harness: string;
      if (isBinaryMode && selectedSymbolName) {
        harness = await generateHarnessBinary(
          provider,
          selectedSymbolName,
          companionHeaderContent ?? null,
          resolvedHeaders.length > 0 ? resolvedHeaders : undefined,
        );
      } else {
        harness = await generateHarness(provider, functionSignature!, getContextLines(), resolvedHeaders.length > 0 ? resolvedHeaders : undefined);
      }
      setHarnessSource(harness);
    } catch (e) {
      setError(String(e));
    } finally {
      setHarnessGenerating(false);
    }
  };

  // Auto-generate on first open — check cache before calling AI
  useEffect(() => {
    const cacheKey = isBinaryMode
      ? (binaryPath && selectedSymbolName ? { path: binaryPath, fn: selectedSymbolName } : null)
      : (filePath && functionSignature ? { path: filePath, fn: functionSignature.name } : null);

    if (!harnessSource && !harnessGenerating && cacheKey) {
      getCachedHarness(cacheKey.path, cacheKey.fn)
        .then((cached) => {
          if (cached) {
            setHarnessSource(cached);
            setFromCache(true);
          } else {
            generate();
          }
        })
        .catch(() => generate())
        .finally(() => setCacheChecking(false));
    } else {
      setCacheChecking(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const selectedPresetName = isCustom ? "custom" : provider.name;
  const needsApiKey = provider.name !== "ollama";

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h2 className="text-lg font-semibold text-[#e6edf3]">Harness Editor</h2>
        <p className="text-sm text-[#8b949e] mt-1">
          AI-generated fuzzing harness for{" "}
          <code className="text-[#d2a8ff]">
            {isBinaryMode ? selectedSymbolName : functionSignature?.name}
          </code>. Review and edit before compiling.
        </p>
      </div>

      {/* Provider config */}
      <div className="bg-[#21262d] rounded-lg p-4 flex flex-col gap-3">
        <p className="text-xs text-[#8b949e] uppercase tracking-wider">AI Provider</p>

        {/* Preset selector */}
        <div className="flex gap-2 flex-wrap">
          {[...PRESET_PROVIDERS.map((p) => p.name), "custom"].map((name) => (
            <button
              key={name}
              onClick={() => selectPreset(name)}
              className={`px-3 py-1.5 rounded-md text-xs font-medium border transition-colors ${
                selectedPresetName === name
                  ? "bg-[#58a6ff] border-[#58a6ff] text-black"
                  : "bg-transparent border-[#30363d] text-[#8b949e] hover:border-[#58a6ff] hover:text-[#e6edf3]"
              }`}
            >
              {PROVIDER_LABELS[name] ?? name}
            </button>
          ))}
        </div>

        {/* Model + base URL (editable for custom, or tweakable for presets) */}
        <div className="grid grid-cols-2 gap-2">
          <div>
            <label className="block text-[10px] text-[#8b949e] mb-1">Model</label>
            <input
              value={provider.model}
              onChange={(e) => setProvider((p) => ({ ...p, model: e.target.value }))}
              className="w-full bg-[#161b22] border border-[#30363d] rounded px-2 py-1.5 text-xs text-[#e6edf3] font-mono focus:outline-none focus:border-[#58a6ff]"
            />
          </div>
          <div>
            <label className="block text-[10px] text-[#8b949e] mb-1">Base URL</label>
            <input
              value={provider.base_url}
              onChange={(e) => setProvider((p) => ({ ...p, base_url: e.target.value }))}
              className="w-full bg-[#161b22] border border-[#30363d] rounded px-2 py-1.5 text-xs text-[#e6edf3] font-mono focus:outline-none focus:border-[#58a6ff]"
            />
          </div>
        </div>

        {/* Format toggle for custom */}
        {isCustom && (
          <div className="flex items-center gap-3">
            <label className="text-[10px] text-[#8b949e] uppercase tracking-wider">API format:</label>
            {(["openai", "anthropic"] as const).map((fmt) => (
              <label key={fmt} className="flex items-center gap-1.5 cursor-pointer text-xs text-[#e6edf3]">
                <input
                  type="radio"
                  name="format"
                  value={fmt}
                  checked={provider.format === fmt}
                  onChange={() => setProvider((p) => ({ ...p, format: fmt }))}
                  className="accent-[#58a6ff]"
                />
                {fmt === "openai" ? "OpenAI-compatible" : "Anthropic"}
              </label>
            ))}
          </div>
        )}

        {/* API key */}
        {needsApiKey && (<>
          <div className="flex gap-2 items-end">
            <div className="flex-1">
              <label className="block text-[10px] text-[#8b949e] mb-1">
                API Key{" "}
                <span className="normal-case text-[#3fb950]">(saved to OS keychain)</span>
              </label>
              <input
                type="password"
                value={provider.api_key}
                onChange={(e) => setProvider((p) => ({ ...p, api_key: e.target.value }))}
                placeholder={
                  provider.name === "deepseek" ? "sk-..." :
                  provider.name === "claude" ? "sk-ant-..." :
                  provider.name === "openai" ? "sk-..." : "API key"
                }
                className="w-full bg-[#161b22] border border-[#30363d] rounded px-2 py-1.5 text-xs text-[#e6edf3] font-mono focus:outline-none focus:border-[#58a6ff]"
              />
            </div>
            <button
              onClick={handleSaveKey}
              disabled={!provider.api_key || savingKey}
              className="px-2.5 py-1.5 bg-[#161b22] hover:bg-[#30363d] border border-[#30363d] text-xs text-[#8b949e] rounded transition-colors disabled:opacity-40"
            >
              {savingKey ? "Saving…" : "Save"}
            </button>
          </div>
          {saveKeyError && (
            <p className="text-[11px] text-[#d29922]">{saveKeyError}</p>
          )}
        </>)}

        {provider.name === "ollama" && (
          <p className="text-[11px] text-[#8b949e]">
            No API key needed — Ollama runs locally. Make sure{" "}
            <code className="font-mono">ollama serve</code> is running and the model is pulled.
          </p>
        )}
      </div>

      {/* Generate button row */}
      <div className="flex justify-end items-center gap-3">
        {fromCache && (
          <span className="text-xs text-[#8b949e]">Cached — regenerate?</span>
        )}
        <button
          onClick={generate}
          disabled={harnessGenerating}
          className="px-3 py-1.5 bg-[#21262d] hover:bg-[#30363d] border border-[#30363d] text-sm text-[#e6edf3] rounded-md transition-colors flex items-center gap-2 disabled:opacity-40"
        >
          {harnessGenerating ? (
            <div className="w-3.5 h-3.5 border-2 border-[#58a6ff] border-t-transparent rounded-full animate-spin" />
          ) : "↺"}
          {harnessGenerating ? "Generating…" : "Regenerate"}
        </button>
      </div>

      {error && (
        <div className="bg-[#3d1414] border border-[#f85149] rounded-md p-3 text-sm text-[#f85149]">
          {error}
        </div>
      )}

      {userEdited && (
        <div className="bg-[#3d2f00] border border-[#d29922] rounded-md p-2 text-xs text-[#d29922]">
          ⚠ You've modified the generated harness. Make sure it compiles correctly.
        </div>
      )}

      <div className="rounded-lg overflow-hidden border border-[#30363d]" style={{ height: 280 }}>
        {(cacheChecking || harnessGenerating) && !harnessSource ? (
          <div className="flex items-center justify-center h-full bg-[#0d1117] gap-3">
            <div className="w-5 h-5 border-2 border-[#58a6ff] border-t-transparent rounded-full animate-spin" />
            <span className="text-sm text-[#8b949e]">
              {cacheChecking ? "Checking cache…" : `Generating via ${PROVIDER_LABELS[provider.name] ?? provider.name}…`}
            </span>
          </div>
        ) : (
          <MonacoEditor
            height="280px"
            language="cpp"
            value={harnessSource}
            theme="vs-dark"
            options={{
              fontSize: 12,
              minimap: { enabled: false },
              scrollBeyondLastLine: false,
              wordWrap: "off",
            }}
            onChange={(v) => {
              setHarnessSource(v ?? "");
              setUserEdited(true);
            }}
          />
        )}
      </div>

      <div className="flex justify-between">
        <button
          onClick={onBack}
          className="px-4 py-2 bg-[#21262d] hover:bg-[#30363d] text-[#e6edf3] text-sm font-medium rounded-md transition-colors"
        >
          ← Back
        </button>
        <button
          onClick={() => {
            // Commit provider (including loaded API key) to store so Results.tsx has it
            setAiProvider(provider);
            if (harnessSource) {
              if (isBinaryMode && binaryPath && selectedSymbolName) {
                void saveCachedHarness(binaryPath, selectedSymbolName, harnessSource);
              } else if (filePath && functionSignature) {
                void saveCachedHarness(filePath, functionSignature.name, harnessSource);
              }
            }
            onNext();
          }}
          disabled={!harnessSource || harnessGenerating}
          className="px-4 py-2 bg-[#238636] hover:bg-[#2ea043] disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm font-medium rounded-md transition-colors"
        >
          Next →
        </button>
      </div>
    </div>
  );
}
