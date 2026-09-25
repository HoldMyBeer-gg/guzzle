import { useEffect, useState } from "react";
import MonacoEditor from "@monaco-editor/react";
import { listen } from "@tauri-apps/api/event";
import { useSession } from "../../store/session";
import { readCrashFiles, revealInFinder, generatePoc } from "../../lib/tauri";
import type { CrashFile } from "../../store/session";
import Terminal from "../shared/Terminal";

interface Props {
  onClose: () => void;
}

function timeAgo(secs: number): string {
  if (secs === 0) return "unknown";
  const diff = Math.floor(Date.now() / 1000) - secs;
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  if (diff < 604800) return `${Math.floor(diff / 86400)}d ago`;
  if (diff < 2592000) return `${Math.floor(diff / 604800)}w ago`;
  return `${Math.floor(diff / 2592000)}mo ago`;
}

function HexDump({ bytes }: { bytes: number[] }) {
  const lines: React.ReactNode[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const hex = chunk.map((b) => b.toString(16).padStart(2, "0")).join(" ");
    const ascii = chunk
      .map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : "."))
      .join("");
    lines.push(
      <div key={i} className="flex gap-4">
        <span className="text-[#8b949e]">{i.toString(16).padStart(4, "0")}</span>
        <span className="text-[#58a6ff]">{hex.padEnd(47)}</span>
        <span className="text-[#e6edf3]">{ascii}</span>
      </div>
    );
  }
  return (
    <div className="font-mono text-xs bg-[#0d1117] rounded p-3 max-h-48 overflow-auto">
      {lines}
    </div>
  );
}

interface PocState {
  status: "idle" | "running" | "done" | "error";
  log: string[];
  script: string | null;
  error: string | null;
}

export default function Results({ onClose }: Props) {
  const {
    filePath,
    crashes,
    setCrashes,
    compiledBinaryPath,
    harnessSource,
    compileSettings,
    aiProvider,
    functionSignature,
  } = useSession();
  const [selected, setSelected] = useState<CrashFile | null>(null);
  const [loading, setLoading] = useState(true);
  const [crashReadError, setCrashReadError] = useState<string | null>(null);
  const [pocStates, setPocStates] = useState<Record<string, PocState>>({});

  useEffect(() => {
    if (!filePath) return;
    const corpusDir = filePath.replace(/[/\\][^/\\]+$/, "") + "/.guzzle/crashes";
    (async () => {
      try {
        const files = await readCrashFiles(corpusDir);
        setCrashes(files);
      } catch (e) {
        setCrashReadError(`Could not re-read crash files from disk — showing in-memory results. (${String(e)})`);
      } finally {
        setLoading(false);
      }
    })();
  }, [filePath, setCrashes]);

  const openFolder = async () => {
    if (!filePath) return;
    const dir = filePath.replace(/[/\\][^/\\]+$/, "") + "/.guzzle";
    await revealInFinder(dir);
  };

  const reproduceCmd = selected
    ? `${compiledBinaryPath ?? "./fuzzer"} ${selected.path}`
    : "";

  const setPocState = (crashPath: string, update: Partial<PocState>) => {
    setPocStates((prev) => ({
      ...prev,
      [crashPath]: { ...(prev[crashPath] ?? { status: "idle", log: [], script: null, error: null }), ...update },
    }));
  };

  const appendPocLog = (crashPath: string, line: string) => {
    setPocStates((prev) => {
      const cur = prev[crashPath] ?? { status: "idle", log: [], script: null, error: null };
      return { ...prev, [crashPath]: { ...cur, log: [...cur.log, line] } };
    });
  };

  const handleGenPoc = async (crash: CrashFile) => {
    if (!filePath || !harnessSource || !functionSignature || !aiProvider) return;

    const isHeader = /\.(h|hpp)$/i.test(filePath);
    const targetFiles = isHeader ? [] : [filePath];

    setPocState(crash.path, { status: "running", log: [], script: null, error: null });

    let unlisten: (() => void) | null = null;
    try {
      unlisten = await listen<string>("poc_log", (e) => {
        appendPocLog(crash.path, e.payload);
      });

      const script = await generatePoc({
        crashPath: crash.path,
        harnessSource,
        targetFiles,
        includes: compileSettings.includes,
        libraryFiles: compileSettings.library_files,
        clangOverride: compileSettings.clang_override || undefined,
        provider: aiProvider,
        functionSignature,
      });

      setPocState(crash.path, { status: "done", script });
    } catch (e) {
      const msg = String(e);
      setPocState(crash.path, { status: "error", error: msg });
      appendPocLog(crash.path, `ERROR: ${msg}`);
    } finally {
      unlisten?.();
    }
  };

  const copyScript = (script: string) => {
    navigator.clipboard.writeText(script).catch(() => {});
  };

  const poc = selected ? (pocStates[selected.path] ?? { status: "idle", log: [], script: null, error: null }) : null;

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-[#e6edf3]">Results</h2>
          <p className="text-sm text-[#8b949e] mt-1">
            Fuzzing session complete.{" "}
            {crashes.length === 0
              ? "No crashes found — great sign!"
              : `${crashes.length} crash${crashes.length !== 1 ? "es" : ""} discovered.`}
          </p>
        </div>
        <button onClick={openFolder} className="text-xs text-[#58a6ff] hover:underline">
          Open .guzzle/ folder →
        </button>
      </div>

      {crashReadError && (
        <div className="bg-[#3d2f00] border border-[#d29922] rounded-md p-2 text-xs text-[#d29922]">
          ⚠ {crashReadError}
        </div>
      )}

      {loading ? (
        <div className="flex items-center gap-3 py-8 justify-center">
          <div className="w-5 h-5 border-2 border-[#58a6ff] border-t-transparent rounded-full animate-spin" />
          <span className="text-sm text-[#8b949e]">Loading crash files…</span>
        </div>
      ) : crashes.length === 0 ? (
        <div className="bg-[#0d2818] border border-[#3fb950] rounded-lg p-6 text-center">
          <p className="text-4xl mb-3">🎉</p>
          <p className="text-[#3fb950] font-semibold">No crashes found</p>
          <p className="text-sm text-[#8b949e] mt-1">
            The fuzzer ran without discovering any crashes. Corpus is saved in{" "}
            <code className="font-mono text-xs">.guzzle/corpus/</code>
          </p>
        </div>
      ) : (
        <div className="flex gap-4" style={{ minHeight: 300 }}>
          {/* Crash list */}
          <div className="w-48 flex-shrink-0 flex flex-col gap-1 overflow-y-auto" style={{ maxHeight: 400 }}>
            <p className="text-xs text-[#8b949e] uppercase tracking-wider mb-1 sticky top-0 bg-[#0d1117]">Crashes</p>
            {crashes.map((c) => (
              <button
                key={c.path}
                onClick={() => setSelected(c)}
                className={`text-left px-3 py-2 rounded-md text-xs font-mono truncate transition-colors flex-shrink-0 ${
                  selected?.path === c.path
                    ? "bg-[#30363d] text-[#e6edf3]"
                    : "text-[#8b949e] hover:bg-[#21262d]"
                }`}
              >
                {c.path.split(/[/\\]/).pop()}
                <span className="block text-[10px] text-[#8b949e]">{c.size}B · {timeAgo(c.modified_secs)}</span>
              </button>
            ))}
          </div>

          {/* Crash detail */}
          <div className="flex-1 flex flex-col gap-3 min-w-0">
            {selected ? (
              <>
                <HexDump bytes={selected.preview_bytes} />

                <div>
                  <p className="text-xs text-[#8b949e] mb-1">Reproduce command:</p>
                  <code className="block bg-[#21262d] rounded p-2 text-xs font-mono text-[#e6edf3] break-all">
                    {reproduceCmd}
                  </code>
                </div>

                {/* Gen PoC button */}
                <div className="flex flex-col gap-1.5">
                  <div className="flex items-center gap-3">
                    <button
                      onClick={() => handleGenPoc(selected)}
                      disabled={poc?.status === "running"}
                      className="px-3 py-1.5 bg-[#21262d] hover:bg-[#30363d] border border-[#30363d] text-xs text-[#e6edf3] rounded-md transition-colors disabled:opacity-40 flex items-center gap-2"
                    >
                      {poc?.status === "running" && (
                        <div className="w-3 h-3 border-2 border-[#58a6ff] border-t-transparent rounded-full animate-spin" />
                      )}
                      {poc?.status === "running" ? "Generating PoC…" : "Gen PoC"}
                    </button>
                    <span className="text-[10px] text-[#8b949e]">
                      Requires <code className="font-mono">radare2</code> (macOS/Windows) or <code className="font-mono">ROPgadget</code> / <code className="font-mono">ropper</code> (Linux)
                    </span>
                  </div>
                  <p className="text-[10px] text-[#8b949e]">
                    Uses AI ({aiProvider.name}) to generate a pwntools exploit script — same provider and API key as harness generation.
                  </p>
                </div>

                {/* PoC progress log */}
                {poc && poc.log.length > 0 && (
                  <Terminal lines={poc.log} className="max-h-52" />
                )}

                {/* PoC error */}
                {poc?.status === "error" && poc.error && (
                  <div className="bg-[#3d1414] border border-[#f85149] rounded-md p-3 text-xs text-[#f85149] whitespace-pre-wrap">
                    {poc.error.includes("No ROP gadget tool found") ? (
                      <>
                        <p className="font-semibold mb-1">ROP tool not found</p>
                        <p className="mb-1">macOS: <code>brew install radare2</code></p>
                        <p>Linux: <code>pip3 install ROPgadget</code> or <code>pip3 install ropper</code></p>
                      </>
                    ) : (
                      poc.error
                    )}
                  </div>
                )}

                {/* Generated PoC script */}
                {poc?.status === "done" && poc.script && (
                  <div className="flex flex-col gap-2">
                    <div className="flex items-center justify-between">
                      <p className="text-xs text-[#8b949e]">Generated pwntools script:</p>
                      <button
                        onClick={() => copyScript(poc.script!)}
                        className="text-xs text-[#58a6ff] hover:underline"
                      >
                        Copy
                      </button>
                    </div>
                    <div className="rounded-lg overflow-hidden border border-[#30363d]">
                      <MonacoEditor
                        height="300px"
                        language="python"
                        value={poc.script}
                        theme="vs-dark"
                        options={{
                          fontSize: 12,
                          minimap: { enabled: false },
                          scrollBeyondLastLine: false,
                          readOnly: true,
                          wordWrap: "off",
                        }}
                      />
                    </div>
                    <div className="bg-[#161b22] border border-[#30363d] rounded-md p-3 flex flex-col gap-2 text-[11px] text-[#8b949e]">
                      <p className="text-[#e6edf3] font-semibold">How to use this script</p>
                      <ol className="flex flex-col gap-1.5 list-decimal list-inside">
                        <li>Save with the <span className="text-[#e6edf3]">Copy</span> button → <code className="font-mono">nano exploit.py</code> → paste</li>
                        <li>Install pwntools if needed: <code className="font-mono">pip3 install pwntools</code></li>
                        <li>Enable core dumps: <code className="font-mono">ulimit -c unlimited</code></li>
                        <li>Disable ASLR: <code className="font-mono">echo 0 | sudo tee /proc/sys/kernel/randomize_va_space</code></li>
                        <li>Run: <code className="font-mono">python3 exploit.py</code></li>
                      </ol>
                      <p className="mt-1">
                        <span className="text-[#f0883e] font-medium">Exits with code 0?</span>{" "}
                        The crash was caught by ASan but didn't produce a native SIGSEGV — common with small heap overflows.
                        Confirm the bug is real by running with ASan:{" "}
                        <code className="font-mono">clang++ -O0 -g -fsanitize=address harness.cpp target.c reproducer_main.c -o asan_repro && ./asan_repro crash_file</code>
                      </p>
                      <p>Most useful for <span className="text-[#e6edf3]">stack-buffer-overflow</span>. Heap/UAF/double-free won't yield a traditional ROP chain. Offsets and libc addresses usually need manual tuning.</p>
                    </div>
                  </div>
                )}
              </>
            ) : (
              <div className="flex items-center justify-center h-full text-sm text-[#8b949e]">
                Select a crash to view details
              </div>
            )}
          </div>
        </div>
      )}

      <div className="flex justify-end">
        <button
          onClick={onClose}
          className="px-4 py-2 bg-[#21262d] hover:bg-[#30363d] text-[#e6edf3] text-sm font-medium rounded-md transition-colors"
        >
          Close
        </button>
      </div>
    </div>
  );
}
