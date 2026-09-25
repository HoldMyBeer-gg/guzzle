import { useState } from "react";
import { useSession } from "../../store/session";
import { compileHarness } from "../../lib/tauri";
import { listen } from "@tauri-apps/api/event";
import { open } from "@tauri-apps/plugin-dialog";
import Terminal from "../shared/Terminal";

interface Props {
  onBack: () => void;
  onNext: () => void;
}

const SANITIZERS = [
  { id: "fuzzer", label: "-fsanitize=fuzzer", required: true },
  { id: "address", label: "-fsanitize=address (ASan)", required: false },
  { id: "undefined", label: "-fsanitize=undefined (UBSan)", required: false },
];

export default function CompileSettings({ onBack, onNext }: Props) {
  const {
    filePath,
    harnessSource,
    compileSettings,
    compiledBinaryPath,
    compileLog,
    updateCompileSettings,
    setCompiledBinaryPath,
    appendCompileLog,
    clearCompileLog,
    isBinaryMode,
    binaryPath,
  } = useSession();

  const [compiling, setCompiling] = useState(false);
  const [includeInput, setIncludeInput] = useState("");
  const [compileError, setCompileError] = useState(false);

  const toggleSanitizer = (id: string) => {
    if (id === "fuzzer") return; // required
    const current = compileSettings.sanitizers;
    const updated = current.includes(id)
      ? current.filter((s) => s !== id)
      : [...current, id];
    updateCompileSettings({ sanitizers: updated });
  };

  const addInclude = () => {
    const val = includeInput.trim();
    if (val && !compileSettings.includes.includes(val)) {
      updateCompileSettings({ includes: [...compileSettings.includes, val] });
      setIncludeInput("");
    }
  };

  const removeInclude = (path: string) => {
    updateCompileSettings({ includes: compileSettings.includes.filter((i) => i !== path) });
  };

  const addLibraryFile = async () => {
    const selected = await open({
      filters: [{ name: "Library Files", extensions: ["a", "so", "dylib", "lib"] }],
      multiple: true,
    });
    if (!selected) return;
    const paths = Array.isArray(selected) ? selected : [selected];
    const merged = [...new Set([...compileSettings.library_files, ...paths])];
    updateCompileSettings({ library_files: merged });
  };

  const removeLibraryFile = (path: string) => {
    updateCompileSettings({ library_files: compileSettings.library_files.filter((l) => l !== path) });
  };

  const runCompile = async () => {
    if (!harnessSource) return;
    if (!isBinaryMode && !filePath) return;
    setCompiling(true);
    setCompileError(false);
    clearCompileLog();
    setCompiledBinaryPath(null);

    let unlisten: (() => void) | null = null;
    try {
      unlisten = await listen<string>("compile_output", (e) => {
        appendCompileLog(e.payload);
      });

      let targetFiles: string[];
      let settings = compileSettings;

      if (isBinaryMode && binaryPath) {
        // Binary mode: no source target files; auto-inject the opened binary into library_files
        targetFiles = [];
        const alreadyLinked = settings.library_files.includes(binaryPath);
        if (!alreadyLinked) {
          settings = { ...settings, library_files: [binaryPath, ...settings.library_files] };
        }
      } else {
        // Source mode: headers aren't compiled as source
        const isHeader = /\.(h|hpp)$/i.test(filePath!);
        targetFiles = isHeader ? [] : [filePath!];
      }

      const compiledPath = await compileHarness({
        harness: harnessSource,
        targetFiles,
        settings,
      });
      setCompiledBinaryPath(compiledPath);
    } catch (e) {
      appendCompileLog(`\nError: ${String(e)}`);
      setCompileError(true);
    } finally {
      setCompiling(false);
      unlisten?.();
    }
  };

  return (
    <div className="flex flex-col gap-5">
      <div>
        <h2 className="text-lg font-semibold text-[#e6edf3]">Compile Settings</h2>
        <p className="text-sm text-[#8b949e] mt-1">
          Configure sanitizers and compiler options, then compile the fuzzer binary.
        </p>
      </div>

      {/* Sanitizers */}
      <div>
        <label className="block text-xs text-[#8b949e] uppercase tracking-wider mb-2">Sanitizers</label>
        <div className="flex flex-col gap-2">
          {SANITIZERS.map((san) => (
            <label key={san.id} className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={compileSettings.sanitizers.includes(san.id)}
                onChange={() => toggleSanitizer(san.id)}
                disabled={san.required}
                className="w-4 h-4 accent-[#58a6ff]"
              />
              <span className="text-sm font-mono text-[#e6edf3]">{san.label}</span>
              {san.required && (
                <span className="text-xs text-[#8b949e]">(required)</span>
              )}
            </label>
          ))}
        </div>
      </div>

      {/* Include paths */}
      <div>
        <label className="block text-xs text-[#8b949e] uppercase tracking-wider mb-2">Include Paths</label>
        <div className="flex gap-2 mb-2">
          <input
            value={includeInput}
            onChange={(e) => setIncludeInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && addInclude()}
            placeholder="/path/to/headers"
            className="flex-1 bg-[#21262d] border border-[#30363d] rounded-md px-3 py-1.5 text-sm text-[#e6edf3] font-mono focus:outline-none focus:border-[#58a6ff]"
          />
          <button
            onClick={addInclude}
            className="px-3 py-1.5 bg-[#21262d] hover:bg-[#30363d] border border-[#30363d] text-sm text-[#e6edf3] rounded-md"
          >
            Add
          </button>
        </div>
        {compileSettings.includes.map((inc) => (
          <div key={inc} className="flex items-center gap-2 mb-1">
            <code className="text-xs text-[#8b949e] font-mono flex-1">{inc}</code>
            <button onClick={() => removeInclude(inc)} className="text-[#f85149] text-xs hover:underline">
              remove
            </button>
          </div>
        ))}
      </div>

      {/* Library files */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <label className="text-xs text-[#8b949e] uppercase tracking-wider">
            Link Libraries
            <span className="normal-case text-[#8b949e] ml-2 text-[10px]">(pre-built .a / .so / .dylib)</span>
          </label>
          <button
            onClick={addLibraryFile}
            className="text-xs text-[#58a6ff] hover:underline"
          >
            + Add library
          </button>
        </div>
        {/* In binary mode, show the opened binary as a locked auto entry */}
        {isBinaryMode && binaryPath && (
          <div className="flex items-center gap-2 mb-1">
            <code className="text-xs text-[#e6edf3] font-mono flex-1 truncate">{binaryPath}</code>
            <span className="text-[10px] text-[#8b949e] bg-[#21262d] border border-[#30363d] rounded px-1.5 py-0.5 flex-shrink-0">
              auto — opened binary
            </span>
          </div>
        )}
        {compileSettings.library_files.length === 0 && !(isBinaryMode && binaryPath) ? (
          <p className="text-xs text-[#8b949e] italic">
            None — add pre-built libraries to fuzz against (e.g. libssl.a)
          </p>
        ) : (
          compileSettings.library_files
            .filter((lib) => !(isBinaryMode && lib === binaryPath))
            .map((lib) => (
              <div key={lib} className="flex items-center gap-2 mb-1">
                <code className="text-xs text-[#e6edf3] font-mono flex-1 truncate">{lib}</code>
                <button onClick={() => removeLibraryFile(lib)} className="text-[#f85149] text-xs hover:underline flex-shrink-0">
                  remove
                </button>
              </div>
            ))
        )}
      </div>

      {/* Extra flags */}
      <div>
        <label className="block text-xs text-[#8b949e] uppercase tracking-wider mb-2">Extra Compiler Flags</label>
        <input
          value={compileSettings.extra_flags}
          onChange={(e) => updateCompileSettings({ extra_flags: e.target.value })}
          placeholder="-O1 -g"
          className="w-full bg-[#21262d] border border-[#30363d] rounded-md px-3 py-1.5 text-sm text-[#e6edf3] font-mono focus:outline-none focus:border-[#58a6ff]"
        />
      </div>

      {/* Compile output */}
      {compileLog.length > 0 && (
        <Terminal lines={compileLog} className="max-h-40" />
      )}

      {compileError && (
        <div className="bg-[#3d1414] border border-[#f85149] rounded-md p-3 text-sm text-[#f85149]">
          Compilation failed. Check the output above and fix harness or settings.
        </div>
      )}

      {compiledBinaryPath && !compileError && (
        <div className="bg-[#0d2818] border border-[#3fb950] rounded-md p-3 text-sm text-[#3fb950]">
          ✓ Binary compiled: <code className="font-mono text-xs">{compiledBinaryPath}</code>
        </div>
      )}

      <div className="flex justify-between">
        <button
          onClick={onBack}
          className="px-4 py-2 bg-[#21262d] hover:bg-[#30363d] text-[#e6edf3] text-sm font-medium rounded-md transition-colors"
        >
          ← Back
        </button>
        <div className="flex gap-2">
          <button
            onClick={runCompile}
            disabled={compiling}
            className="px-4 py-2 bg-[#21262d] hover:bg-[#30363d] border border-[#30363d] text-[#e6edf3] text-sm font-medium rounded-md transition-colors disabled:opacity-40"
          >
            {compiling ? "Compiling…" : "Test Compile"}
          </button>
          <button
            onClick={onNext}
            disabled={!compiledBinaryPath || compileError}
            className="px-4 py-2 bg-[#238636] hover:bg-[#2ea043] disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm font-medium rounded-md transition-colors"
          >
            Start Fuzzing →
          </button>
        </div>
      </div>
    </div>
  );
}
