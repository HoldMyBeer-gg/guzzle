import { useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { readTextFile } from "@tauri-apps/plugin-fs";
import { useSession } from "./store/session";
import { resolveIncludes, extractSymbols } from "./lib/tauri";
import { isBinaryFile, BINARY_EXTENSIONS } from "./lib/fileUtils";
import SourceViewer from "./components/SourceViewer";
import SymbolPicker from "./components/SymbolPicker";
import Wizard from "./components/Wizard";

async function afterOpen(
  path: string,
  content: string,
  setFilePath: (p: string, c: string) => void,
  updateCompileSettings: (s: { includes: string[] }) => void,
  setResolvedHeaders: (h: string[]) => void,
) {
  setFilePath(path, content);
  try {
    const result = await resolveIncludes(path);
    if (result.include_dirs.length > 0) {
      updateCompileSettings({ includes: result.include_dirs });
    }
    if (result.available_headers.length > 0) {
      setResolvedHeaders(result.available_headers);
    }
  } catch (e) {
    // Non-fatal — resolve failure just means no auto-detected includes
    console.warn("resolveIncludes failed:", e);
  }
}

function HomePage({ onOpen }: { onOpen: () => void }) {
  const {
    recentFiles,
    setFilePath,
    addRecentFile,
    updateCompileSettings,
    setResolvedHeaders,
    setBinaryMode,
    setExportedSymbols,
    setSymbolsLoading,
  } = useSession();
  const [recentError, setRecentError] = useState<string | null>(null);

  const openRecent = async (path: string) => {
    setRecentError(null);
    try {
      if (isBinaryFile(path)) {
        setBinaryMode(true, path);
        setSymbolsLoading(true);
        try {
          const result = await extractSymbols(path);
          setExportedSymbols(result.symbols);
        } finally {
          setSymbolsLoading(false);
        }
      } else {
        const content = await readTextFile(path);
        setBinaryMode(false, null);
        await afterOpen(path, content, setFilePath, updateCompileSettings, setResolvedHeaders);
      }
      addRecentFile(path);
    } catch (e) {
      console.error("Failed to open recent file", e);
      setRecentError(`Could not open ${path.split("/").pop()}: ${String(e)}`);
    }
  };

  return (
    <div className="flex-1 flex flex-col items-center justify-center gap-8 p-8">
      <div className="text-center">
        <h1 className="text-4xl font-bold text-[#e6edf3] mb-2">
          ⚡ Guzzle
        </h1>
        <p className="text-[#8b949e] text-lg">
          libFuzzer made easy — open a C/C++ source file or a binary library and fuzz any function in minutes.
        </p>
      </div>

      <button
        onClick={onOpen}
        className="px-8 py-4 bg-[#238636] hover:bg-[#2ea043] text-white font-semibold rounded-xl text-lg transition-colors shadow-lg"
      >
        Open File…
      </button>

      {recentError && (
        <p className="text-sm text-[#f85149] max-w-md text-center">{recentError}</p>
      )}

      {recentFiles.length > 0 && (
        <div className="w-full max-w-md">
          <p className="text-xs text-[#8b949e] uppercase tracking-wider mb-3">Recent Files</p>
          <div className="flex flex-col gap-1">
            {recentFiles.map((f) => (
              <button
                key={f}
                onClick={() => openRecent(f)}
                className="text-left px-4 py-2.5 bg-[#161b22] hover:bg-[#21262d] border border-[#30363d] rounded-lg text-sm text-[#e6edf3] font-mono truncate transition-colors"
              >
                {f}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function Header({ filePath, onOpen }: { filePath: string | null; onOpen: () => void }) {
  return (
    <div className="flex items-center justify-between px-4 py-2 bg-[#161b22] border-b border-[#30363d]">
      <div className="flex items-center gap-3">
        <span className="font-bold text-[#e6edf3]">⚡ Guzzle</span>
        {filePath && (
          <>
            <span className="text-[#30363d]">/</span>
            <span className="text-sm text-[#8b949e] font-mono truncate max-w-xs">
              {filePath.split("/").pop()}
            </span>
          </>
        )}
      </div>
      <button
        onClick={onOpen}
        className="px-3 py-1.5 bg-[#21262d] hover:bg-[#30363d] border border-[#30363d] text-sm text-[#e6edf3] rounded-md transition-colors"
      >
        Open file…
      </button>
    </div>
  );
}


export default function App() {
  const {
    filePath,
    isBinaryMode,
    setFilePath,
    addRecentFile,
    updateCompileSettings,
    setResolvedHeaders,
    setBinaryMode,
    setExportedSymbols,
    setSymbolsLoading,
  } = useSession();

  const [openError, setOpenError] = useState<string | null>(null);

  const afterOpenBinary = async (path: string) => {
    setBinaryMode(true, path);
    setSymbolsLoading(true);
    setOpenError(null);
    try {
      const result = await extractSymbols(path);
      setExportedSymbols(result.symbols);
    } catch (e) {
      setOpenError(`Failed to extract symbols: ${String(e)}`);
    } finally {
      setSymbolsLoading(false);
    }
  };

  const handleOpen = async () => {
    setOpenError(null);
    try {
      const selected = await open({
        filters: [
          { name: "C/C++ Files", extensions: ["c", "cpp", "cc", "cxx", "h", "hpp"] },
          { name: "Binary / Library", extensions: BINARY_EXTENSIONS },
          { name: "All Files", extensions: ["*"] },
        ],
        multiple: false,
      });
      if (typeof selected === "string") {
        if (isBinaryFile(selected)) {
          await afterOpenBinary(selected);
          addRecentFile(selected);
        } else {
          const content = await readTextFile(selected);
          setBinaryMode(false, null);
          await afterOpen(selected, content, setFilePath, updateCompileSettings, setResolvedHeaders);
          addRecentFile(selected);
        }
      }
    } catch (e) {
      setOpenError(`Could not open file: ${String(e)}`);
    }
  };

  // Effective path for the header (binary mode uses binaryPath, source mode uses filePath)
  const { binaryPath } = useSession();
  const displayPath = isBinaryMode ? binaryPath : filePath;
  const hasFile = isBinaryMode ? !!binaryPath : !!filePath;

  return (
    <div className="flex flex-col h-screen">
      {hasFile && <Header filePath={displayPath} onOpen={handleOpen} />}
      {openError && (
        <div className="px-4 py-2 bg-[#3d1414] border-b border-[#f85149] text-sm text-[#f85149]">
          {openError}
        </div>
      )}
      {hasFile
        ? isBinaryMode
          ? <SymbolPicker />
          : <SourceViewer />
        : <HomePage onOpen={handleOpen} />}
      <Wizard />
    </div>
  );
}
