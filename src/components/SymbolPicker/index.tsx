import { useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { readTextFile } from "@tauri-apps/plugin-fs";
import { useSession } from "../../store/session";

export default function SymbolPicker() {
  const {
    binaryPath,
    exportedSymbols,
    symbolsLoading,
    symbolFilter,
    selectedSymbolName,
    setSymbolFilter,
    setSelectedSymbolName,
    setCompanionHeaderContent,
    openWizard,
  } = useSession();

  const [showAll, setShowAll] = useState(false);
  const [headerName, setHeaderName] = useState<string | null>(null);

  const filename = binaryPath ? binaryPath.split(/[\\/]/).pop() : "binary";

  const filtered = exportedSymbols.filter((s) => {
    if (!showAll && !s.is_function) return false;
    if (!symbolFilter) return true;
    return s.name.toLowerCase().includes(symbolFilter.toLowerCase());
  });

  const handleFuzz = (name: string) => {
    setSelectedSymbolName(name);
    openWizard();
  };

  const handleAddHeader = async () => {
    const selected = await open({
      filters: [{ name: "C/C++ Header", extensions: ["h", "hpp"] }],
      multiple: false,
    });
    if (typeof selected === "string") {
      const content = await readTextFile(selected);
      setCompanionHeaderContent(content);
      setHeaderName(selected.split(/[\\/]/).pop() ?? selected);
    }
  };

  return (
    <div className="flex flex-col h-full">
      {/* Header bar */}
      <div className="px-4 py-3 bg-[#161b22] border-b border-[#30363d] flex items-center gap-3">
        <div className="flex-1 min-w-0">
          <span className="font-semibold text-[#e6edf3] font-mono truncate block">{filename}</span>
          {symbolsLoading ? (
            <span className="text-xs text-[#8b949e]">Loading symbols…</span>
          ) : (
            <span className="text-xs text-[#8b949e]">
              {exportedSymbols.length} symbols
              {" · "}
              {exportedSymbols.filter((s) => s.is_function).length} functions
            </span>
          )}
        </div>

        {/* Companion header */}
        <button
          onClick={handleAddHeader}
          title="Add a companion .h header so the AI knows exact function signatures"
          className="px-2.5 py-1.5 bg-[#21262d] hover:bg-[#30363d] border border-[#30363d] text-xs text-[#8b949e] hover:text-[#e6edf3] rounded-md transition-colors whitespace-nowrap"
        >
          {headerName ? `Header: ${headerName}` : "Add companion header (.h)"}
        </button>
      </div>

      {/* Toolbar */}
      <div className="px-4 py-2 flex items-center gap-3 border-b border-[#30363d] bg-[#0d1117]">
        <input
          value={symbolFilter}
          onChange={(e) => setSymbolFilter(e.target.value)}
          placeholder="Filter symbols…"
          className="flex-1 bg-[#21262d] border border-[#30363d] rounded-md px-3 py-1.5 text-sm text-[#e6edf3] font-mono focus:outline-none focus:border-[#58a6ff]"
        />
        <label className="flex items-center gap-2 text-xs text-[#8b949e] whitespace-nowrap cursor-pointer select-none">
          <input
            type="checkbox"
            checked={showAll}
            onChange={(e) => setShowAll(e.target.checked)}
            className="accent-[#58a6ff]"
          />
          Show all symbols
        </label>
      </div>

      {/* Symbol list */}
      <div className="flex-1 overflow-y-auto">
        {symbolsLoading ? (
          <div className="flex items-center justify-center h-full gap-3">
            <div className="w-5 h-5 border-2 border-[#58a6ff] border-t-transparent rounded-full animate-spin" />
            <span className="text-sm text-[#8b949e]">Extracting symbols…</span>
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex items-center justify-center h-full">
            <span className="text-sm text-[#8b949e]">
              {symbolFilter ? "No symbols match the filter." : "No exported functions found."}
            </span>
          </div>
        ) : (
          <table className="w-full text-sm font-mono">
            <tbody>
              {filtered.map((sym) => (
                <tr
                  key={sym.raw_name}
                  className={`border-b border-[#21262d] hover:bg-[#161b22] transition-colors ${
                    selectedSymbolName === sym.name ? "bg-[#1a2332]" : ""
                  }`}
                >
                  <td className="px-4 py-2 text-[#e6edf3] truncate max-w-xs">
                    {sym.name}
                  </td>
                  <td className="px-2 py-2 text-[#8b949e] text-xs w-8 text-center">
                    {sym.symbol_type}
                  </td>
                  <td className="px-4 py-2 w-32 text-right">
                    <button
                      onClick={() => handleFuzz(sym.name)}
                      className="px-2.5 py-1 bg-[#238636] hover:bg-[#2ea043] text-white text-xs rounded-md transition-colors"
                    >
                      ⚡ Fuzz this →
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
