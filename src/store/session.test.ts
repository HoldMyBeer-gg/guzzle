import { beforeEach, describe, it, expect } from "vitest";
import { useSession, partializeState, PRESET_PROVIDERS, type ExportedSymbol } from "./session";

// Reset the relevant slice of store state before each test to prevent leakage.
// We only reset fields touched by these tests — simple passthrough setters
// have no logic and are not tested here.
beforeEach(() => {
  localStorage.clear();
  useSession.setState({
    recentFiles: [],
    wizardOpen: false,
    wizardStep: "toolchain",
    compileLog: [],
    fuzzerOutput: [],
    fuzzerStats: null,
    crashes: [],
    compiledBinaryPath: null,
    isBinaryMode: false,
    binaryPath: null,
    exportedSymbols: [],
    symbolsLoading: false,
    symbolFilter: "",
    selectedSymbolName: null,
    companionHeaderContent: null,
    harnessSource: "",
    functionSignature: null,
    aiProvider: PRESET_PROVIDERS[0],
  });
});

// ── addRecentFile ────────────────────────────────────────────────────────────

describe("addRecentFile", () => {
  it("prepends to an empty list", () => {
    useSession.getState().addRecentFile("/a/b/c.c");
    expect(useSession.getState().recentFiles).toEqual(["/a/b/c.c"]);
  });

  it("prepends new entries to the front", () => {
    useSession.getState().addRecentFile("/first.c");
    useSession.getState().addRecentFile("/second.c");
    expect(useSession.getState().recentFiles[0]).toBe("/second.c");
    expect(useSession.getState().recentFiles[1]).toBe("/first.c");
  });

  it("deduplicates — moves existing entry to front, no duplicate", () => {
    useSession.getState().addRecentFile("/a.c");
    useSession.getState().addRecentFile("/b.c");
    useSession.getState().addRecentFile("/a.c"); // already in list
    const { recentFiles } = useSession.getState();
    expect(recentFiles).toEqual(["/a.c", "/b.c"]);
    expect(recentFiles.filter((f) => f === "/a.c")).toHaveLength(1);
  });

  it("caps the list at 10 entries", () => {
    for (let i = 1; i <= 11; i++) {
      useSession.getState().addRecentFile(`/file${i}.c`);
    }
    const { recentFiles } = useSession.getState();
    expect(recentFiles).toHaveLength(10);
    expect(recentFiles[0]).toBe("/file11.c");   // newest at front
    expect(recentFiles[9]).toBe("/file2.c");    // oldest kept
    // file1 was the first added — it should be dropped
    expect(recentFiles.includes("/file1.c")).toBe(false);
  });
});

// ── openWizard ───────────────────────────────────────────────────────────────

describe("openWizard", () => {
  it("opens the wizard and resets transient state", () => {
    useSession.setState({
      wizardOpen: false,
      wizardStep: "results",
      compileLog: ["line1"],
      fuzzerOutput: ["out"],
      fuzzerStats: { execs_per_sec: 1, coverage: 1, corpus_size: 1, run_time_secs: 1, total_execs: 1 },
      crashes: [{ path: "/crash", size: 1, preview_bytes: [], modified_secs: 0 }],
      compiledBinaryPath: "/bin/fuzzer",
    });

    useSession.getState().openWizard();
    const s = useSession.getState();

    expect(s.wizardOpen).toBe(true);
    expect(s.wizardStep).toBe("toolchain");
    expect(s.compileLog).toEqual([]);
    expect(s.fuzzerOutput).toEqual([]);
    expect(s.fuzzerStats).toBeNull();
    expect(s.crashes).toEqual([]);
    expect(s.compiledBinaryPath).toBeNull();
  });

  it("is a no-op when the wizard is already open", () => {
    useSession.setState({ wizardOpen: true, wizardStep: "compile" });
    useSession.getState().openWizard();
    // Step must not be reset to "toolchain"
    expect(useSession.getState().wizardStep).toBe("compile");
  });
});

// ── appendFuzzerOutput ───────────────────────────────────────────────────────

describe("appendFuzzerOutput", () => {
  it("appends to an empty buffer", () => {
    useSession.getState().appendFuzzerOutput("hello");
    expect(useSession.getState().fuzzerOutput).toEqual(["hello"]);
  });

  it("keeps buffer at 500 lines when appending past the cap", () => {
    // Fill to 500
    useSession.setState({ fuzzerOutput: Array.from({ length: 500 }, (_, i) => `line${i}`) });
    useSession.getState().appendFuzzerOutput("new");
    expect(useSession.getState().fuzzerOutput).toHaveLength(500);
    expect(useSession.getState().fuzzerOutput[499]).toBe("new");
    // Oldest line (line0) should have been dropped
    expect(useSession.getState().fuzzerOutput[0]).toBe("line1");
  });

  it("does not exceed 500 lines under continuous appending", () => {
    for (let i = 0; i < 600; i++) {
      useSession.getState().appendFuzzerOutput(`line${i}`);
    }
    expect(useSession.getState().fuzzerOutput.length).toBeLessThanOrEqual(500);
  });
});

// ── setBinaryMode ────────────────────────────────────────────────────────────

describe("setBinaryMode", () => {
  const dummySymbol: ExportedSymbol = {
    name: "compress2", raw_name: "_compress2", symbol_type: "T", is_function: true,
  };

  it("activating binary mode sets path and clears all symbol + harness state", () => {
    // Set up populated source-mode state
    useSession.setState({
      isBinaryMode: false,
      exportedSymbols: [dummySymbol],
      symbolsLoading: true,
      symbolFilter: "compress",
      selectedSymbolName: "compress2",
      companionHeaderContent: "#include <zlib.h>",
      harnessSource: "int LLVMFuzzerTestOneInput(...) {}",
      functionSignature: { name: "foo", return_type: "int", params: [], start_line: 1, end_line: 5 },
    });

    useSession.getState().setBinaryMode(true, "/usr/lib/libz.dylib");
    const s = useSession.getState();

    expect(s.isBinaryMode).toBe(true);
    expect(s.binaryPath).toBe("/usr/lib/libz.dylib");
    expect(s.exportedSymbols).toEqual([]);
    expect(s.symbolsLoading).toBe(false);
    expect(s.symbolFilter).toBe("");
    expect(s.selectedSymbolName).toBeNull();
    expect(s.companionHeaderContent).toBeNull();
    expect(s.harnessSource).toBe("");
    expect(s.functionSignature).toBeNull();
  });

  it("deactivating binary mode resets the same fields", () => {
    useSession.setState({
      isBinaryMode: true,
      binaryPath: "/usr/lib/libz.dylib",
      exportedSymbols: [dummySymbol],
      selectedSymbolName: "compress2",
      harnessSource: "// harness",
    });

    useSession.getState().setBinaryMode(false, null);
    const s = useSession.getState();

    expect(s.isBinaryMode).toBe(false);
    expect(s.binaryPath).toBeNull();
    expect(s.exportedSymbols).toEqual([]);
    expect(s.selectedSymbolName).toBeNull();
    expect(s.harnessSource).toBe("");
  });
});

// ── partializeState (persistence security) ───────────────────────────────────

describe("partializeState", () => {
  const fullState = () => useSession.getState();

  it("excludes api_key from the persisted provider", () => {
    useSession.setState({ aiProvider: { ...PRESET_PROVIDERS[0], api_key: "sk-supersecret" } });
    const persisted = partializeState(fullState());
    expect(persisted.aiProvider.api_key).toBe("");
  });

  it("excludes exportedSymbols", () => {
    const dummySymbol: ExportedSymbol = {
      name: "compress2", raw_name: "_compress2", symbol_type: "T", is_function: true,
    };
    useSession.setState({ exportedSymbols: [dummySymbol] });
    const persisted = partializeState(fullState());
    expect("exportedSymbols" in persisted).toBe(false);
  });

  it("includes isBinaryMode and binaryPath", () => {
    useSession.setState({ isBinaryMode: true, binaryPath: "/usr/lib/libz.dylib" });
    const persisted = partializeState(fullState());
    expect(persisted.isBinaryMode).toBe(true);
    expect(persisted.binaryPath).toBe("/usr/lib/libz.dylib");
  });

  it("persists recentFiles, compileSettings, fuzzerTimeoutSecs, fuzzerExtraFlags", () => {
    useSession.setState({ recentFiles: ["/a.c"], fuzzerTimeoutSecs: 120, fuzzerExtraFlags: "-rss_limit_mb=2048" });
    const persisted = partializeState(fullState());
    expect(persisted.recentFiles).toEqual(["/a.c"]);
    expect(persisted.fuzzerTimeoutSecs).toBe(120);
    expect(persisted.fuzzerExtraFlags).toBe("-rss_limit_mb=2048");
  });
});
