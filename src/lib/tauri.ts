import { invoke } from "@tauri-apps/api/core";
import type {
  FunctionSignature,
  ToolchainInfo,
  CompileSettings,
  CrashFile,
  AiProvider,
  ExportedSymbol,
} from "../store/session";

export type { ExportedSymbol };

export interface SymbolList {
  symbols: ExportedSymbol[];
  tool_used: string;
  binary_path: string;
}

export interface FuzzerArgs {
  binary: string;
  corpus_dir: string;
  max_total_time: number;
  jobs: number;
  extra_flags: string;
}

export async function checkToolchain(): Promise<ToolchainInfo> {
  return invoke("check_toolchain");
}

export async function checkToolchainAt(clangPath: string): Promise<ToolchainInfo> {
  return invoke("check_toolchain_at", { clangPath });
}

export async function parseFunctionAtLine(
  filePath: string,
  lineNumber: number
): Promise<FunctionSignature | null> {
  return invoke("parse_function_at_line", { filePath, lineNumber });
}

export async function generateHarness(
  provider: AiProvider,
  signature: FunctionSignature,
  contextLines: string,
  includeHints?: string[]
): Promise<string> {
  return invoke("generate_harness", { provider, signature, contextLines, includeHints });
}

export interface ResolvedIncludes {
  include_dirs: string[];
  available_headers: string[];
  unresolved: string[];
}

export async function resolveIncludes(filePath: string): Promise<ResolvedIncludes> {
  return invoke("resolve_includes", { filePath });
}

export async function compileHarness(args: {
  harness: string;
  targetFiles: string[];
  settings: CompileSettings;
}): Promise<string> {
  return invoke("compile_harness", args);
}

export async function startFuzzer(args: FuzzerArgs): Promise<number> {
  return invoke("start_fuzzer", { args });
}

export async function stopFuzzer(pid: number): Promise<void> {
  return invoke("stop_fuzzer", { pid });
}

export async function readCrashFiles(corpusDir: string): Promise<CrashFile[]> {
  return invoke("read_crash_files", { corpusDir });
}

export async function saveApiKey(providerName: string, key: string): Promise<void> {
  return invoke("save_api_key", { providerName, key });
}

export async function loadApiKey(providerName: string): Promise<string | null> {
  return invoke("load_api_key", { providerName });
}

export async function revealInFinder(path: string): Promise<void> {
  return invoke("reveal_in_finder", { path });
}

export async function getCachedHarness(filePath: string, functionName: string): Promise<string | null> {
  return invoke("get_cached_harness", { filePath, functionName });
}

export async function saveCachedHarness(filePath: string, functionName: string, harness: string): Promise<void> {
  return invoke("save_cached_harness", { filePath, functionName, harness });
}

export async function extractSymbols(binaryPath: string): Promise<SymbolList> {
  return invoke("extract_symbols", { binaryPath });
}

export async function generateHarnessBinary(
  provider: AiProvider,
  symbolName: string,
  companionHeaderContent: string | null,
  includeHints?: string[]
): Promise<string> {
  return invoke("generate_harness_binary", { provider, symbolName, companionHeaderContent, includeHints });
}

export async function generatePoc(args: {
  crashPath: string;
  harnessSource: string;
  targetFiles: string[];
  includes: string[];
  libraryFiles: string[];
  clangOverride?: string;
  provider: AiProvider;
  functionSignature: FunctionSignature;
}): Promise<string> {
  return invoke("generate_poc", args);
}
