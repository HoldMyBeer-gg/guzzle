import { memo, useEffect, useRef, useState } from "react";
import { useSession } from "../../store/session";
import { startFuzzer, stopFuzzer } from "../../lib/tauri";
import { listen } from "@tauri-apps/api/event";
import { open } from "@tauri-apps/plugin-dialog";
import Terminal from "../shared/Terminal";
import type { FuzzerStats } from "../../store/session";

interface Props {
  onBack: () => void;
  onNext: () => void;
}

const StatBadge = memo(function StatBadge({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-[#21262d] rounded-lg px-4 py-3 text-center">
      <p className="text-[10px] text-[#8b949e] uppercase tracking-wider">{label}</p>
      <p className="text-lg font-bold text-[#e6edf3] mt-0.5">{value}</p>
    </div>
  );
});

function fmtTime(secs: number): string {
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = Math.floor(secs % 60);
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export default function FuzzerRunning({ onBack, onNext }: Props) {
  const {
    compiledBinaryPath,
    filePath,
    fuzzerPid,
    fuzzerOutput,
    fuzzerStats,
    crashes,
    fuzzerTimeoutSecs,
    fuzzerExtraFlags,
    setFuzzerPid,
    appendFuzzerOutput,
    clearFuzzerOutput,
    setFuzzerStats,
    setCrashes,
    appendCrash,
    setFuzzerTimeoutSecs,
    setFuzzerExtraFlags,
  } = useSession();

  const startedRef = useRef(false);
  // Track active event-listener cleanup fns so we can tear them down on unmount
  // even if the fuzzer_stopped event hasn't fired yet (e.g. user navigates away).
  const unlistenRef = useRef<Array<() => void>>([]);
  useEffect(() => {
    return () => {
      unlistenRef.current.forEach(fn => fn());
      unlistenRef.current = [];
    };
  }, []);

  const [running, setRunning] = useState(false);
  const [seedDir, setSeedDir] = useState<string | null>(null);

  const defaultCorpusDir = filePath
    ? filePath.replace(/[/\\][^/\\]+$/, "") + "/.guzzle/corpus"
    : "/tmp/guzzle_corpus";

  const corpusDir = seedDir ?? defaultCorpusDir;

  const startFuzzing = async () => {
    if (!compiledBinaryPath) return;
    clearFuzzerOutput();
    setCrashes([]);
    setFuzzerStats(null);
    setRunning(true);

    // Clean up any listeners left over from a previous run that ended without
    // a fuzzer_stopped event (e.g. user navigated away before the process exited).
    unlistenRef.current.forEach(fn => fn());
    unlistenRef.current = [];

    // Buffer lines and flush every 150ms to avoid hammering React with
    // thousands of state updates per second from libFuzzer's output
    let outputBuffer: string[] = [];
    const flushInterval = setInterval(() => {
      if (outputBuffer.length === 0) return;
      outputBuffer.forEach(appendFuzzerOutput);
      outputBuffer = [];
    }, 150);

    const cleanup = () => {
      clearInterval(flushInterval);
      outputBuffer.forEach(appendFuzzerOutput);
      outputBuffer = [];
      unlistenRef.current.forEach(fn => fn());
      unlistenRef.current = [];
    };

    const unlistenOutput = await listen<string>("fuzzer_output", (e) => {
      outputBuffer.push(e.payload);
    });
    const unlistenCrash = await listen<{ path: string; size: number; preview_bytes: number[]; modified_secs: number }>(
      "fuzzer_crash",
      (e) => {
        appendCrash(e.payload);
      }
    );
    let lastStats = 0;
    const unlistenStats = await listen<FuzzerStats>("fuzzer_stats", (e) => {
      const now = Date.now();
      if (now - lastStats < 500) return;
      lastStats = now;
      setFuzzerStats(e.payload);
    });
    const unlistenStopped = await listen("fuzzer_stopped", () => {
      setRunning(false);
      setFuzzerPid(null);
      cleanup();
    });

    unlistenRef.current = [unlistenOutput, unlistenCrash, unlistenStats, unlistenStopped];

    try {
      const pid = await startFuzzer({
        binary: compiledBinaryPath,
        corpus_dir: corpusDir,
        max_total_time: fuzzerTimeoutSecs,
        jobs: 1,
        extra_flags: fuzzerExtraFlags,
      });
      setFuzzerPid(pid);
    } catch (e) {
      appendFuzzerOutput(`Error starting fuzzer: ${String(e)}`);
      setRunning(false);
    }
  };


  const handleStop = async () => {
    if (fuzzerPid) {
      await stopFuzzer(fuzzerPid);
    }
    setRunning(false);
    setFuzzerPid(null);
    onNext();
  };

  const pickSeedDir = async () => {
    const dir = await open({ directory: true, multiple: false });
    if (typeof dir === "string") setSeedDir(dir);
  };

  return (
    <div className="flex flex-col gap-4 h-full">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-[#e6edf3]">Fuzzer Running</h2>
          <p className="text-sm text-[#8b949e] mt-1">
            Corpus: <code className="text-xs font-mono text-[#8b949e]">{corpusDir}</code>
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <label className="text-xs text-[#8b949e]">Timeout</label>
            <input
              type="number"
              min={0}
              value={fuzzerTimeoutSecs}
              onChange={(e) => setFuzzerTimeoutSecs(Math.max(0, parseInt(e.target.value) || 0))}
              disabled={running}
              className="w-14 bg-[#161b22] border border-[#30363d] rounded px-2 py-0.5 text-xs text-[#e6edf3] font-mono focus:outline-none focus:border-[#58a6ff] disabled:opacity-50"
            />
            <span className="text-xs text-[#8b949e]">sec (0=∞)</span>
          </div>
          {running ? (
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 bg-[#3fb950] rounded-full animate-pulse" />
              <span className="text-xs text-[#3fb950] font-medium">Running</span>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 bg-[#8b949e] rounded-full" />
              <span className="text-xs text-[#8b949e] font-medium">Stopped</span>
            </div>
          )}
        </div>
      </div>

      <div className="flex items-center gap-3">
        <button
          onClick={pickSeedDir}
          disabled={running}
          className="text-xs text-[#58a6ff] hover:underline disabled:opacity-50"
        >
          + Seed corpus
        </button>
        <div className="flex items-center gap-1.5 flex-1">
          <label className="text-xs text-[#8b949e] shrink-0">Flags</label>
          <input
            type="text"
            value={fuzzerExtraFlags}
            onChange={(e) => setFuzzerExtraFlags(e.target.value)}
            disabled={running}
            placeholder="-max_len=65536 -rss_limit_mb=2048"
            className="flex-1 bg-[#161b22] border border-[#30363d] rounded px-2 py-0.5 text-xs text-[#e6edf3] font-mono focus:outline-none focus:border-[#58a6ff] disabled:opacity-50 placeholder-[#484f58]"
          />
        </div>
      </div>

      <div className="grid grid-cols-4 gap-3">
        <StatBadge label="Execs/sec" value={fuzzerStats ? fuzzerStats.execs_per_sec.toLocaleString() : "—"} />
        <StatBadge label="Coverage"  value={fuzzerStats ? `${fuzzerStats.coverage}` : "—"} />
        <StatBadge label="Corpus"    value={fuzzerStats ? `${fuzzerStats.corpus_size}` : "—"} />
        <StatBadge label="Run Time"  value={fuzzerStats ? fmtTime(fuzzerStats.run_time_secs) : "—"} />
      </div>

      <div className={`rounded-md text-sm flex items-center justify-between transition-colors ${
        crashes.length > 0
          ? "p-3 bg-[#3d1414] border border-[#f85149] text-[#f85149]"
          : "h-0 overflow-hidden"
      }`}>
        <span>🐛 {crashes.length} crash{crashes.length !== 1 ? "es" : ""} found!</span>
        <button onClick={crashes.length > 0 ? onNext : undefined} className="underline text-xs">View results →</button>
      </div>

      <Terminal lines={fuzzerOutput} className="flex-1 min-h-0" />

      <div className="flex justify-between">
        <button
          onClick={onBack}
          disabled={running}
          className="px-4 py-2 bg-[#21262d] hover:bg-[#30363d] disabled:opacity-40 text-[#e6edf3] text-sm font-medium rounded-md transition-colors"
        >
          ← Back
        </button>
        <div className="flex gap-2">
          {!running && !startedRef.current && (
            <button
              onClick={() => { startedRef.current = true; startFuzzing(); }}
              className="px-4 py-2 bg-[#238636] hover:bg-[#2ea043] text-white text-sm font-medium rounded-md transition-colors"
            >
              ▶ Start Fuzzing
            </button>
          )}
          {!running && startedRef.current && (
            <button
              onClick={onNext}
              className="px-4 py-2 bg-[#21262d] hover:bg-[#30363d] border border-[#30363d] text-[#e6edf3] text-sm font-medium rounded-md transition-colors"
            >
              View Results →
            </button>
          )}
          {running && (
            <button
              onClick={handleStop}
              className="px-4 py-2 bg-[#da3633] hover:bg-[#b91c1c] text-white text-sm font-medium rounded-md transition-colors"
            >
              ■ Stop & View Results
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
