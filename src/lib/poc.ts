// Structured result of a PoC attempt, mirroring the Rust `PocResult` enum
// (`#[serde(tag = "kind", rename_all = "snake_case")]`).
export type PocResult =
  | { kind: "script"; script: string }
  | { kind: "not_exploitable"; reason: string };

export type PocStatus = "idle" | "running" | "done" | "error" | "not_exploitable";

export interface PocStateUpdate {
  status: PocStatus;
  script: string | null;
  verdict: string | null;
  error: string | null;
}

// Map a backend PocResult onto a UI state update. A non-reproducing crash is a
// legitimate verdict ("not exploitable"), never routed through the error channel.
export function pocResultToState(result: PocResult): PocStateUpdate {
  if (result.kind === "script") {
    return { status: "done", script: result.script, verdict: null, error: null };
  }
  return { status: "not_exploitable", script: null, verdict: result.reason, error: null };
}
