import { describe, it, expect } from "vitest";
import { pocResultToState, type PocResult } from "./poc";

describe("pocResultToState", () => {
  it("maps a script result to a done state carrying the script", () => {
    const result: PocResult = { kind: "script", script: "#!/usr/bin/env python3\n" };
    expect(pocResultToState(result)).toEqual({
      status: "done",
      script: "#!/usr/bin/env python3\n",
      verdict: null,
      error: null,
    });
  });

  it("maps a not_exploitable result to a verdict state, not an error", () => {
    const result: PocResult = { kind: "not_exploitable", reason: "exited cleanly (0)" };
    const state = pocResultToState(result);
    expect(state.status).toBe("not_exploitable");
    expect(state.verdict).toBe("exited cleanly (0)");
    // The verdict must NOT be surfaced through the error channel.
    expect(state.error).toBeNull();
    expect(state.script).toBeNull();
  });
});
