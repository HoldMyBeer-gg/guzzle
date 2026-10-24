import { describe, it, expect } from "vitest";
import { stepStatus, stepAccessibleLabel } from "./StepIndicator";

describe("stepStatus", () => {
  it("classifies steps relative to the current index", () => {
    // current index = 2
    expect(stepStatus(0, 2)).toBe("done");
    expect(stepStatus(1, 2)).toBe("done");
    expect(stepStatus(2, 2)).toBe("current");
    expect(stepStatus(3, 2)).toBe("upcoming");
  });
});

describe("stepAccessibleLabel", () => {
  it("numbers from 1 and annotates state for a screenreader", () => {
    expect(stepAccessibleLabel(0, 2, "Toolchain")).toBe("Step 1: Toolchain (completed)");
    expect(stepAccessibleLabel(2, 2, "Compile")).toBe("Step 3: Compile (current step)");
    expect(stepAccessibleLabel(3, 2, "Fuzzing")).toBe("Step 4: Fuzzing");
  });
});
