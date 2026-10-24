import type { WizardStep } from "../../store/session";

const STEPS: { key: WizardStep; label: string }[] = [
  { key: "toolchain", label: "Toolchain" },
  { key: "harness", label: "Harness" },
  { key: "compile", label: "Compile" },
  { key: "running", label: "Fuzzing" },
  { key: "results", label: "Results" },
];

export type StepState = "done" | "current" | "upcoming";

// Pure: where a step sits relative to the current one.
export function stepStatus(index: number, currentIndex: number): StepState {
  if (index < currentIndex) return "done";
  if (index === currentIndex) return "current";
  return "upcoming";
}

// Pure: the screenreader label, carrying state that's otherwise only conveyed
// by colour and a checkmark glyph.
export function stepAccessibleLabel(index: number, currentIndex: number, label: string): string {
  const status = stepStatus(index, currentIndex);
  const suffix = status === "done" ? " (completed)" : status === "current" ? " (current step)" : "";
  return `Step ${index + 1}: ${label}${suffix}`;
}

interface StepIndicatorProps {
  current: WizardStep;
  onGoTo?: (step: WizardStep) => void;
}

export default function StepIndicator({ current, onGoTo }: StepIndicatorProps) {
  const currentIdx = STEPS.findIndex((s) => s.key === current);

  return (
    <div className="flex items-center gap-0" role="list" aria-label="Wizard progress">
      {STEPS.map((step, idx) => {
        const status = stepStatus(idx, currentIdx);
        const done = status === "done";
        const active = status === "current";
        const clickable = done && !!onGoTo;
        const label = stepAccessibleLabel(idx, currentIdx, step.label);

        const circleClasses = `w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold border-2 transition-all ${
          done
            ? "bg-[#3fb950] border-[#3fb950] text-black"
            : active
            ? "bg-transparent border-[#58a6ff] text-[#58a6ff]"
            : "bg-transparent border-[#30363d] text-[#8b949e]"
        } ${clickable ? "cursor-pointer hover:opacity-75" : ""}`;

        return (
          <div
            key={step.key}
            className="flex items-center"
            role="listitem"
            aria-current={active ? "step" : undefined}
          >
            <div className="flex flex-col items-center">
              {clickable ? (
                <button
                  onClick={() => onGoTo!(step.key)}
                  aria-label={`Go to ${label}`}
                  className={`${circleClasses} focus:outline-none focus:ring-2 focus:ring-[#58a6ff]`}
                >
                  <span aria-hidden="true">{done ? "✓" : idx + 1}</span>
                </button>
              ) : (
                <div className={circleClasses} aria-label={label}>
                  <span aria-hidden="true">{done ? "✓" : idx + 1}</span>
                </div>
              )}
              <span
                onClick={() => clickable && onGoTo!(step.key)}
                aria-hidden="true"
                className={`mt-1 text-[10px] font-medium ${
                  active ? "text-[#58a6ff]" : done ? "text-[#3fb950]" : "text-[#8b949e]"
                } ${clickable ? "cursor-pointer hover:opacity-75" : ""}`}
              >
                {step.label}
              </span>
            </div>
            {idx < STEPS.length - 1 && (
              <div
                aria-hidden="true"
                className={`h-0.5 w-10 mx-1 mb-4 transition-all ${
                  done ? "bg-[#3fb950]" : "bg-[#30363d]"
                }`}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}
