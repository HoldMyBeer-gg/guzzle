import { useEffect, useState } from "react";
import { useSession } from "../../store/session";
import StepIndicator from "../shared/StepIndicator";
import ToolchainCheck from "./ToolchainCheck";
import HarnessEditor from "./HarnessEditor";
import CompileSettings from "./CompileSettings";
import FuzzerRunning from "./FuzzerRunning";
import Results from "./Results";
import type { FunctionSignature } from "../../store/session";

export default function Wizard() {
  const {
    wizardOpen,
    wizardStep,
    setWizardStep,
    closeWizard,
    functionSignature,
    isBinaryMode,
    selectedSymbolName,
  } = useSession();

  // Lock the signature at open time so the background Monaco editor's cursor
  // events (which temporarily null out functionSignature during re-parses)
  // don't unmount and reset the wizard mid-session.
  const [lockedSig, setLockedSig] = useState<FunctionSignature | null>(functionSignature);
  useEffect(() => {
    if (functionSignature) setLockedSig(functionSignature);
    if (!wizardOpen) setLockedSig(null);
  }, [wizardOpen, functionSignature]);

  // In binary mode we don't need a function signature — just a selected symbol name.
  const canOpen = isBinaryMode ? !!selectedSymbolName : !!lockedSig;
  if (!wizardOpen || !canOpen) return null;

  const subtitle = isBinaryMode ? `${selectedSymbolName}()` : `${lockedSig!.name}()`;

  const goTo = (step: typeof wizardStep) => setWizardStep(step);

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div
        className="bg-[#161b22] border border-[#30363d] rounded-xl shadow-2xl w-full max-w-2xl flex flex-col max-h-[90vh]"
        style={{ minHeight: 520 }}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#30363d]">
          <div className="flex items-center gap-3">
            <span className="text-lg">⚡</span>
            <span className="font-semibold text-[#e6edf3]">Fuzz Wizard</span>
            <span className="text-sm text-[#8b949e]">— {subtitle}</span>
          </div>
          <button
            onClick={closeWizard}
            className="text-[#8b949e] hover:text-[#e6edf3] text-xl leading-none transition-colors"
          >
            ×
          </button>
        </div>

        {/* Step indicator */}
        <div className="px-6 pt-5 pb-3 flex justify-center">
          <StepIndicator current={wizardStep} onGoTo={goTo} />
        </div>

        {/* Step content */}
        <div className="flex-1 overflow-y-auto px-6 pb-6">
          {wizardStep === "toolchain" && (
            <ToolchainCheck onNext={() => goTo("harness")} onClose={closeWizard} />
          )}
          {wizardStep === "harness" && (
            <HarnessEditor
              onBack={() => goTo("toolchain")}
              onNext={() => goTo("compile")}
            />
          )}
          {wizardStep === "compile" && (
            <CompileSettings
              onBack={() => goTo("harness")}
              onNext={() => goTo("running")}
            />
          )}
          {wizardStep === "running" && (
            <FuzzerRunning
              onBack={() => goTo("compile")}
              onNext={() => goTo("results")}
            />
          )}
          {wizardStep === "results" && (
            <Results onClose={closeWizard} />
          )}
        </div>
      </div>
    </div>
  );
}
