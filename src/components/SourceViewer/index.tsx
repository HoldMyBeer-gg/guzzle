import { useCallback, useEffect, useRef, useState } from "react";
import MonacoEditor from "@monaco-editor/react";
import { useSession } from "../../store/session";
import { parseFunctionAtLine } from "../../lib/tauri";
import FunctionBanner from "./FunctionBanner";

export default function SourceViewer() {
  const { fileContent, filePath, functionSignature, setSelectedLine, setFunctionSignature, openWizard } =
    useSession();
  const [detecting, setDetecting] = useState(false);
  const [parseError, setParseError] = useState<string | null>(null);
  const detectTimeout = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Always-current ref so the Monaco cursor listener (registered once at mount)
  // never holds a stale closure over filePath.
  const filePathRef = useRef(filePath);
  useEffect(() => { filePathRef.current = filePath; }, [filePath]);

  // Reset detecting state whenever the file changes so we never get stuck.
  useEffect(() => { setDetecting(false); }, [filePath]);

  const handleLineClick = useCallback(
    (lineNumber: number) => {
      const currentPath = filePathRef.current;
      if (!currentPath) return;
      setSelectedLine(lineNumber);

      if (detectTimeout.current) clearTimeout(detectTimeout.current);

      detectTimeout.current = setTimeout(async () => {
        setDetecting(true);
        setFunctionSignature(null);
        try {
          const sig = await parseFunctionAtLine(currentPath, lineNumber);
          setFunctionSignature(sig);
          setParseError(null);
        } catch (e) {
          setFunctionSignature(null);
          setParseError(`Parse error: ${String(e)}`);
        } finally {
          setDetecting(false);
        }
      }, 200);
    },
    [setSelectedLine, setFunctionSignature]
  );

  const handleEditorMount = useCallback(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (editor: any) => {
      editor.onDidChangeCursorPosition((e: { position: { lineNumber: number } }) => {
        handleLineClick(e.position.lineNumber);
      });
    },
    [handleLineClick]
  );

  const language = filePath?.endsWith(".c") ? "c" : "cpp";

  return (
    <div className="flex-1 flex flex-col min-h-0">
      {parseError && (
        <div className="px-4 py-1.5 bg-[#3d1414] border-b border-[#f85149] text-xs text-[#f85149] font-mono">
          {parseError}
        </div>
      )}
      <div className="flex-1 min-h-0">
        <MonacoEditor
          height="100%"
          language={language}
          value={fileContent ?? "// Open a C/C++ file to get started"}
          theme="vs-dark"
          options={{
            readOnly: true,
            minimap: { enabled: true },
            fontSize: 13,
            lineNumbers: "on",
            scrollBeyondLastLine: false,
            wordWrap: "off",
            renderLineHighlight: "all",
          }}
          onMount={handleEditorMount}
        />
      </div>
      <FunctionBanner
        signature={functionSignature}
        loading={detecting}
        onFuzz={() => {
          if (functionSignature) openWizard();
        }}
      />
    </div>
  );
}
