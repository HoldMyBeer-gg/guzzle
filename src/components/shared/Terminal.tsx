import { memo, useEffect, useRef } from "react";
import type { KeyboardEvent } from "react";

interface TerminalProps {
  lines: string[];
  className?: string;
  // When true, the terminal fills its flex parent's height instead of using the
  // default fixed height — used on the Results screen so the analysis/next-steps
  // log fills the frame rather than hiding in a short strip.
  fill?: boolean;
}

// Color ANSI codes to spans
function colorize(str: string): React.ReactNode[] {
  const parts: React.ReactNode[] = [];
  const regex = /(\x1b\[[0-9;]*m)/g;
  let last = 0;
  let currentStyle: React.CSSProperties = {};
  let key = 0;

  str.replace(regex, (match, _code, offset) => {
    if (offset > last) {
      parts.push(
        <span key={key++} style={currentStyle}>
          {str.slice(last, offset)}
        </span>
      );
    }
    // Parse basic ANSI codes
    const codes = match.slice(2, -1).split(";").map(Number);
    for (const code of codes) {
      if (code === 0) currentStyle = {};
      else if (code === 1) currentStyle = { ...currentStyle, fontWeight: "bold" };
      else if (code === 31) currentStyle = { ...currentStyle, color: "#f85149" };
      else if (code === 32) currentStyle = { ...currentStyle, color: "#3fb950" };
      else if (code === 33) currentStyle = { ...currentStyle, color: "#d29922" };
      else if (code === 34) currentStyle = { ...currentStyle, color: "#58a6ff" };
      else if (code === 35) currentStyle = { ...currentStyle, color: "#bc8cff" };
      else if (code === 36) currentStyle = { ...currentStyle, color: "#39c5cf" };
    }
    last = offset + match.length;
    return match;
  });

  if (last < str.length) {
    parts.push(
      <span key={key++} style={currentStyle}>
        {str.slice(last)}
      </span>
    );
  }

  return parts.length > 0 ? parts : [<span key={0}>{str}</span>];
}

export default memo(function Terminal({ lines, className = "", fill = false }: TerminalProps) {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Scroll only THIS container to its bottom. Using scrollIntoView here would
    // bubble to scroll ancestors and drag the whole panel down (past the log,
    // onto the script), so set scrollTop directly instead.
    const el = containerRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [lines]);

  const handleKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === "a" && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      const el = containerRef.current;
      if (!el) return;
      const range = document.createRange();
      range.selectNodeContents(el);
      const sel = window.getSelection();
      sel?.removeAllRanges();
      sel?.addRange(range);
    }
  };

  return (
    <div
      ref={containerRef}
      tabIndex={0}
      onKeyDown={handleKeyDown}
      className={`font-mono text-xs leading-5 overflow-auto bg-[#0d1117] rounded-lg border border-[#30363d] p-3 focus:outline-none focus:ring-1 focus:ring-[#58a6ff] ${fill ? "h-full min-h-0" : ""} ${className}`}
      style={fill ? undefined : { height: 260 }}
    >
      {lines.length === 0 ? (
        <span className="text-[#8b949e]">No output yet…</span>
      ) : (
        lines.map((line, i) => (
          <div key={i} className="whitespace-pre-wrap break-all">
            {colorize(line)}
          </div>
        ))
      )}
    </div>
  );
});
