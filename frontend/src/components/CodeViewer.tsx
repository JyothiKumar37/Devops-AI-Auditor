import Editor, { type OnMount } from "@monaco-editor/react";
import { useCallback, useEffect, useRef } from "react";

import { Spinner } from "@/components/ui";
import { useFileContent } from "@/hooks/useScans";
import { monacoLanguage } from "@/lib/format";

type MonacoEditor = Parameters<OnMount>[0];
type Monaco = Parameters<OnMount>[1];

export interface CodeMarker {
  line: number;
  severity?: string;
  message?: string;
}

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

// Per-severity editor decoration styling (static classes so Tailwind keeps them).
const SEVERITY_DECOR: Record<
  string,
  { line: string; margin: string; border: string; ruler: string }
> = {
  critical: { line: "bg-rose-100", margin: "bg-rose-200", border: "border-rose-500", ruler: "rgba(225,29,72,0.85)" },
  high: { line: "bg-orange-100", margin: "bg-orange-200", border: "border-orange-500", ruler: "rgba(234,88,12,0.85)" },
  medium: { line: "bg-amber-100", margin: "bg-amber-200", border: "border-amber-500", ruler: "rgba(217,119,6,0.85)" },
  low: { line: "bg-sky-100", margin: "bg-sky-200", border: "border-sky-500", ruler: "rgba(2,132,199,0.8)" },
  info: { line: "bg-slate-100", margin: "bg-slate-200", border: "border-slate-400", ruler: "rgba(100,116,139,0.7)" },
};

const DEFAULT_DECOR = {
  line: "bg-rose-100",
  margin: "bg-rose-200",
  border: "border-rose-500",
  ruler: "rgba(225,29,72,0.85)",
};

interface CodeViewerProps {
  scanId: string;
  fileId: string | null;
  path?: string;
  fileType?: string;
  /** A single line to reveal/focus (e.g. from a finding detail view). */
  highlightLine?: number | null;
  /** All finding lines in the file — highlighted in red. */
  markers?: CodeMarker[];
}

export function CodeViewer({
  scanId,
  fileId,
  path,
  fileType,
  highlightLine,
  markers,
}: CodeViewerProps) {
  const { data, isLoading, isError } = useFileContent(scanId, fileId);
  const editorRef = useRef<MonacoEditor | null>(null);
  const monacoRef = useRef<Monaco | null>(null);
  const decorationsRef = useRef<string[]>([]);

  const applyHighlight = useCallback(() => {
    const ed = editorRef.current;
    const monaco = monacoRef.current;
    if (!ed || !monaco) return;

    // Collect every line that has a finding, keeping the highest severity per
    // line (and counting the rest for the tooltip).
    type LineInfo = { rank: number; severity: string; message?: string; count: number };
    const lines = new Map<number, LineInfo>();
    const add = (line: number, severity: string, message?: string) => {
      if (!line || line <= 0) return;
      const rank = SEVERITY_RANK[severity] ?? 3;
      const cur = lines.get(line);
      if (!cur) {
        lines.set(line, { rank, severity, message, count: 1 });
      } else {
        cur.count += 1;
        if (rank > cur.rank) {
          cur.rank = rank;
          cur.severity = severity;
          cur.message = message;
        }
      }
    };
    (markers ?? []).forEach((m) => add(m.line, m.severity ?? "high", m.message));
    if (highlightLine && highlightLine > 0 && !lines.has(highlightLine)) {
      add(highlightLine, "high", undefined);
    }

    decorationsRef.current = ed.deltaDecorations(
      decorationsRef.current,
      [...lines.entries()].map(([line, info]) => {
        const d = SEVERITY_DECOR[info.severity] ?? DEFAULT_DECOR;
        const message =
          info.count > 1 && info.message ? `${info.message} (+${info.count - 1} more)` : info.message;
        return {
          range: new monaco.Range(line, 1, line, 1),
          options: {
            isWholeLine: true,
            className: d.line,
            marginClassName: d.margin,
            linesDecorationsClassName: `border-l-2 ${d.border}`,
            overviewRuler: {
              color: d.ruler,
              position: monaco.editor.OverviewRulerLane.Full,
            },
            ...(message ? { hoverMessage: { value: message } } : {}),
          },
        };
      }),
    );

    const focus = highlightLine ?? [...lines.keys()].sort((a, b) => a - b)[0];
    if (focus) {
      ed.revealLineInCenter(focus);
      ed.setPosition({ lineNumber: focus, column: 1 });
    }
  }, [markers, highlightLine]);

  const onMount: OnMount = (ed, monaco) => {
    editorRef.current = ed;
    monacoRef.current = monaco;
    decorationsRef.current = [];
    applyHighlight();
  };

  // Re-apply when findings or the loaded content change (they can arrive after mount).
  useEffect(() => {
    applyHighlight();
  }, [applyHighlight, data]);

  if (!fileId) {
    return (
      <div className="grid h-full min-h-[24rem] place-items-center text-sm text-slate-500">
        Select a file to view its contents.
      </div>
    );
  }
  if (isLoading) {
    return (
      <div className="grid h-full min-h-[24rem] place-items-center">
        <Spinner label="Loading file…" />
      </div>
    );
  }
  if (isError || !data) {
    return (
      <div className="grid h-full min-h-[24rem] place-items-center text-sm text-rose-700">
        Could not load this file.
      </div>
    );
  }
  if (data.content === null) {
    return (
      <div className="grid h-full min-h-[24rem] place-items-center text-sm text-slate-500">
        Preview unavailable (binary or oversized file).
      </div>
    );
  }

  return (
    <Editor
      key={fileId}
      height="100%"
      theme="light"
      language={monacoLanguage(fileType ?? data.file_type, path ?? data.path)}
      value={data.content}
      onMount={onMount}
      options={{
        readOnly: true,
        minimap: { enabled: false },
        fontSize: 13,
        lineNumbers: "on",
        glyphMargin: true,
        scrollBeyondLastLine: false,
        renderLineHighlight: "none",
        padding: { top: 12, bottom: 12 },
      }}
    />
  );
}
