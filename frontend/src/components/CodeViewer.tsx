import Editor, { type OnMount } from "@monaco-editor/react";
import { useCallback, useEffect, useRef } from "react";

import { Spinner } from "@/components/ui";
import { useFileContent } from "@/hooks/useScans";
import { monacoLanguage } from "@/lib/format";

type MonacoEditor = Parameters<OnMount>[0];
type Monaco = Parameters<OnMount>[1];

export interface CodeMarker {
  line: number;
  message?: string;
}

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

    // Collect every line that has a finding (deduped, keeping a message).
    const lines = new Map<number, string | undefined>();
    (markers ?? []).forEach((m) => {
      if (m.line && m.line > 0) lines.set(m.line, m.message);
    });
    if (highlightLine && highlightLine > 0 && !lines.has(highlightLine)) {
      lines.set(highlightLine, undefined);
    }

    decorationsRef.current = ed.deltaDecorations(
      decorationsRef.current,
      [...lines.entries()].map(([line, message]) => ({
        range: new monaco.Range(line, 1, line, 1),
        options: {
          isWholeLine: true,
          className: "bg-rose-100",
          marginClassName: "bg-rose-200",
          linesDecorationsClassName: "border-l-2 border-rose-500",
          overviewRuler: {
            color: "rgba(225, 29, 72, 0.85)",
            position: monaco.editor.OverviewRulerLane.Full,
          },
          ...(message ? { hoverMessage: { value: message } } : {}),
        },
      })),
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
