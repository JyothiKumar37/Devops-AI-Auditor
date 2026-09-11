import Editor, { type OnMount } from "@monaco-editor/react";
import { useCallback, useRef } from "react";

import { Spinner } from "@/components/ui";
import { useFileContent } from "@/hooks/useScans";
import { monacoLanguage } from "@/lib/format";

type MonacoEditor = Parameters<OnMount>[0];
type Monaco = Parameters<OnMount>[1];

interface CodeViewerProps {
  scanId: string;
  fileId: string | null;
  path?: string;
  fileType?: string;
  highlightLine?: number | null;
}

export function CodeViewer({ scanId, fileId, path, fileType, highlightLine }: CodeViewerProps) {
  const { data, isLoading, isError } = useFileContent(scanId, fileId);
  const editorRef = useRef<MonacoEditor | null>(null);
  const decorationsRef = useRef<string[]>([]);

  const applyHighlight = useCallback(
    (ed: MonacoEditor, monaco: Monaco) => {
      if (!highlightLine) return;
      decorationsRef.current = ed.deltaDecorations(decorationsRef.current, [
        {
          range: new monaco.Range(highlightLine, 1, highlightLine, 1),
          options: {
            isWholeLine: true,
            className: "bg-amber-400/15",
            marginClassName: "bg-amber-400/40",
            linesDecorationsClassName: "border-l-2 border-amber-400",
          },
        },
      ]);
      ed.revealLineInCenter(highlightLine);
      ed.setPosition({ lineNumber: highlightLine, column: 1 });
    },
    [highlightLine],
  );

  const onMount: OnMount = (ed, monaco) => {
    editorRef.current = ed;
    applyHighlight(ed, monaco);
  };

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
      <div className="grid h-full min-h-[24rem] place-items-center text-sm text-rose-300">
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
      theme="vs-dark"
      language={monacoLanguage(fileType ?? data.file_type, path ?? data.path)}
      value={data.content}
      onMount={onMount}
      options={{
        readOnly: true,
        minimap: { enabled: false },
        fontSize: 13,
        lineNumbers: "on",
        scrollBeyondLastLine: false,
        renderLineHighlight: "none",
        padding: { top: 12, bottom: 12 },
      }}
    />
  );
}
