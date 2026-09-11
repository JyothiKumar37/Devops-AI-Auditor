import { useCallback, useRef, useState } from "react";

import { ACCEPTED_EXTENSIONS, MAX_UPLOAD_MB, formatBytes } from "@/lib/format";
import { useUploadScan } from "@/hooks/useScans";
import type { ScanSummary } from "@/types/api";

interface UploadPanelProps {
  onUploaded: (scan: ScanSummary) => void;
}

const MAX_BYTES = MAX_UPLOAD_MB * 1024 * 1024;

function validate(file: File): string | null {
  const hasAllowedExt = ACCEPTED_EXTENSIONS.some((ext) =>
    file.name.toLowerCase().endsWith(ext),
  );
  if (!hasAllowedExt) {
    return `Unsupported file type. Allowed: ${ACCEPTED_EXTENSIONS.join(", ")}`;
  }
  if (file.size > MAX_BYTES) {
    return `File is too large (${formatBytes(file.size)}). Maximum is ${MAX_UPLOAD_MB} MB.`;
  }
  return null;
}

export function UploadPanel({ onUploaded }: UploadPanelProps) {
  const [progress, setProgress] = useState(0);
  const [dragging, setDragging] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);
  const [fileName, setFileName] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const upload = useUploadScan((fraction) => setProgress(fraction));

  const handleFile = useCallback(
    (file: File) => {
      setLocalError(null);
      const validationError = validate(file);
      if (validationError) {
        setLocalError(validationError);
        return;
      }
      setFileName(file.name);
      setProgress(0);
      upload.mutate(file, {
        onSuccess: (scan) => {
          setProgress(1);
          onUploaded(scan);
        },
      });
    },
    [upload, onUploaded],
  );

  const onDrop = useCallback(
    (event: React.DragEvent<HTMLDivElement>) => {
      event.preventDefault();
      setDragging(false);
      const file = event.dataTransfer.files?.[0];
      if (file) handleFile(file);
    },
    [handleFile],
  );

  const busy = upload.isPending;
  const serverError = upload.isError ? (upload.error as Error).message : null;

  return (
    <section className="rounded-xl border border-white/10 bg-surface-soft/60 p-5">
      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">
          Upload Repository
        </h2>
        <span className="text-xs text-slate-500">source: ZIP</span>
      </div>

      <div
        role="button"
        tabIndex={0}
        onClick={() => inputRef.current?.click()}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") inputRef.current?.click();
        }}
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        className={`flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed px-6 py-10 text-center transition ${
          dragging
            ? "border-brand bg-brand/5"
            : "border-white/15 hover:border-brand/50 hover:bg-white/5"
        } ${busy ? "pointer-events-none opacity-60" : ""}`}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".zip,application/zip"
          className="hidden"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) handleFile(file);
            e.target.value = "";
          }}
        />
        <svg
          className="mb-3 h-8 w-8 text-slate-400"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth={1.5}
          aria-hidden
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M12 16.5V9m0 0L8.25 12.75M12 9l3.75 3.75M3 16.5v1.875A2.625 2.625 0 005.625 21h12.75A2.625 2.625 0 0021 18.375V16.5"
          />
        </svg>
        <p className="text-sm font-medium text-slate-200">
          Drag & drop a repository ZIP, or click to browse
        </p>
        <p className="mt-1 text-xs text-slate-500">
          Supported: {ACCEPTED_EXTENSIONS.join(", ")} · Max {MAX_UPLOAD_MB} MB
        </p>
      </div>

      {(busy || progress > 0) && fileName ? (
        <div className="mt-4">
          <div className="mb-1 flex items-center justify-between text-xs text-slate-400">
            <span className="truncate">{fileName}</span>
            <span>{Math.round(progress * 100)}%</span>
          </div>
          <div className="h-2 overflow-hidden rounded-full bg-white/10">
            <div
              className="h-full rounded-full bg-brand transition-all"
              style={{ width: `${Math.round(progress * 100)}%` }}
            />
          </div>
          {busy ? (
            <p className="mt-2 text-xs text-slate-500">
              Uploading and running discovery…
            </p>
          ) : null}
        </div>
      ) : null}

      {localError || serverError ? (
        <p className="mt-4 rounded-lg bg-rose-500/10 px-3 py-2 text-sm text-rose-300 ring-1 ring-inset ring-rose-500/30">
          {localError ?? serverError}
        </p>
      ) : null}
    </section>
  );
}
