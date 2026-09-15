import { useCallback, useRef, useState } from "react";

import { ACCEPTED_EXTENSIONS, MAX_UPLOAD_MB, formatBytes } from "@/lib/format";
import { useUploadScan } from "@/hooks/useScans";
import type { ScanSummary } from "@/types/api";

interface UploadPanelProps {
  onUploaded: (scan: ScanSummary) => void;
}

type Mode = "zip" | "folder";

const MAX_BYTES = MAX_UPLOAD_MB * 1024 * 1024;

// Client-side guards for folder uploads (the backend enforces the authoritative
// limits after extraction). Junk/build/vendor directories are skipped so the
// zip stays small and relevant.
const MAX_FOLDER_FILES = 6000;
const MAX_FOLDER_BYTES = 300 * 1024 * 1024;
const MAX_SINGLE_FILE_BYTES = 15 * 1024 * 1024;
const IGNORED_DIRS = new Set([
  "node_modules", ".git", ".svn", ".hg", "dist", "build", ".next", ".nuxt",
  ".output", ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache",
  ".ruff_cache", ".cache", "coverage", ".idea", ".vscode", "target",
  ".terraform", "vendor", ".gradle", ".turbo", ".parcel-cache", ".angular",
]);
const IGNORED_FILES = new Set([".ds_store", "thumbs.db"]);

function validateZip(file: File): string | null {
  const hasAllowedExt = ACCEPTED_EXTENSIONS.some((ext) => file.name.toLowerCase().endsWith(ext));
  if (!hasAllowedExt) return `Unsupported file type. Allowed: ${ACCEPTED_EXTENSIONS.join(", ")}`;
  if (file.size > MAX_BYTES) {
    return `File is too large (${formatBytes(file.size)}). Maximum is ${MAX_UPLOAD_MB} MB.`;
  }
  return null;
}

function isIgnored(relPath: string, file: File): boolean {
  const segments = relPath.split("/");
  const name = (segments[segments.length - 1] ?? "").toLowerCase();
  if (IGNORED_FILES.has(name)) return true;
  if (file.size > MAX_SINGLE_FILE_BYTES) return true;
  return segments.some((segment) => IGNORED_DIRS.has(segment));
}

export function UploadPanel({ onUploaded }: UploadPanelProps) {
  const [mode, setMode] = useState<Mode>("zip");
  const [progress, setProgress] = useState(0);
  const [packFraction, setPackFraction] = useState(0);
  const [phase, setPhase] = useState<"idle" | "packaging" | "uploading">("idle");
  const [dragging, setDragging] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);
  const [label, setLabel] = useState<string | null>(null);

  const zipInputRef = useRef<HTMLInputElement>(null);
  const folderInputRef = useRef<HTMLInputElement | null>(null);

  const upload = useUploadScan((fraction) => setProgress(fraction));
  const busy = upload.isPending || phase === "packaging";

  const startUpload = useCallback(
    (file: File, displayName: string) => {
      setLabel(displayName);
      setProgress(0);
      setPhase("uploading");
      upload.mutate(file, {
        onSuccess: (scan) => {
          setProgress(1);
          setPhase("idle");
          onUploaded(scan);
        },
        onError: () => setPhase("idle"),
      });
    },
    [upload, onUploaded],
  );

  const handleZip = useCallback(
    (file: File) => {
      setLocalError(null);
      const error = validateZip(file);
      if (error) {
        setLocalError(error);
        return;
      }
      startUpload(file, file.name);
    },
    [startUpload],
  );

  const handleFolder = useCallback(
    async (fileList: FileList) => {
      setLocalError(null);
      const all = Array.from(fileList);
      const included = all.filter((f) => !isIgnored(f.webkitRelativePath || f.name, f));

      if (included.length === 0) {
        setLocalError("No analyzable files found in that folder.");
        return;
      }
      if (included.length > MAX_FOLDER_FILES) {
        setLocalError(
          `Folder has too many files (${included.length}). Limit is ${MAX_FOLDER_FILES}.`,
        );
        return;
      }
      const totalBytes = included.reduce((sum, f) => sum + f.size, 0);
      if (totalBytes > MAX_FOLDER_BYTES) {
        setLocalError(
          `Folder is too large (${formatBytes(totalBytes)}). Maximum is ${formatBytes(MAX_FOLDER_BYTES)}.`,
        );
        return;
      }

      const first = included[0];
      const root = (first?.webkitRelativePath || first?.name || "repository").split("/")[0];
      const repoName = root || "repository";

      try {
        setPhase("packaging");
        setPackFraction(0);
        setLabel(`${repoName} · ${included.length} files`);

        // Load the zip library on demand so it stays out of the initial bundle.
        const { default: JSZip } = await import("jszip");
        const zip = new JSZip();
        for (const file of included) {
          zip.file(file.webkitRelativePath || file.name, file);
        }
        const blob = await zip.generateAsync(
          { type: "blob", compression: "DEFLATE", compressionOptions: { level: 6 } },
          (meta) => setPackFraction(meta.percent / 100),
        );

        if (blob.size > MAX_BYTES) {
          setPhase("idle");
          setLocalError(
            `Packaged folder is too large (${formatBytes(blob.size)}). Maximum upload is ${MAX_UPLOAD_MB} MB. Exclude large files and try again.`,
          );
          return;
        }
        const zipFile = new File([blob], `${repoName}.zip`, { type: "application/zip" });
        startUpload(zipFile, `${repoName}.zip`);
      } catch {
        setPhase("idle");
        setLocalError("Could not package the folder. Please try a ZIP instead.");
      }
    },
    [startUpload],
  );

  const onDrop = useCallback(
    (event: React.DragEvent<HTMLDivElement>) => {
      event.preventDefault();
      setDragging(false);
      if (mode !== "zip") return; // folder drag varies by browser; use the picker
      const file = event.dataTransfer.files?.[0];
      if (file) handleZip(file);
    },
    [mode, handleZip],
  );

  const serverError = upload.isError ? (upload.error as Error).message : null;
  const activeFraction = phase === "packaging" ? packFraction : progress;
  const phaseLabel =
    phase === "packaging"
      ? "Packaging folder…"
      : phase === "uploading"
        ? "Uploading and running discovery…"
        : null;

  return (
    <section className="card p-5">
      <div className="mb-4 flex items-center justify-between">
        <h2 className="section-title">Upload repository</h2>
        <div className="flex rounded-lg border border-slate-200 p-0.5 text-xs">
          {(["zip", "folder"] as Mode[]).map((m) => (
            <button
              key={m}
              type="button"
              onClick={() => {
                setMode(m);
                setLocalError(null);
              }}
              className={`rounded-md px-3 py-1 font-medium capitalize transition ${
                mode === m ? "bg-white text-slate-900 shadow-sm ring-1 ring-slate-200" : "text-slate-500 hover:text-slate-800"
              }`}
            >
              {m === "zip" ? "ZIP file" : "Folder"}
            </button>
          ))}
        </div>
      </div>

      <input
        ref={zipInputRef}
        type="file"
        accept=".zip,application/zip"
        className="hidden"
        onChange={(e) => {
          const file = e.target.files?.[0];
          if (file) handleZip(file);
          e.target.value = "";
        }}
      />
      <input
        ref={(el) => {
          folderInputRef.current = el;
          if (el) {
            el.setAttribute("webkitdirectory", "");
            el.setAttribute("directory", "");
          }
        }}
        type="file"
        multiple
        className="hidden"
        onChange={(e) => {
          if (e.target.files && e.target.files.length > 0) void handleFolder(e.target.files);
          e.target.value = "";
        }}
      />

      <div
        role="button"
        tabIndex={0}
        onClick={() => (mode === "zip" ? zipInputRef : folderInputRef).current?.click()}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            (mode === "zip" ? zipInputRef : folderInputRef).current?.click();
          }
        }}
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        className={`flex cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed px-6 py-12 text-center transition ${
          dragging ? "border-brand bg-brand/5" : "border-slate-300 hover:border-brand/50 hover:bg-slate-50"
        } ${busy ? "pointer-events-none opacity-60" : ""}`}
      >
        <svg
          className="mb-3 h-9 w-9 text-slate-500"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth={1.5}
          aria-hidden
        >
          {mode === "folder" ? (
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2V7z"
            />
          ) : (
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M12 16.5V9m0 0L8.25 12.75M12 9l3.75 3.75M3 16.5v1.875A2.625 2.625 0 005.625 21h12.75A2.625 2.625 0 0021 18.375V16.5"
            />
          )}
        </svg>
        {mode === "folder" ? (
          <>
            <p className="text-sm font-medium text-slate-800">Click to choose a project folder</p>
            <p className="mt-1 text-xs text-slate-500">
              The folder is packaged in your browser; build/vendor dirs (node_modules, .git, …) are
              skipped.
            </p>
          </>
        ) : (
          <>
            <p className="text-sm font-medium text-slate-800">
              Drag &amp; drop a repository ZIP, or click to browse
            </p>
            <p className="mt-1 text-xs text-slate-500">
              Supported: {ACCEPTED_EXTENSIONS.join(", ")} · Max {MAX_UPLOAD_MB} MB
            </p>
          </>
        )}
      </div>

      {(busy || activeFraction > 0) && label ? (
        <div className="mt-4">
          <div className="mb-1 flex items-center justify-between text-xs text-slate-500">
            <span className="truncate">{label}</span>
            <span>{Math.round(activeFraction * 100)}%</span>
          </div>
          <div className="h-2 overflow-hidden rounded-full bg-slate-100">
            <div
              className="h-full rounded-full bg-brand transition-all"
              style={{ width: `${Math.round(activeFraction * 100)}%` }}
            />
          </div>
          {phaseLabel ? <p className="mt-2 text-xs text-slate-500">{phaseLabel}</p> : null}
        </div>
      ) : null}

      {localError || serverError ? (
        <p className="mt-4 rounded-lg bg-rose-50 px-3 py-2 text-sm text-rose-700 ring-1 ring-inset ring-rose-600/20">
          {localError ?? serverError}
        </p>
      ) : null}
    </section>
  );
}
