import { useNavigate } from "react-router-dom";

import { UploadPanel } from "@/components/UploadPanel";
import { Card, PageHeader } from "@/components/ui";

export default function NewScan() {
  const navigate = useNavigate();
  return (
    <div className="mx-auto max-w-3xl">
      <PageHeader
        title="New Scan"
        subtitle="Upload a repository archive to run a full security and readiness audit."
      />
      <UploadPanel onUploaded={(scan) => navigate(`/scans/${scan.id}`)} />

      <Card className="mt-6 p-5">
        <h2 className="text-sm font-semibold text-white">How it works</h2>
        <ol className="mt-3 space-y-2 text-sm text-slate-400">
          {[
            "The archive is validated and safely extracted into an isolated workspace.",
            "Files are discovered and classified (Docker, Kubernetes, Terraform, CI/CD, …).",
            "Deterministic scanners analyse each artifact and detect secrets.",
            "The AI reasoning layer correlates findings and scores production readiness.",
          ].map((step, i) => (
            <li key={step} className="flex gap-3">
              <span className="grid h-5 w-5 shrink-0 place-items-center rounded-full bg-brand/15 text-[11px] font-semibold text-brand">
                {i + 1}
              </span>
              {step}
            </li>
          ))}
        </ol>
        <p className="mt-4 text-xs text-slate-500">
          Repository code is never executed — files are only read for analysis.
        </p>
      </Card>
    </div>
  );
}
