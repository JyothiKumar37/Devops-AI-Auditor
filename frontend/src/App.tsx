import { Navigate, Route, Routes, useLocation } from "react-router-dom";

import { ErrorBoundary } from "@/components/ErrorBoundary";
import { AppShell } from "@/components/layout/AppShell";
import Dashboard from "@/pages/Dashboard";
import FindingDetails from "@/pages/FindingDetails";
import Findings from "@/pages/Findings";
import NewScan from "@/pages/NewScan";
import Readiness from "@/pages/Readiness";
import ReportView from "@/pages/ReportView";
import RepositoryFiles from "@/pages/RepositoryFiles";
import ScanDiff from "@/pages/ScanDiff";
import ScanHistory from "@/pages/ScanHistory";
import ScanLayout from "@/pages/ScanLayout";
import ScanOverview from "@/pages/ScanOverview";
import Settings from "@/pages/Settings";

export default function App() {
  const location = useLocation();
  return (
    <AppShell>
      <ErrorBoundary resetKey={location.pathname}>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/scan/new" element={<NewScan />} />
        <Route path="/scans" element={<ScanHistory />} />
        <Route path="/scans/:scanId" element={<ScanLayout />}>
          <Route index element={<ScanOverview />} />
          <Route path="findings" element={<Findings />} />
          <Route path="findings/:findingId" element={<FindingDetails />} />
          <Route path="files" element={<RepositoryFiles />} />
          <Route path="readiness" element={<Readiness />} />
          <Route path="diff" element={<ScanDiff />} />
          <Route path="report" element={<ReportView />} />
        </Route>
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
      </ErrorBoundary>
    </AppShell>
  );
}
