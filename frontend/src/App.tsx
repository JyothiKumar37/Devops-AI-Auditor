import { Navigate, Route, Routes, useLocation } from "react-router-dom";

import { ErrorBoundary } from "@/components/ErrorBoundary";
import { AppShell } from "@/components/layout/AppShell";
import AIInvestigation from "@/pages/AIInvestigation";
import AuditLog from "@/pages/AuditLog";
import Dashboard from "@/pages/Dashboard";
import Dependencies from "@/pages/Dependencies";
import FindingDetails from "@/pages/FindingDetails";
import Findings from "@/pages/Findings";
import Integrations from "@/pages/Integrations";
import NewScan from "@/pages/NewScan";
import Notifications from "@/pages/Notifications";
import Policies from "@/pages/Policies";
import Posture from "@/pages/Posture";
import PullRequestDetail from "@/pages/PullRequestDetail";
import PullRequests from "@/pages/PullRequests";
import Readiness from "@/pages/Readiness";
import ReportView from "@/pages/ReportView";
import RepositoryFiles from "@/pages/RepositoryFiles";
import ScanChat from "@/pages/ScanChat";
import ScanDiff from "@/pages/ScanDiff";
import ScanHistory from "@/pages/ScanHistory";
import ScanLayout from "@/pages/ScanLayout";
import ScanOverview from "@/pages/ScanOverview";
import Settings from "@/pages/Settings";
import Trends from "@/pages/Trends";

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
          <Route path="posture" element={<Posture />} />
          <Route path="trends" element={<Trends />} />
          <Route path="dependencies" element={<Dependencies />} />
          <Route path="files" element={<RepositoryFiles />} />
          <Route path="readiness" element={<Readiness />} />
          <Route path="diff" element={<ScanDiff />} />
          <Route path="chat" element={<ScanChat />} />
          <Route path="investigate" element={<AIInvestigation />} />
          <Route path="report" element={<ReportView />} />
        </Route>
        <Route path="/integrations" element={<Integrations />} />
        <Route path="/pull-requests" element={<PullRequests />} />
        <Route path="/pull-requests/:prId" element={<PullRequestDetail />} />
        <Route path="/policies" element={<Policies />} />
        <Route path="/notifications" element={<Notifications />} />
        <Route path="/audit" element={<AuditLog />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
      </ErrorBoundary>
    </AppShell>
  );
}
