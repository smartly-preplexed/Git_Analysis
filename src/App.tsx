import { useState } from "react";
import { AuditConsole } from "@/components/AuditConsole";
import { Header } from "@/components/Header";
import { SubmissionPanel } from "@/components/SubmissionPanel";
import { ProgressPanel } from "@/components/ProgressPanel";
import { ReportPanel } from "@/components/ReportPanel";
import { useAnalysisEngine } from "@/hooks/useAnalysisEngine";

export default function App() {
  const engine = useAnalysisEngine();
  const [activeView, setActiveView] = useState<"submit" | "progress" | "report">("submit");

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans">
      <Header activeView={activeView} setActiveView={setActiveView} engine={engine} />
      <main className="max-w-7xl mx-auto px-6 pb-16">
        {activeView === "submit" && <SubmissionPanel engine={engine} setActiveView={setActiveView} />}
        {activeView === "progress" && <ProgressPanel engine={engine} setActiveView={setActiveView} />}
        {activeView === "report" && <ReportPanel engine={engine} setActiveView={setActiveView} />}
      </main>
      <AuditConsole entries={engine.auditLog} />
    </div>
  );
}
