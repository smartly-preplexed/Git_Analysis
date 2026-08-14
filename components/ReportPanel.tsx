import { Download, FileText, ShieldCheck, AlertTriangle, ShieldAlert, Info } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

interface ReportPanelProps {
  engine: any;
  setActiveView: (v: "submit" | "progress" | "report" | "deploy") => void;
}

const severityConfig: Record<string, { color: string; bg: string; border: string; icon: any }> = {
  Critical: { color: "text-rose-400", bg: "bg-rose-500/10", border: "border-rose-500/30", icon: ShieldAlert },
  High: { color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30", icon: AlertTriangle },
  Medium: { color: "text-amber-400", bg: "bg-amber-500/10", border: "border-amber-500/30", icon: AlertTriangle },
  Low: { color: "text-sky-400", bg: "bg-sky-500/10", border: "border-sky-500/30", icon: Info },
};

export function ReportPanel({ engine, setActiveView }: ReportPanelProps) {
  const report = engine.report;
  if (!report) {
    return (
      <div className="pt-16 flex flex-col items-center justify-center text-center">
        <FileText className="h-12 w-12 text-slate-700 mb-4" />
        <p className="text-slate-400 mb-4">No report available yet.</p>
        <Button onClick={() => setActiveView("submit")} variant="outline" className="border-slate-700 text-slate-300">
          Submit a Repository
        </Button>
      </div>
    );
  }

  const handleDownload = () => {
    const html = engine.generateHtmlReport();
    const blob = new Blob([html], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `reposentinel-report-${Date.now()}.html`;
    a.click();
    URL.revokeObjectURL(url);
    engine.log("REPORT_DOWNLOADED", { findings: report.findings.length });
  };

  return (
    <div className="pt-8 space-y-6">
      <Card className="bg-slate-900 border-slate-800 rounded-2xl">
        <CardHeader>
          <div className="flex items-start justify-between">
            <div>
              <CardTitle className="text-slate-50 text-xl font-serif">Security Analysis Report</CardTitle>
              <CardDescription className="text-slate-500 font-mono text-sm mt-1">
                {engine.currentUrl}
              </CardDescription>
            </div>
            <Button onClick={handleDownload} className="bg-emerald-600 hover:bg-emerald-500 text-slate-50 rounded-lg">
              <Download className="h-4 w-4 mr-2" />
              Download HTML
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {(["Critical", "High", "Medium", "Low"] as const).map((sev) => {
              const cfg = severityConfig[sev];
              const Icon = cfg.icon;
              const count = report.findings.filter((f: any) => f.severity === sev).length;
              return (
                <div key={sev} className={`rounded-xl border p-4 ${cfg.bg} ${cfg.border}`}>
                  <div className="flex items-center justify-between mb-2">
                    <Icon className={`h-5 w-5 ${cfg.color}`} />
                    <span className={`text-2xl font-bold ${cfg.color}`}>{count}</span>
                  </div>
                  <p className="text-xs text-slate-400 font-medium">{sev}</p>
                </div>
              );
            })}
          </div>
          <div className="mt-4 flex flex-wrap gap-3 text-sm">
            <div className="flex items-center gap-2 text-slate-400">
              <ShieldCheck className="h-4 w-4 text-emerald-400" />
              <span>True Positives: <span className="text-slate-200 font-medium">{report.findings.filter((f: any) => f.classification === "True Positive").length}</span></span>
            </div>
            <div className="flex items-center gap-2 text-slate-400">
              <Info className="h-4 w-4 text-slate-500" />
              <span>False Positives: <span className="text-slate-200 font-medium">{report.findings.filter((f: any) => f.classification === "False Positive").length}</span></span>
            </div>
            <div className="flex items-center gap-2 text-slate-400">
              <FileText className="h-4 w-4 text-sky-400" />
              <span>AI Model: <span className="text-slate-200 font-mono text-xs">{report.aiModel}</span></span>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card className="bg-slate-900 border-slate-800 rounded-2xl">
        <CardHeader>
          <CardTitle className="text-slate-100 text-base">Findings & AI Triage</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-800 text-left">
                  <th className="pb-3 pr-4 font-medium text-slate-500">ID</th>
                  <th className="pb-3 pr-4 font-medium text-slate-500">Tool</th>
                  <th className="pb-3 pr-4 font-medium text-slate-500">Finding</th>
                  <th className="pb-3 pr-4 font-medium text-slate-500">Severity</th>
                  <th className="pb-3 pr-4 font-medium text-slate-500">AI Classification</th>
                  <th className="pb-3 font-medium text-slate-500">Mitigation</th>
                </tr>
              </thead>
              <tbody>
                {report.findings.map((f: any, i: number) => {
                  const cfg = severityConfig[f.severity] || severityConfig.Low;
                  return (
                    <tr key={f.id} className="border-b border-slate-800/50 hover:bg-slate-800/30 transition-colors">
                      <td className="py-3 pr-4 font-mono text-xs text-slate-500">{f.id}</td>
                      <td className="py-3 pr-4">
                        <Badge variant="outline" className="border-slate-700 bg-slate-800/50 text-slate-300 font-mono text-xs">
                          {f.tool}
                        </Badge>
                      </td>
                      <td className="py-3 pr-4 text-slate-200">{f.title}</td>
                      <td className="py-3 pr-4">
                        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-medium ${cfg.bg} ${cfg.border} ${cfg.color}`}>
                          {f.severity}
                        </span>
                      </td>
                      <td className="py-3 pr-4">
                        <span className={`text-xs font-medium ${f.classification === "True Positive" ? "text-emerald-400" : "text-slate-500"}`}>
                          {f.classification}
                        </span>
                      </td>
                      <td className="py-3 text-slate-400 text-xs max-w-xs">{f.mitigation}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {report.codeSnippets.length > 0 && (
        <Card className="bg-slate-950 border-slate-800 rounded-2xl">
          <CardHeader>
            <CardTitle className="text-slate-100 text-base">Code Snippets</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {report.codeSnippets.map((snip: any, i: number) => (
              <div key={i}>
                <div className="flex items-center gap-2 mb-2">
                  <Badge variant="outline" className="border-slate-700 bg-slate-800/50 text-slate-400 font-mono text-xs">
                    {snip.file}:{snip.line}
                  </Badge>
                  <span className="text-xs text-slate-500">{snip.rule}</span>
                </div>
                <pre className="bg-slate-900 border border-slate-800 rounded-lg p-3 overflow-x-auto text-xs font-mono text-slate-300">
                  {snip.code}
                </pre>
              </div>
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
