import { CheckCircle2, Circle, Loader2, XCircle, Terminal } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

interface ProgressPanelProps {
  engine: any;
  setActiveView: (v: "submit" | "progress" | "report" | "deploy") => void;
}

export function ProgressPanel({ engine, setActiveView }: ProgressPanelProps) {
  const stages = engine.stages;

  return (
    <div className="pt-8 space-y-6">
      <Card className="bg-slate-900 border-slate-800 rounded-2xl">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-slate-50 text-lg">Analysis Progress</CardTitle>
            {engine.status === "completed" && (
              <Button
                onClick={() => setActiveView("report")}
                className="bg-emerald-600 hover:bg-emerald-500 text-slate-50 rounded-lg"
              >
                View Report
              </Button>
            )}
          </div>
          {engine.currentUrl && (
            <p className="text-sm text-slate-500 font-mono truncate">{engine.currentUrl}</p>
          )}
        </CardHeader>
        <CardContent>
          <div className="space-y-1">
            {stages.map((stage: any, idx: number) => {
              const Icon =
                stage.status === "completed" ? CheckCircle2 :
                stage.status === "running" ? Loader2 :
                stage.status === "failed" ? XCircle : Circle;
              const color =
                stage.status === "completed" ? "text-emerald-400" :
                stage.status === "running" ? "text-sky-400" :
                stage.status === "failed" ? "text-rose-400" : "text-slate-600";
              return (
                <div
                  key={stage.id}
                  className={`flex items-center gap-3 p-3 rounded-lg transition-colors ${
                    stage.status === "running" ? "bg-sky-500/5 border border-sky-500/20" : "border border-transparent"
                  }`}
                >
                  <Icon className={`h-5 w-5 shrink-0 ${color} ${stage.status === "running" ? "animate-spin" : ""}`} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between">
                      <span className={`text-sm font-medium ${
                        stage.status === "pending" ? "text-slate-500" : "text-slate-200"
                      }`}>
                        {stage.name}
                      </span>
                      <Badge
                        variant="outline"
                        className={`text-xs font-mono ${
                          stage.status === "completed" ? "border-emerald-500/30 text-emerald-400 bg-emerald-500/10" :
                          stage.status === "running" ? "border-sky-500/30 text-sky-400 bg-sky-500/10" :
                          stage.status === "failed" ? "border-rose-500/30 text-rose-400 bg-rose-500/10" :
                          "border-slate-700 text-slate-500 bg-slate-800/50"
                        }`}
                      >
                        {stage.status}
                      </Badge>
                    </div>
                    {stage.detail && (
                      <p className="text-xs text-slate-500 mt-0.5 font-mono truncate">{stage.detail}</p>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          <div className="mt-6">
            <div className="flex justify-between text-xs text-slate-500 mb-1.5">
              <span>Overall Progress</span>
              <span className="font-mono">{engine.overallProgress}%</span>
            </div>
            <div className="h-2 rounded-full bg-slate-800 overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-emerald-600 to-emerald-400 transition-all duration-500"
                style={{ width: `${engine.overallProgress}%` }}
              />
            </div>
          </div>
        </CardContent>
      </Card>

      <Card className="bg-slate-950 border-slate-800 rounded-2xl">
        <CardHeader>
          <CardTitle className="text-slate-100 text-base flex items-center gap-2">
            <Terminal className="h-4 w-4 text-slate-400" />
            Live Tool Output
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="bg-slate-950 rounded-lg border border-slate-800 p-4 h-64 overflow-y-auto font-mono text-xs space-y-1">
            {engine.toolOutput.length === 0 ? (
              <p className="text-slate-600">Waiting for tool output...</p>
            ) : (
              engine.toolOutput.map((line: any, i: number) => (
                <div key={i} className="flex gap-2">
                  <span className="text-slate-600 shrink-0">{line.time}</span>
                  <span className={`shrink-0 ${line.level === "ERROR" ? "text-rose-400" : line.level === "WARN" ? "text-amber-400" : "text-emerald-400"}`}>
                    [{line.level}]
                  </span>
                  <span className="text-slate-300">{line.msg}</span>
                </div>
              ))
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
