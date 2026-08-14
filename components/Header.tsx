import { ShieldCheck, GitBranch, Activity, FileText, Lock, Terminal } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

interface HeaderProps {
  activeView: "submit" | "progress" | "report" | "deploy";
  setActiveView: (v: "submit" | "progress" | "report" | "deploy") => void;
  engine: any;
}

export function Header({ activeView, setActiveView, engine }: HeaderProps) {
  const navItems = [
    { id: "submit", label: "Submit", icon: GitBranch },
    { id: "progress", label: "Progress", icon: Activity },
    { id: "report", label: "Report", icon: FileText },
    { id: "deploy", label: "Deploy Guide", icon: Terminal },
  ] as const;

  return (
    <header className="border-b border-slate-800 bg-slate-900/60 backdrop-blur sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="h-9 w-9 rounded-lg bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center">
            <ShieldCheck className="h-5 w-5 text-emerald-400" />
          </div>
          <div>
            <h1 className="text-base font-semibold tracking-tight text-slate-50">
              RepoSentinel <span className="text-emerald-400">/</span> Analysis
            </h1>
            <p className="text-xs text-slate-500">Internal SCA · OSINT · Static/Dynamic · AI Triage</p>
          </div>
        </div>

        <nav className="flex items-center gap-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeView === item.id;
            return (
              <Button
                key={item.id}
                variant={isActive ? "default" : "ghost"}
                size="sm"
                onClick={() => setActiveView(item.id)}
                className={
                  isActive
                    ? "bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 hover:bg-emerald-500/20"
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-800"
                }
              >
                <Icon className="h-4 w-4 mr-1.5" />
                {item.label}
                {item.id === "progress" && engine.status === "running" && (
                  <span className="ml-1.5 h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                )}
              </Button>
            );
          })}
        </nav>

        <div className="flex items-center gap-2">
          <Badge variant="outline" className="border-slate-700 text-slate-400 bg-slate-800/50">
            <Lock className="h-3 w-3 mr-1 text-emerald-400" />
            mTLS · 10.0.0.0/8
          </Badge>
        </div>
      </div>
    </header>
  );
}
