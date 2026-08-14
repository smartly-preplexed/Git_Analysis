import { ScrollText } from "lucide-react";
import { useState } from "react";

interface AuditConsoleProps {
  entries: any[];
}

export function AuditConsole({ entries }: AuditConsoleProps) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className={`fixed bottom-0 left-0 right-0 border-t border-slate-800 bg-slate-950/95 backdrop-blur transition-all duration-300 ${expanded ? "h-64" : "h-10"}`}>
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full h-10 flex items-center justify-between px-6 text-xs text-slate-500 hover:text-slate-300 transition-colors"
      >
        <div className="flex items-center gap-2">
          <ScrollText className="h-3.5 w-3.5" />
          <span className="font-mono">Audit Log ({entries.length} entries)</span>
        </div>
        <span className="font-mono">{expanded ? "collapse ▼" : "expand ▲"}</span>
      </button>
      {expanded && (
        <div className="h-[calc(100%-2.5rem)] overflow-y-auto px-6 pb-4 font-mono text-xs space-y-0.5">
          {entries.length === 0 ? (
            <p className="text-slate-600 pt-2">No audit events recorded.</p>
          ) : (
            entries.map((e, i) => (
              <div key={i} className="flex gap-3 py-0.5">
                <span className="text-slate-600 shrink-0">{e.timestamp}</span>
                <span className="text-emerald-400 shrink-0 w-32 truncate">[{e.action}]</span>
                <span className="text-slate-400 truncate">{JSON.stringify(e.details)}</span>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
}
