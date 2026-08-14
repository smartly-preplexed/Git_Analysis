import { useState } from "react";
import { GitBranch, ShieldAlert, Clock, Server, AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

interface SubmissionPanelProps {
  engine: any;
  setActiveView: (v: "submit" | "progress" | "report") => void;
}

const ALLOWED_HOSTS = ["github.com", "gitlab.com", "git.internal.corp"];
const RATE_LIMIT_SECONDS = 60;

export function SubmissionPanel({ engine, setActiveView }: SubmissionPanelProps) {
  const [url, setUrl] = useState("");
  const [error, setError] = useState<string | null>(null);

  const sanitizeUrl = (raw: string) => raw.trim().replace(/[\s]/g, "");

  const validateUrl = (raw: string): string | null => {
    const cleaned = sanitizeUrl(raw);
    if (!cleaned) return "Repository URL is required.";
    if (cleaned.length > 2048) return "URL exceeds maximum length.";
    let parsed: URL;
    try {
      parsed = new URL(cleaned);
    } catch {
      return "Invalid URL format.";
    }
    if (!parsed.protocol.startsWith("https")) {
      return "Only HTTPS URLs are accepted.";
    }
    if (!ALLOWED_HOSTS.includes(parsed.hostname)) {
      return `Host must be one of: ${ALLOWED_HOSTS.join(", ")}.`;
    }
    const pathParts = parsed.pathname.split("/").filter(Boolean);
    if (pathParts.length < 2) return "URL must include owner/repo path segments.";
    return null;
  };

  const handleSubmit = () => {
    const validationError = validateUrl(url);
    if (validationError) {
      setError(validationError);
      engine.log("VALIDATION_FAIL", { url: sanitizeUrl(url), reason: validationError });
      return;
    }
    if (engine.secondsSinceLastSubmission() < RATE_LIMIT_SECONDS) {
      const wait = RATE_LIMIT_SECONDS - engine.secondsSinceLastSubmission();
      setError(`Rate limit: retry in ${Math.ceil(wait)}s.`);
      engine.log("RATE_LIMIT_HIT", { url: sanitizeUrl(url), waitSeconds: wait });
      return;
    }
    setError(null);
    const cleaned = sanitizeUrl(url);
    engine.startAnalysis(cleaned);
    setActiveView("progress");
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 pt-8">
      <div className="lg:col-span-2 space-y-6">
        <Card className="bg-slate-900 border-slate-800 rounded-2xl shadow-lg shadow-black/20">
          <CardHeader>
            <div className="flex items-center gap-2">
              <div className="h-8 w-8 rounded-md bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center">
                <GitBranch className="h-4 w-4 text-emerald-400" />
              </div>
              <div>
                <CardTitle className="text-slate-50 text-lg">Submit Repository for Analysis</CardTitle>
                <CardDescription className="text-slate-500">
                  HTTPS only · Company-owned repos · Input sanitized
                </CardDescription>
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="repo-url" className="text-slate-300 text-sm font-medium">
                Repository URL
              </Label>
              <Input
                id="repo-url"
                placeholder="https://github.com/your-org/your-repo"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
                className="bg-slate-950 border-slate-700 text-slate-100 placeholder:text-slate-600 rounded-lg font-mono text-sm"
              />
              {error && (
                <div className="flex items-start gap-2 text-sm text-rose-400 mt-2">
                  <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0" />
                  <span>{error}</span>
                </div>
              )}
            </div>

            <div className="flex flex-wrap gap-2 pt-1">
              {ALLOWED_HOSTS.map((h) => (
                <Badge key={h} variant="outline" className="border-slate-700 bg-slate-800/40 text-slate-400 font-mono text-xs">
                  {h}
                </Badge>
              ))}
            </div>

            <div className="flex items-center justify-between pt-2">
              <p className="text-xs text-slate-500">
                Pipeline: Clone → Trivy → Bandit → Megalinter → OSINT → Network → AI Triage
              </p>
              <Button
                onClick={handleSubmit}
                disabled={engine.status === "running"}
                className="bg-emerald-600 hover:bg-emerald-500 text-slate-50 rounded-lg font-medium"
              >
                Start Analysis
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900 border-slate-800 rounded-2xl">
          <CardHeader>
            <CardTitle className="text-slate-100 text-base">Analysis Pipeline Stages</CardTitle>
          </CardHeader>
          <CardContent>
            <ol className="space-y-2.5">
              {[
                { n: "1", t: "Clone & Integrity Check", d: "Shallow clone over HTTPS, verify org ownership" },
                { n: "2", t: "SCA (Trivy)", d: "Dependency & container vulnerability scan" },
                { n: "3", t: "Static Analysis (Bandit + Megalinter)", d: "Python security lint + multi-language linting" },
                { n: "4", t: "OSINT & Network", d: "Exposed secrets, metadata, outbound endpoints" },
                { n: "5", t: "Dynamic Behavior", d: "Sandboxed execution trace, syscall monitoring" },
                { n: "6", t: "AI Triage (OpenAI)", d: "GPT-4o classifies true/false positives, severity, mitigation" },
              ].map((s) => (
                <li key={s.n} className="flex items-start gap-3">
                  <span className="mt-0.5 h-6 w-6 rounded-md bg-slate-800 border border-slate-700 text-emerald-400 text-xs font-mono flex items-center justify-center shrink-0">
                    {s.n}
                  </span>
                  <div>
                    <p className="text-sm font-medium text-slate-200">{s.t}</p>
                    <p className="text-xs text-slate-500">{s.d}</p>
                  </div>
                </li>
              ))}
            </ol>
          </CardContent>
        </Card>
      </div>

      <div className="space-y-6">
        <Card className="bg-slate-900 border-slate-800 rounded-2xl">
          <CardHeader>
            <CardTitle className="text-slate-100 text-base flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-amber-400" />
              Security Posture
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            {[
              { label: "Transport", value: "mTLS (corp PKI)", ok: true },
              { label: "IP Allowlist", value: "10.0.0.0/8", ok: true },
              { label: "API Key Storage", value: "Env var / Vault", ok: true },
              { label: "Rate Limit", value: "1 req / 60s", ok: true },
              { label: "OIDC + Org Check", value: "Phase 2", ok: false },
            ].map((row) => (
              <div key={row.label} className="flex items-center justify-between">
                <span className="text-slate-400">{row.label}</span>
                <div className="flex items-center gap-2">
                  <span className="text-slate-200 font-mono text-xs">{row.value}</span>
                  <span className={`h-2 w-2 rounded-full ${row.ok ? "bg-emerald-400" : "bg-amber-400"}`} />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card className="bg-slate-900 border-slate-800 rounded-2xl">
          <CardHeader>
            <CardTitle className="text-slate-100 text-base flex items-center gap-2">
              <Server className="h-4 w-4 text-sky-400" />
              Backend Runtime
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-xs text-slate-400 font-mono">
            <div className="flex justify-between"><span>OS</span><span className="text-slate-300">Ubuntu 24.04 LTS</span></div>
            <div className="flex justify-between"><span>OpenAI Model</span><span className="text-slate-300">gpt-4o</span></div>
            <div className="flex justify-between"><span>Report Format</span><span className="text-slate-300">HTML + Charts</span></div>
            <div className="flex justify-between"><span>Audit Log</span><span className="text-slate-300">Append-only</span></div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900 border-slate-800 rounded-2xl">
          <CardHeader>
            <CardTitle className="text-slate-100 text-base flex items-center gap-2">
              <Clock className="h-4 w-4 text-violet-400" />
              Rate Limit
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-slate-400">
              One submission per <span className="text-slate-200 font-mono">60s</span> per session to prevent abuse.
            </p>
            <div className="mt-3 h-2 rounded-full bg-slate-800 overflow-hidden">
              <div
                className="h-full bg-violet-500 transition-all duration-300"
                style={{ width: `${Math.min(100, (engine.secondsSinceLastSubmission() / RATE_LIMIT_SECONDS) * 100)}%` }}
              />
            </div>
            <p className="text-xs text-slate-500 mt-2 font-mono">
              {engine.lastSubmissionTime
                ? `Last: ${new Date(engine.lastSubmissionTime).toLocaleTimeString()}`
                : "No submissions yet"}
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
