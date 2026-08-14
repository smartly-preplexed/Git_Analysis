import { useState, useEffect, useRef, useCallback } from "react";

const STAGE_DEFINITIONS = [
  { id: "clone", name: "Clone & Integrity Check" },
  { id: "sca", name: "SCA — Trivy" },
  { id: "static", name: "Static Analysis — Bandit + Megalinter" },
  { id: "osint", name: "OSINT & Network Analysis" },
  { id: "dynamic", name: "Dynamic Behavior Analysis" },
  { id: "ai", name: "AI Triage — OpenAI GPT-4o" },
];

const MOCK_FINDINGS = [
  {
    id: "SCA-001",
    tool: "Trivy",
    title: "CVE-2024-1234 in lodash@4.17.20",
    severity: "High",
    classification: "True Positive",
    mitigation: "Upgrade lodash to >=4.17.21. Run npm audit fix and verify CI pipeline passes.",
  },
  {
    id: "SCA-002",
    tool: "Trivy",
    title: "CVE-2023-45805 in requests@2.28.0",
    severity: "Medium",
    classification: "True Positive",
    mitigation: "Update requests to >=2.31.0. Pin in requirements.txt and rebuild container.",
  },
  {
    id: "STATIC-001",
    tool: "Bandit",
    title: "B608: Possible SQL injection via string construction",
    severity: "Critical",
    classification: "True Positive",
    mitigation: "Use parameterized queries with SQLAlchemy ORM. Never concatenate SQL strings.",
  },
  {
    id: "STATIC-002",
    tool: "Bandit",
    title: "B301: Use of pickle.load() — deserialization risk",
    severity: "High",
    classification: "True Positive",
    mitigation: "Replace pickle with JSON or use restricted unpickler. Validate input source.",
  },
  {
    id: "STATIC-003",
    tool: "Megalinter",
    title: "Unused variable in auth.py:42",
    severity: "Low",
    classification: "False Positive",
    mitigation: "No action required — variable used in conditional branch not detected by linter.",
  },
  {
    id: "OSINT-001",
    tool: "OSINT",
    title: "Hardcoded AWS access key detected in .env.example",
    severity: "Critical",
    classification: "True Positive",
    mitigation: "Revoke key immediately in IAM. Rotate all credentials. Use secrets manager.",
  },
  {
    id: "NET-001",
    tool: "Network",
    title: "Outbound HTTP (non-TLS) to 203.0.113.5 detected",
    severity: "Medium",
    classification: "True Positive",
    mitigation: "Enforce HTTPS for all outbound calls. Add network policy restricting egress.",
  },
  {
    id: "DYN-001",
    tool: "Dynamic",
    title: "Unexpected subprocess.exec call during runtime",
    severity: "High",
    classification: "True Positive",
    mitigation: "Audit call path. Sandbox execution. Restrict via seccomp profile.",
  },
];

const MOCK_SNIPPETS = [
  {
    file: "src/db/queries.py",
    line: 42,
    rule: "B608 SQL Injection",
    code: `query = "SELECT * FROM users WHERE id = " + user_input\ncursor.execute(query)\n# Should be: cursor.execute("SELECT * FROM users WHERE id = %s", (user_input,))`,
  },
  {
    file: "src/utils/serializer.py",
    line: 18,
    rule: "B301 Pickle Deserialization",
    code: `import pickle\ndata = pickle.load(open(user_file, 'rb'))\n# Replace with json.load() or safe loader`,
  },
];

const TOOL_OUTPUT_LINES = [
  { level: "INFO", msg: "git clone --depth 1 https://github.com/corp/repo.git" },
  { level: "INFO", msg: "Clone successful. HEAD: a1b2c3d" },
  { level: "INFO", msg: "trivy fs --severity HIGH,CRITICAL ." },
  { level: "WARN", msg: "trivy: 2 HIGH, 1 CRITICAL vulnerabilities found" },
  { level: "INFO", msg: "bandit -r src/ -f json -o bandit.json" },
  { level: "WARN", msg: "bandit: 3 issues found (1 CRITICAL, 1 HIGH, 1 LOW)" },
  { level: "INFO", msg: "megalinter --flavor python --format json" },
  { level: "INFO", msg: "megalinter: completed, 1 lint issue" },
  { level: "WARN", msg: "osint: hardcoded AWS key pattern AKIA**** detected" },
  { level: "WARN", msg: "network: plaintext HTTP outbound to 203.0.113.5" },
  { level: "WARN", msg: "dynamic: subprocess.exec syscall traced in sandbox" },
  { level: "INFO", msg: "openai chat.completions.create(model=gpt-4o)" },
  { level: "INFO", msg: "ai-triage: 8 findings classified, 7 TP, 1 FP" },
  { level: "INFO", msg: "report: HTML generated with tables, charts, snippets" },
];

export function useAnalysisEngine() {
  const [stages, setStages] = useState(
    STAGE_DEFINITIONS.map((s) => ({ ...s, status: "pending", detail: "" }))
  );
  const [status, setStatus] = useState<"idle" | "running" | "completed" | "failed">("idle");
  const [currentUrl, setCurrentUrl] = useState("");
  const [toolOutput, setToolOutput] = useState<any[]>([]);
  const [report, setReport] = useState<any>(null);
  const [auditLog, setAuditLog] = useState<any[]>([]);
  const [lastSubmissionTime, setLastSubmissionTime] = useState<number | null>(null);
  const timersRef = useRef<any[]>([]);

  const log = useCallback((action: string, details: any) => {
    const entry = {
      timestamp: new Date().toISOString(),
      action,
      details,
    };
    setAuditLog((prev) => [...prev, entry]);
  }, []);

  const secondsSinceLastSubmission = useCallback(() => {
    if (!lastSubmissionTime) return Infinity;
    return (Date.now() - lastSubmissionTime) / 1000;
  }, [lastSubmissionTime]);

  const clearTimers = useCallback(() => {
    timersRef.current.forEach((t) => clearTimeout(t));
    timersRef.current = [];
  }, []);

  const startAnalysis = useCallback((url: string) => {
    clearTimers();
    setCurrentUrl(url);
    setStatus("running");
    setReport(null);
    setToolOutput([]);
    setStages(STAGE_DEFINITIONS.map((s) => ({ ...s, status: "pending", detail: "" })));
    setLastSubmissionTime(Date.now());
    log("ANALYSIS_STARTED", { url });

    const stageDurations = [1500, 2500, 3000, 2000, 2500, 3000];
    let cumulative = 0;
    let outputIdx = 0;

    STAGE_DEFINITIONS.forEach((stageDef, idx) => {
      const startDelay = cumulative;
      const endDelay = cumulative + stageDurations[idx];

      const startTimer = setTimeout(() => {
        setStages((prev) =>
          prev.map((s) =>
            s.id === stageDef.id ? { ...s, status: "running", detail: "Executing..." } : s
          )
        );
        const linesForStage = TOOL_OUTPUT_LINES.filter((_, i) => i >= outputIdx && i < outputIdx + 2);
        linesForStage.forEach((line, li) => {
          setTimeout(() => {
            setToolOutput((prev) => [
              ...prev,
              { ...line, time: new Date().toLocaleTimeString() },
            ]);
          }, li * 400);
        });
        outputIdx += 2;
      }, startDelay);
      timersRef.current.push(startTimer);

      const endTimer = setTimeout(() => {
        setStages((prev) =>
          prev.map((s) =>
            s.id === stageDef.id
              ? { ...s, status: "completed", detail: "Completed successfully" }
              : s
          )
        );
        log("STAGE_COMPLETED", { stage: stageDef.name });

        if (idx === STAGE_DEFINITIONS.length - 1) {
          const mockReport = {
            url,
            generatedAt: new Date().toISOString(),
            aiModel: "gpt-4o",
            findings: MOCK_FINDINGS,
            codeSnippets: MOCK_SNIPPETS,
          };
          setReport(mockReport);
          setStatus("completed");
          log("ANALYSIS_COMPLETED", { findings: mockReport.findings.length });
        }
      }, endDelay);
      timersRef.current.push(endTimer);

      cumulative = endDelay;
    });
  }, [clearTimers, log]);

  const overallProgress = stages.length
    ? Math.round((stages.filter((s) => s.status === "completed").length / stages.length) * 100)
    : 0;

  const generateHtmlReport = useCallback(() => {
    if (!report) return "";
    const sevCounts = ["Critical", "High", "Medium", "Low"].map((sev) => ({
      sev,
      count: report.findings.filter((f: any) => f.severity === sev).length,
    }));
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>RepoSentinel Report — ${report.url}</title>
<style>
  body { font-family: -apple-system, sans-serif; background: #0f172a; color: #e2e8f0; padding: 40px; }
  h1 { color: #f8fafc; font-family: Georgia, serif; }
  .summary { display: flex; gap: 16px; margin: 24px 0; }
  .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 20px; flex: 1; }
  .sev-critical { color: #fb7185; } .sev-high { color: #fb923c; }
  .sev-medium { color: #fbbf24; } .sev-low { color: #38bdf8; }
  table { width: 100%; border-collapse: collapse; margin-top: 24px; }
  th, td { text-align: left; padding: 10px; border-bottom: 1px solid #334155; font-size: 14px; }
  th { color: #94a3b8; font-weight: 600; }
  .badge { padding: 2px 8px; border-radius: 6px; font-size: 12px; font-weight: 600; }
  pre { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 12px; overflow-x: auto; font-size: 13px; }
  .meta { color: #64748b; font-family: monospace; font-size: 13px; }
</style>
</head>
<body>
  <h1>Security Analysis Report</h1>
  <p class="meta">${report.url} · Generated ${report.generatedAt} · AI Model: ${report.aiModel}</p>
  <div class="summary">
    ${sevCounts.map(s => `<div class="card"><div class="sev-${s.sev.toLowerCase()}"><strong style="font-size:28px">${s.count}</strong></div><div style="color:#94a3b8;font-size:13px;margin-top:4px">${s.sev}</div></div>`).join("")}
  </div>
  <table>
    <thead><tr><th>ID</th><th>Tool</th><th>Finding</th><th>Severity</th><th>AI Classification</th><th>Mitigation</th></tr></thead>
    <tbody>
      ${report.findings.map((f: any) => `<tr><td class="meta">${f.id}</td><td>${f.tool}</td><td>${f.title}</td><td><span class="badge sev-${f.severity.toLowerCase()}">${f.severity}</span></td><td>${f.classification}</td><td>${f.mitigation}</td></tr>`).join("")}
    </tbody>
  </table>
  <h2>Code Snippets</h2>
  ${report.codeSnippets.map((s: any) => `<div style="margin-bottom:16px"><p class="meta">${s.file}:${s.line} — ${s.rule}</p><pre>${s.code}</pre></div>`).join("")}
</body>
</html>`;
  }, [report]);

  useEffect(() => {
    return () => clearTimers();
  }, [clearTimers]);

  return {
    stages,
    status,
    currentUrl,
    toolOutput,
    report,
    auditLog,
    lastSubmissionTime,
    overallProgress,
    startAnalysis,
    log,
    secondsSinceLastSubmission,
    generateHtmlReport,
  };
}
