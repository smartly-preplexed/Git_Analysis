#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║                 RepoSec Analyzer —  v1.0                     ║
║                 DevSecOps pipeline tools                     ║
║   Usage: python3 reposec.py <github-url|local-path>          ║
╚══════════════════════════════════════════════════════════════╝
"""

import argparse, json, os, re, shutil, subprocess, sys, textwrap, time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any
from html import escape

REPOSEC_TMP_ROOT = Path(os.environ.get("REPOSEC_TMP_DIR", "/tmp")).resolve()
REPOSEC_TMP_ROOT.mkdir(parents=True, exist_ok=True)

def reposec_tmp(name: str) -> str:
    """Return a per-job temporary path supplied by the WebUI backend."""
    return str(REPOSEC_TMP_ROOT / name)


# ─────────────────────────────────────────────────────────────────────────────
# ANSI COLOURS
# ─────────────────────────────────────────────────────────────────────────────
R  = "\033[0m"
B  = "\033[1m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
PURPLE = "\033[95m"
GREY   = "\033[90m"
WHITE  = "\033[97m"
ORANGE = "\033[38;5;208m"

def banner():
    print(f"""{GREEN}{B}
██████╗ ███████╗██████╗  ██████╗ ███████╗███████╗ ██████╗
██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔════╝██╔════╝██╔════╝
██████╔╝█████╗  ██████╔╝██║   ██║███████╗█████╗  ██║
██╔══██╗██╔══╝  ██╔═══╝ ██║   ██║╚════██║██╔══╝  ██║
██║  ██║███████╗██║     ╚██████╔╝███████║███████╗╚██████╗
╚═╝  ╚═╝╚══════╝╚═╝      ╚═════╝ ╚══════╝╚══════╝ ╚═════╝
{R}{GREY}         Repository Security Analysis{R}
""")

def ph(num, tag, name, color=CYAN):
    print(f"\n{color}{B}{'═'*60}{R}")
    print(f"{color}{B}  PHASE {num} / {tag} — {name}{R}")
    print(f"{color}{B}{'═'*60}{R}")

def cmd_print(c):  print(f"  {GREY}${R} {c}")
def ok(msg):       print(f"  {GREEN}✓{R} {msg}")
def warn(msg):     print(f"  {YELLOW}⚠{R} {msg}")
def err(msg):      print(f"  {RED}✗{R} {msg}")
def info(msg):     print(f"  {GREY}·{R} {msg}")

SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
SEV_COLOR = {"CRITICAL": RED, "HIGH": ORANGE, "MEDIUM": YELLOW, "LOW": GREEN, "INFO": CYAN}
SEV_WEIGHT = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 0.5, "INFO": 0}


# ─────────────────────────────────────────────────────────────────────────────
# DATA MODEL
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Finding:
    phase:       str
    tool:        str
    severity:    str        # CRITICAL HIGH MEDIUM LOW INFO
    title:       str
    description: str        = ""
    file:        str        = ""
    line:        str        = ""
    cve:         str        = ""
    cwe:         str        = ""
    package:     str        = ""
    remediation: str        = ""

    def sev_norm(self):
        s = self.severity.upper()
        return s if s in SEV_ORDER else "INFO"
def __post_init__(self):
    # Coerce all string fields — some parsers pass ints (e.g. CWE IDs, line numbers)
    self.line        = str(self.line)        if self.line        is not None else ""
    self.cve         = str(self.cve)         if self.cve         is not None else ""
    self.cwe         = str(self.cwe)         if self.cwe         is not None else ""
    self.package     = str(self.package)     if self.package     is not None else ""
    self.remediation = str(self.remediation) if self.remediation is not None else ""
    self.description = str(self.description) if self.description is not None else ""
    self.file        = str(self.file)        if self.file        is not None else ""

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def tool_available(name: str) -> bool:
    return shutil.which(name) is not None

def run(cmd: str, cwd: str = ".", timeout: int = 300,
        env: dict = None) -> Tuple[int, str, str]:
    """Run shell command, return (returncode, stdout, stderr)."""
    try:
        e = {**os.environ, **(env or {})}
        r = subprocess.run(
            cmd, shell=True, cwd=cwd, capture_output=True,
            text=True, timeout=timeout, env=e
        )
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"TIMEOUT after {timeout}s"
    except Exception as ex:
        return -1, "", str(ex)

def parse_sarif(sarif_path: str, tool: str, phase: str) -> List[Finding]:
    """Parse SARIF 2.1.0 format into Finding list."""
    findings = []
    try:
        with open(sarif_path) as f:
            data = json.load(f)
        for run_ in data.get("runs", []):
            rules = {r["id"]: r for r in
                     run_.get("tool", {}).get("driver", {}).get("rules", [])}
            for result in run_.get("results", []):
                rid   = result.get("ruleId", "")
                rule  = rules.get(rid, {})
                level = result.get("level", "warning")
                sev_map = {"error": "HIGH", "warning": "MEDIUM",
                           "note": "LOW", "none": "INFO"}
                sev = sev_map.get(level, "MEDIUM")
                # Try to extract severity from properties
                props = result.get("properties", {})
                if "severity" in props:
                    sev = props["severity"].upper()
                msg = result.get("message", {}).get("text", rid)
                loc = result.get("locations", [{}])[0]
                phys = loc.get("physicalLocation", {})
                fpath = phys.get("artifactLocation", {}).get("uri", "")
                lineno = str(phys.get("region", {}).get("startLine", ""))
                desc = rule.get("fullDescription", {}).get("text", "") or \
                       rule.get("shortDescription", {}).get("text", "")
                cwe = ""
                for tag in rule.get("properties", {}).get("tags", []):
                    if tag.startswith("CWE-"):
                        cwe = tag
                        break
                findings.append(Finding(
                    phase=phase, tool=tool, severity=sev,
                    title=msg[:120], description=desc[:300],
                    file=fpath, line=lineno, cwe=cwe
                ))
    except Exception as e:
        warn(f"SARIF parse error ({tool}): {e}")
    return findings

def normalize_sev(raw: str) -> str:
    raw = (raw or "").upper()
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if s in raw:
            return s
    return "INFO"


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 01 — DISCOVERY
# ─────────────────────────────────────────────────────────────────────────────
def phase_discovery(repo_path: str) -> Tuple[List[str], str, Dict]:
    ph("01", "RECON", "Repository Discovery & Cataloging", CYAN)
    p = Path(repo_path)
    meta = {"path": str(p), "name": p.name, "files": 0, "dirs": 0,
            "languages": {}, "manifests": [], "sensitive": []}

    # Enumerate files
    all_files = []
    MANIFEST_NAMES = {"package.json","requirements.txt","go.mod","cargo.toml",
                      "pom.xml","build.gradle","dockerfile","docker-compose.yml",
                      "gemfile","pyproject.toml","go.sum","pipfile","setup.py",
                      "composer.json","pubspec.yaml"}
    SENSITIVE_PAT  = re.compile(
        r'(\.env$|\.pem$|\.key$|\.crt$|\.p12$|\.pfx$|secret|credential|'
        r'password|\.ovpn$|id_rsa|\.ppk$)', re.I)

    ext_counts: Dict[str, int] = {}
    cmd_print("find . -type f | sort")
    for root, dirs, files in os.walk(repo_path):
        # Skip hidden dirs and common noise
        dirs[:] = [d for d in dirs if not d.startswith('.')
                   and d not in ('node_modules','__pycache__','.git',
                                 'vendor','dist','build','.venv','venv')]
        for fname in files:
            fpath = os.path.join(root, fname)
            rel   = os.path.relpath(fpath, repo_path)
            all_files.append(rel)
            ext = Path(fname).suffix.lower().lstrip('.')
            if ext:
                ext_counts[ext] = ext_counts.get(ext, 0) + 1
            if fname.lower() in MANIFEST_NAMES:
                meta["manifests"].append(rel)
            if SENSITIVE_PAT.search(fname):
                meta["sensitive"].append(rel)
        meta["dirs"] += len(dirs)

    meta["files"] = len(all_files)
    meta["languages"] = dict(sorted(ext_counts.items(),
                                    key=lambda x: -x[1])[:10])
    ok(f"Cataloged {meta['files']} files across {meta['dirs']} directories")

    if meta["manifests"]:
        ok(f"Manifests: {', '.join(meta['manifests'][:8])}")
    if meta["sensitive"]:
        warn(f"SENSITIVE FILES: {', '.join(meta['sensitive'][:6])}")

    top_exts = ", ".join(f".{e}×{c}" for e, c in
                         list(meta["languages"].items())[:8])
    ok(f"Extensions: {top_exts}")

    # cloc for language stats
    if tool_available("cloc"):
        cmd_print("cloc . --json")
        rc, out, _ = run("cloc . --json --quiet", cwd=repo_path, timeout=60)
        if rc == 0:
            try:
                cloc = json.loads(out)
                langs = {k: v["code"] for k, v in cloc.items()
                         if k not in ("header", "SUM") and isinstance(v, dict)}
                meta["cloc"] = langs
                top = sorted(langs.items(), key=lambda x: -x[1])[:5]
                ok(f"Lines of code: {', '.join(f'{l}:{c}' for l,c in top)}")
            except Exception:
                pass

    # Generate Memmaidjs
    cmd_print("mermaid-gen --annotate --depth=3")
    mermaid = _gen_mermaid(all_files, p.name)
    ok("Mermaid structure diagram generated")

    return all_files, mermaid, meta


def _gen_mermaid(files: List[str], repo_name: str) -> str:
    """Generate a Mermaid flowchart representing the repo directory tree."""
    EXT_MAP = {
        ".py": "Python",  ".js": "JavaScript", ".ts": "TypeScript",
        ".jsx": "React",  ".tsx": "React",      ".go": "Go",
        ".rs": "Rust",    ".java": "Java",      ".rb": "Ruby",
        ".php": "PHP",    ".sh": "Shell",       ".bash": "Shell",
        ".yml": "YAML",   ".yaml": "YAML",      ".json": "JSON",
        ".toml": "TOML",  ".md": "Docs",        ".tf": "Terraform",
        ".pem": "Creds",  ".key": "Creds",
    }
    def annotate(name: str) -> str:
        n = name.lower()
        if "dockerfile" in n: return "Docker"
        if ".env" in n:        return "Env"
        return EXT_MAP.get(Path(n).suffix.lower(), "file")

    def mmd_label(text: str) -> str:
        return text.replace('"', "'")

    # Build the same tree structure as before
    tree: Dict = {}
    for f in files[:300]:
        parts = Path(f).parts
        node  = tree
        for part in parts[:-1]:
            node = node.setdefault(part, {"__files__": []})
        node.setdefault("__files__", [])
        if len(node["__files__"]) < 8:
            node["__files__"].append(parts[-1])

    lines: List[str] = ["graph TD"]
    counter = [0]

    def uid() -> str:
        counter[0] += 1
        return f"N{counter[0]}"

    root_id = uid()
    lines.append(f'  {root_id}["{mmd_label(repo_name)}"]:::folder')

    def render(node: Dict, parent_id: str, depth: int, max_d: int = 3) -> None:
        if depth > max_d:
            return
        for k, v in node.items():
            if k == "__files__":
                continue
            nid = uid()
            lines.append(f'  {nid}["{mmd_label(k)}"]:::folder')
            lines.append(f'  {parent_id} --> {nid}')
            render(v, nid, depth + 1, max_d)
            for fname in v.get("__files__", []):
                fid   = uid()
                label = annotate(fname)
                lines.append(f'  {fid}["{mmd_label(fname)}\n{label}"]:::file')
                lines.append(f'  {nid} --> {fid}')

    render(tree, root_id, 1)

    lines += [
        "  classDef folder fill:#0d1321,stroke:#1e2d40,color:#38bdf8",
        "  classDef file   fill:#070b12,stroke:#2d3f55,color:#c9d1d9",
    ]
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 02 — OSINT / SECRET SCANNING
# ─────────────────────────────────────────────────────────────────────────────
def phase_osint(repo_path: str) -> List[Finding]:
    ph("02", "OSINT", "Secret & Credential Scanning", PURPLE)
    findings: List[Finding] = []

    # ── Gitleaks ──────────────────────────────────────────
    if tool_available("gitleaks"):
        out_f = reposec_tmp("gitleaks_report.json")
        cmd = f"gitleaks detect --source . --report-format json --report-path {out_f} --no-banner"
        cmd_print(cmd)
        rc, _, _ = run(cmd, cwd=repo_path, timeout=120)
        if os.path.exists(out_f):
            try:
                with open(out_f) as f:
                    leaks = json.load(f) or []
                for leak in leaks[:50]:
                    findings.append(Finding(
                        phase="osint", tool="Gitleaks",
                        severity="CRITICAL",
                        title=f"Secret found: {leak.get('Description', leak.get('RuleID',''))}",
                        description=f"Match: {str(leak.get('Secret',''))[:80]} | Commit: {leak.get('Commit','')[:10]}",
                        file=leak.get("File", ""), line=str(leak.get("StartLine", "")),
                        remediation="Rotate credential immediately. Remove from history with git-filter-repo."
                    ))
                ok(f"Gitleaks: {len(leaks)} secrets found")
            except Exception as e:
                warn(f"Gitleaks parse error: {e}")
            os.remove(out_f)
        else:
            ok("Gitleaks: no secrets detected") if rc == 0 else warn("Gitleaks: scan failed")
    else:
        warn("gitleaks not found — skipping")

    # ── Trufflehog ────────────────────────────────────────
    if tool_available("trufflehog"):
        cmd = "trufflehog git file://. --json --no-update --only-verified 2>/dev/null"
        cmd_print(cmd)
        rc, out, _ = run(cmd, cwd=repo_path, timeout=180)
        count = 0
        for line in out.strip().splitlines():
            try:
                d = json.loads(line)
                det = d.get("DetectorName", "")
                raw = d.get("Raw", "")[:60]
                source = d.get("SourceMetadata", {}).get("Data", {})
                fpath = ""
                if isinstance(source, dict):
                    for v in source.values():
                        if isinstance(v, dict):
                            fpath = v.get("file", "")
                            break
                findings.append(Finding(
                    phase="osint", tool="Trufflehog",
                    severity="CRITICAL",
                    title=f"Verified secret: {det}",
                    description=f"Raw: {raw}",
                    file=fpath,
                    remediation="Revoke and rotate immediately. Use git-filter-repo to purge history."
                ))
                count += 1
            except Exception:
                pass
        ok(f"Trufflehog: {count} verified secrets found")
    else:
        warn("trufflehog not found — skipping")

    # ── git-secrets ───────────────────────────────────────
    if tool_available("git-secrets"):
        cmd = "git-secrets --scan -r . 2>&1"
        cmd_print(cmd)
        rc, out, stderr = run(cmd, cwd=repo_path, timeout=60)
        combined = (out + stderr).strip()
        if rc != 0 and combined:
            for line in combined.splitlines()[:20]:
                if line.strip():
                    findings.append(Finding(
                        phase="osint", tool="git-secrets",
                        severity="HIGH",
                        title="Potential secret pattern matched",
                        description=line[:200],
                        remediation="Review and remove the flagged pattern."
                    ))
            ok(f"git-secrets: {min(20, len(combined.splitlines()))} patterns flagged")
        else:
            ok("git-secrets: no patterns matched")
    else:
        warn("git-secrets not found — skipping")

    # ── grep — hardcoded secrets pattern ──────────────────
    cmd_print("grep -rn secret/password/token/api_key patterns")
    GREP_PATTERNS = [
        r'password\s*=\s*["\'][^"\']{4,}["\']',
        r'api_key\s*=\s*["\'][^"\']{8,}["\']',
        r'secret\s*=\s*["\'][^"\']{8,}["\']',
        r'token\s*=\s*["\'][^"\']{8,}["\']',
        r'-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY',
        r'(AKIA|ABIA|ACCA)[0-9A-Z]{16}',  # AWS
        r'ghp_[0-9a-zA-Z]{36}',            # GitHub PAT
        r'xox[baprs]-[0-9a-zA-Z]{10,}',   # Slack
    ]
    grep_count = 0
    for pat in GREP_PATTERNS:
        rc, out, _ = run(
            f'grep -rn --include="*.py" --include="*.js" --include="*.ts" '
            f'--include="*.env" --include="*.yml" --include="*.yaml" '
            f'--include="*.json" --include="*.rb" --include="*.go" '
            f'-E "{pat}" . 2>/dev/null | head -5',
            cwd=repo_path, timeout=30
        )
        for line in out.strip().splitlines()[:5]:
            parts = line.split(":", 2)
            findings.append(Finding(
                phase="osint", tool="grep",
                severity="HIGH",
                title=f"Hardcoded secret pattern: {pat[:40]}",
                description=line[:200],
                file=parts[0] if len(parts) >= 1 else "",
                line=parts[1] if len(parts) >= 2 else "",
                remediation="Move to environment variable or secrets manager."
            ))
            grep_count += 1
    ok(f"grep: {grep_count} hardcoded credential patterns found")
    _print_phase_summary(findings, "osint")
    return findings


INLINE_RULES: List[Dict] = [

    # ── eval-exec ─────────────────────────────────────────────────────────────
    {
        "id": "eval-atob-chain",
        "severity": "CRITICAL",
        "cwe": "CWE-95",
        "category": "eval-exec",
        "description": (
            "eval(atob(...)) — base64-decoded string executed directly. "
            "Most common two-stage payload delivery pattern in JS malware."
        ),
        "remediation": "Decode the base64 payload and audit its content. Remove dynamic eval().",
        "pattern": re.compile(
            r'(?:eval|window\[["\'`]eval["\'`]\]|globalThis\[["\'`]eval["\'`]\]|\(0,eval\))'
            r'\s*\(\s*atob\s*\(',
            re.IGNORECASE
        ),
        "extensions": {".js", ".ts", ".jsx", ".tsx", ".html", ".php"},
    },
    {
        "id": "function-constructor-obfuscated",
        "severity": "HIGH",
        "cwe": "CWE-95",
        "category": "eval-exec",
        "description": (
            "new Function() / Function() on decoded/transformed string. "
            "Semantically equivalent to eval() but bypasses eval-only scanners."
        ),
        "remediation": "Replace dynamic Function() construction with explicit, audited functions.",
        "pattern": re.compile(
            r'(?:new\s+Function|Function)\s*\(\s*(?:atob|unescape)\s*\(',
            re.IGNORECASE
        ),
        "extensions": {".js", ".ts", ".jsx", ".tsx"},
    },
    {
        "id": "settimeout-string-eval",
        "severity": "HIGH",
        "cwe": "CWE-95",
        "category": "eval-exec",
        "description": (
            "setTimeout/setInterval called with a string literal — "
            "these eval their string argument in global scope."
        ),
        "remediation": "Pass a function reference instead of a string to setTimeout/setInterval.",
        "pattern": re.compile(
            r"""\b(?:setTimeout|setInterval)\s*\(\s*["'`]""",
            re.IGNORECASE
        ),
        "extensions": {".js", ".ts", ".jsx", ".tsx", ".html"},
    },
    {
        "id": "python-exec-dynamic",
        "severity": "HIGH",
        "cwe": "CWE-95",
        "category": "eval-exec",
        "description": (
            "Python exec() or compile() on a non-literal expression — "
            "enables arbitrary code execution from external data."
        ),
        "remediation": "Avoid exec() with dynamic input. Use explicit function dispatch tables.",
        "pattern": re.compile(
            r'\bexec\s*\(\s*(?!(?:["\'].*["\']))',
            re.IGNORECASE
        ),
        "extensions": {".py"},
    },
    {
        "id": "php-eval-dynamic",
        "severity": "HIGH",
        "cwe": "CWE-95",
        "category": "eval-exec",
        "description": "PHP eval() on a non-literal — full arbitrary code execution sink.",
        "remediation": "Never use eval() in PHP. Refactor to a whitelist-based dispatch.",
        "pattern": re.compile(
            r'\beval\s*\(\s*\$',
            re.IGNORECASE
        ),
        "extensions": {".php"},
    },
    {
        "id": "powershell-iex-encoded",
        "severity": "HIGH",
        "cwe": "CWE-95",
        "category": "eval-exec",
        "description": (
            "PowerShell IEX/Invoke-Expression with encoded or piped content. "
            "Encoded commands hide payload from log-based detection."
        ),
        "remediation": "Avoid IEX with user-controlled or encoded input. Use approved cmdlets.",
        "pattern": re.compile(
            r'(?:iex|invoke-expression|invoke-command)\b.*(?:\||;|\n)'
            r'|-encodedcommand\s+[A-Za-z0-9+/=]{20,}',
            re.IGNORECASE
        ),
        "extensions": {".ps1", ".psm1", ".psd1"},
    },

    # ── network ───────────────────────────────────────────────────────────────
    {
        "id": "fetch-post-external-dynamic",
        "severity": "HIGH",
        "cwe": "CWE-359",
        "category": "network",
        "description": (
            "fetch() POST to a dynamically-constructed external URL. "
            "May transmit user data, credentials, or environment info to uncontrolled endpoint."
        ),
        "remediation": "Restrict fetch() calls to relative paths or an allowlist of trusted domains.",
        "pattern": re.compile(
            r"""fetch\s*\(\s*(?!(?:["'`]/|["'`]https?://localhost))"""
            r"""[^,)]{4,}[,)][^)]*method\s*:\s*["'`]POST["'`]""",
            re.IGNORECASE | re.DOTALL
        ),
        "extensions": {".js", ".ts", ".jsx", ".tsx"},
    },
    {
        "id": "xhr-open-external",
        "severity": "MEDIUM",
        "cwe": "CWE-359",
        "category": "network",
        "description": (
            "XMLHttpRequest.open() POST/PUT to a non-relative URL. "
            "Hardcoded external endpoints may indicate exfiltration."
        ),
        "remediation": "Validate and restrict XHR destination URLs against a server-side allowlist.",
        "pattern": re.compile(
            r"""\.open\s*\(\s*["'`](?:POST|PUT)["'`]\s*,\s*["'`]https?://""",
            re.IGNORECASE
        ),
        "extensions": {".js", ".ts", ".jsx", ".tsx"},
    },
    {
        "id": "cloud-storage-exfiltration",
        "severity": "HIGH",
        "cwe": "CWE-200",
        "category": "network",
        "description": (
            "Direct API call to cloud object storage (S3, GCS, Azure Blob, Dropbox). "
            "In unexpected contexts this strongly suggests data exfiltration."
        ),
        "remediation": "Audit all cloud storage calls. Verify legitimacy and restrict via IAM policies.",
        "pattern": re.compile(
            r'(?:s3\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net'
            r'|api\.dropboxapi\.com|content\.dropboxapi\.com|files\.slack\.com)/',
            re.IGNORECASE
        ),
        "extensions": {".js", ".ts", ".jsx", ".tsx", ".py", ".php", ".go", ".rb"},
    },
    {
        "id": "websocket-external-host",
        "severity": "MEDIUM",
        "cwe": "CWE-200",
        "category": "network",
        "description": (
            "WebSocket connection to a non-local host. "
            "Persistent channels are less visible and used for covert C2."
        ),
        "remediation": "Validate WebSocket server origins. Enforce WSS and origin checking.",
        "pattern": re.compile(
            r"""new\s+WebSocket\s*\(\s*["'`]wss?://(?!localhost|127\.0\.0\.1)""",
            re.IGNORECASE
        ),
        "extensions": {".js", ".ts", ".jsx", ".tsx"},
    },
    {
        "id": "dns-tunneling-subdomain-construction",
        "severity": "HIGH",
        "cwe": "CWE-200",
        "category": "network",
        "description": (
            "Dynamic domain construction by appending encoded data as subdomains — "
            "canonical DNS tunneling exfiltration pattern."
        ),
        "remediation": "Never construct DNS names from user-controlled or encoded data.",
        "pattern": re.compile(
            r"""(?:btoa|atob|encode|hex|b64|chunk|split)[^+]*\+\s*["'`]\.[^"'`]+["'`]""",
            re.IGNORECASE
        ),
        "extensions": {".js", ".ts", ".py"},
    },
    {
        "id": "beacon-api-external",
        "severity": "MEDIUM",
        "cwe": "CWE-359",
        "category": "network",
        "description": (
            "navigator.sendBeacon() to a non-relative URL. "
            "Fire-and-forget POST completing after page unload — used for silent exfiltration."
        ),
        "remediation": "Restrict Beacon API targets to relative paths or trusted domains.",
        "pattern": re.compile(
            r"""navigator\.sendBeacon\s*\(\s*["'`]https?://""",
            re.IGNORECASE
        ),
        "extensions": {".js", ".ts", ".jsx", ".tsx"},
    },

    # ── obfuscation ───────────────────────────────────────────────────────────
    {
        "id": "js-obfuscator-hex-variables",
        "severity": "MEDIUM",
        "cwe": "CWE-506",
        "category": "obfuscation",
        "description": (
            "_0x<hex> variable names — canonical output of js-obfuscator / obfuscator.io. "
            "Deobfuscate with: npx js-beautify + de4js, or synchrony."
        ),
        "remediation": "Run a JS deobfuscator (synchrony, de4js) and re-audit the output.",
        "pattern": re.compile(r'\b_0x[0-9a-fA-F]{3,8}\b'),
        "extensions": {".js", ".ts", ".jsx", ".tsx"},
    },
    {
        "id": "base64-long-literal",
        "severity": "MEDIUM",
        "cwe": "CWE-506",
        "category": "obfuscation",
        "description": (
            "Long Base64 string literal (>=60 chars). May encode a hidden payload. "
            "Decode and inspect when adjacent to eval, atob, or network calls."
        ),
        "remediation": "Decode the string and verify its contents. Avoid embedding large b64 blobs.",
        "pattern": re.compile(r'''["'][A-Za-z0-9+/]{60,}={0,2}["']'''),
        "extensions": {".js", ".ts", ".jsx", ".tsx", ".php", ".py"},
    },
    {
        "id": "hex-byte-array-shellcode",
        "severity": "HIGH",
        "cwe": "CWE-506",
        "category": "obfuscation",
        "description": (
            "Dense hex byte array (12+ values) — characteristic of inline shellcode, "
            "binary payload storage, or encrypted data staging."
        ),
        "remediation": "Inspect surrounding context for execution primitives (exec, eval, WASM).",
        "pattern": re.compile(r'(?:0x[0-9a-fA-F]{2},\s*){12,}'),
        "extensions": {".js", ".ts", ".py", ".php"},
    },
    {
        "id": "unicode-escape-sequence-cluster",
        "severity": "MEDIUM",
        "cwe": "CWE-116",
        "category": "obfuscation",
        "description": (
            "3+ consecutive Unicode/hex escape sequences — used to hide keywords "
            "like eval, fetch, exec from static scanners."
        ),
        "remediation": "Resolve all escape sequences and re-audit. Flag code that uses this technique.",
        "pattern": re.compile(r'(?:\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}){3,}'),
        "extensions": {".js", ".ts", ".jsx", ".tsx", ".php"},
    },
    {
        "id": "string-split-reverse-join",
        "severity": "MEDIUM",
        "cwe": "CWE-116",
        "category": "obfuscation",
        "description": (
            "String reconstructed via split/reverse/join — hides keywords like "
            "'eval', 'system', or URLs from static scanners."
        ),
        "remediation": "Evaluate the reconstructed string and audit it. Remove obfuscated constructs.",
        "pattern": re.compile(
            r'''["'`][^"'`]+["'`]\s*\.split\s*\([^)]*\)\s*\.(?:reverse\s*\(\s*\)\s*\.)?\s*join\s*\('''
        ),
        "extensions": {".js", ".ts", ".jsx", ".tsx", ".php"},
    },
    {
        "id": "dynamic-bracket-notation-call",
        "severity": "MEDIUM",
        "cwe": "CWE-116",
        "category": "obfuscation",
        "description": (
            "Method call via bracket notation on decoded string — hides "
            "eval/fetch/XMLHttpRequest from static scanners."
        ),
        "remediation": "Resolve the decoded key and refactor to explicit method calls.",
        "pattern": re.compile(
            r'\w+\s*\[\s*(?:atob|unescape|String\.fromCharCode)\s*\(',
            re.IGNORECASE
        ),
        "extensions": {".js", ".ts", ".jsx", ".tsx"},
    },
    {
        "id": "nonprintable-zero-width-chars",
        "severity": "HIGH",
        "cwe": "CWE-116",
        "category": "obfuscation",
        "description": (
            "Zero-width / non-printable Unicode chars in source — "
            "used for Trojan Source attacks, bypass string matching, or steganographic data."
        ),
        "remediation": "Strip all zero-width characters and re-review. Enable editor invisible-char display.",
        "pattern": re.compile(
            r'[\u200B\u200C\u200D\u2060\uFEFF\u180E\u00AD\u2028\u2029]'
        ),
        "extensions": {".js", ".ts", ".jsx", ".tsx", ".py", ".php"},
    },
    {
        "id": "mz-pe-header-embedded",
        "severity": "CRITICAL",
        "cwe": "CWE-506",
        "category": "obfuscation",
        "description": (
            "MZ/PE magic bytes in encoded strings — embedded Windows executable "
            "or reflective DLL injection payload. TVqQ is base64(MZ header)."
        ),
        "remediation": "Quarantine file immediately. Investigate for malware or supply-chain compromise.",
        "pattern": re.compile(
            r'(?:TVqQAA|TVoAAA|4d5a90|\\x4d\\x5a\\x90)',
            re.IGNORECASE
        ),
        "extensions": {".js", ".ts", ".py", ".php", ".txt", ".json"},
    },

    # ── css-chains ────────────────────────────────────────────────────────────
    {
        "id": "css-import-external-domain",
        "severity": "HIGH",
        "cwe": "CWE-830",
        "category": "css-chains",
        "description": (
            "CSS @import of external domain (non-Google Fonts). "
            "External stylesheets can exfiltrate attribute values via selector timing or keylogger CSS."
        ),
        "remediation": "Enforce SRI hashes on all external @import sources. Self-host where possible.",
        "pattern": re.compile(
            r'@import\s+(?:url\s*\()?["\']?'
            r'https?://(?!fonts\.googleapis\.com|fonts\.gstatic\.com)'
            r'[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}',
            re.IGNORECASE
        ),
        "extensions": {".css", ".scss", ".less", ".html", ".php"},
    },
    {
        "id": "css-attribute-selector-exfiltration",
        "severity": "HIGH",
        "cwe": "CWE-200",
        "category": "css-chains",
        "description": (
            "CSS attribute selector combined with remote url() call — "
            "leaks form field values / tokens character-by-character via CSS injection (no JS)."
        ),
        "remediation": "Sanitize any user-controlled CSS. Audit for injected attribute selectors.",
        "pattern": re.compile(
            r'\[[a-zA-Z\-]+[\^$*~|]?=["\'][^"\']{0,32}["\']\]\s*\{[^}]*url\s*\(\s*["\']?https?://',
            re.IGNORECASE
        ),
        "extensions": {".css", ".scss"},
    },
    {
        "id": "css-data-uri-import",
        "severity": "HIGH",
        "cwe": "CWE-116",
        "category": "css-chains",
        "description": (
            "CSS @import of data: URI — embeds entire stylesheet payload, "
            "common exfiltration carrier in CSS injection attacks."
        ),
        "remediation": "Block data: URI imports via CSP. Strip them from user-supplied CSS.",
        "pattern": re.compile(
            r'@import\s+(?:url\s*\()?["\']?data:',
            re.IGNORECASE
        ),
        "extensions": {".css", ".scss", ".less"},
    },
    {
        "id": "css-expression-ie",
        "severity": "HIGH",
        "cwe": "CWE-79",
        "category": "css-chains",
        "description": (
            "CSS expression() — IE-era arbitrary JS execution in stylesheets. "
            "Still accepted by some parsers in compatibility mode."
        ),
        "remediation": "Remove all expression() usages. Migrate IE-era codebases.",
        "pattern": re.compile(r'\bexpression\s*\(', re.IGNORECASE),
        "extensions": {".css", ".scss", ".less"},
    },

    # ── webworker ─────────────────────────────────────────────────────────────
    {
        "id": "webworker-blob-eval",
        "severity": "HIGH",
        "cwe": "CWE-116",
        "category": "webworker",
        "description": (
            "Worker from Blob URL with eval/Function/importScripts content — "
            "CSP-isolated sandbox invisible to main-thread monitoring."
        ),
        "remediation": "Avoid eval-like constructs in Blob workers. Use dedicated worker files.",
        "pattern": re.compile(
            r'new\s+Worker\s*\(\s*URL\.createObjectURL\s*\(\s*new\s+Blob\s*\(',
            re.IGNORECASE
        ),
        "extensions": {".js", ".ts", ".jsx", ".tsx"},
    },
    {
        "id": "webworker-dynamic-importscripts",
        "severity": "HIGH",
        "cwe": "CWE-829",
        "category": "webworker",
        "description": (
            "importScripts() with non-literal URL in Worker — loads arbitrary external "
            "scripts without triggering main-thread CSP."
        ),
        "remediation": "Use only static literal URLs with importScripts(). Enforce SRI.",
        "pattern": re.compile(
            r"""\bimportScripts\s*\(\s*(?!["'`])""",
            re.IGNORECASE
        ),
        "extensions": {".js", ".ts"},
    },
    {
        "id": "webworker-postmessage-eval",
        "severity": "HIGH",
        "cwe": "CWE-95",
        "category": "webworker",
        "description": (
            "postMessage data passed directly to eval() in Worker — "
            "attacker controlling message sender achieves arbitrary code execution."
        ),
        "remediation": "Never eval() postMessage data. Validate and parse message payloads explicitly.",
        "pattern": re.compile(
            r"""(?:onmessage|addEventListener\s*\(\s*["'`]message["'`])"""
            r'[^}]{0,300}eval\s*\(',
            re.IGNORECASE | re.DOTALL
        ),
        "extensions": {".js", ".ts"},
    },
    {
        "id": "webworker-sharedarraybuffer-timing",
        "severity": "MEDIUM",
        "cwe": "CWE-203",
        "category": "webworker",
        "description": (
            "SharedArrayBuffer + Atomics.wait polling loop — implements "
            "sub-millisecond timers enabling Spectre-class cache side-channel attacks."
        ),
        "remediation": "Set COOP+COEP response headers. Limit SharedArrayBuffer usage.",
        "pattern": re.compile(
            r'new\s+SharedArrayBuffer[^;]{0,300}Atomics\.wait(?:Async)?',
            re.IGNORECASE | re.DOTALL
        ),
        "extensions": {".js", ".ts"},
    },

    # ── wasm ──────────────────────────────────────────────────────────────────
    {
        "id": "wasm-dynamic-instantiation",
        "severity": "HIGH",
        "cwe": "CWE-829",
        "category": "wasm",
        "description": (
            "WebAssembly instantiated from dynamic/non-literal source — "
            "possible obfuscated payload delivery."
        ),
        "remediation": "Verify WASM origin. Enforce SRI hashes on all .wasm fetches.",
        "pattern": re.compile(
            r'WebAssembly\.(?:instantiate|instantiateStreaming|compile)\s*\(',
            re.IGNORECASE
        ),
        "extensions": {".js", ".ts", ".jsx", ".tsx"},
    },
    {
        "id": "wasm-base64-magic-bytes",
        "severity": "HIGH",
        "cwe": "CWE-506",
        "category": "wasm",
        "description": (
            "Base64-encoded WASM magic bytes (AGFzbQ == \\0asm) — "
            "embedded WASM binary likely decoded and executed at runtime."
        ),
        "remediation": "Decompile and audit the embedded WASM binary before deployment.",
        "pattern": re.compile(r'AGFzbQ[A-Za-z0-9+/=]{4,}'),
        "extensions": {".js", ".ts", ".jsx", ".tsx", ".php", ".py"},
    },
    {
        "id": "wasm-fetch-arraybuffer-chain",
        "severity": "HIGH",
        "cwe": "CWE-829",
        "category": "wasm",
        "description": (
            "fetch()→arrayBuffer()→WebAssembly.instantiate() chain — "
            "runtime-fetched WASM binary with immediate execution."
        ),
        "remediation": "Add SRI verification before instantiating fetched WASM.",
        "pattern": re.compile(
            r'fetch\s*\([^)]+\)[^;]{0,200}arrayBuffer\s*\(\s*\)[^;]{0,200}'
            r'WebAssembly\.instantiate',
            re.IGNORECASE | re.DOTALL
        ),
        "extensions": {".js", ".ts"},
    },
    {
        "id": "wasm-suspicious-import-names",
        "severity": "HIGH",
        "cwe": "CWE-78",
        "category": "wasm",
        "description": (
            "WASM import object with eval/exec/shell-like key names — "
            "review the WASM binary's imported host functions."
        ),
        "remediation": "Audit WASM import objects for dangerous host-function bindings.",
        "pattern": re.compile(
            r'WebAssembly\.instantiate[^{]{0,100}\{[^}]{0,300}'
            r'(?:eval|exec|system|popen|shell|spawn|run_cmd|invoke)',
            re.IGNORECASE | re.DOTALL
        ),
        "extensions": {".js", ".ts"},
    },
]

# ─────────────────────────────────────────────────────────────────────────────
# DATA MODEL
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Finding:
    phase:       str
    tool:        str
    severity:    str
    title:       str
    description: str = ""
    file:        str = ""
    line:        str = ""
    cve:         str = ""
    cwe:         str = ""
    package:     str = ""
    remediation: str = ""

    def sev_norm(self):
        s = self.severity.upper()
        return s if s in SEV_ORDER else "INFO"

    def __post_init__(self):
        for attr in ("line","cve","cwe","package","remediation","description","file"):
            val = getattr(self, attr)
            setattr(self, attr, str(val) if val is not None else "")


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def tool_available(name: str) -> bool:
    return shutil.which(name) is not None

def run(cmd: str, cwd: str = ".", timeout: int = 300,
        env: Optional[Dict[str, str]] = None) -> Tuple[int, str, str]:
    try:
        e = {**os.environ, **(env or {})}
        r = subprocess.run(
            cmd, shell=True, cwd=cwd, capture_output=True,  # nosec B602 - intentional: cmd strings use pipes/redirects
            text=True, timeout=timeout, env=e
        )
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"TIMEOUT after {timeout}s"
    except Exception as ex:
        return -1, "", str(ex)

def normalize_sev(raw: str) -> str:
    raw = (raw or "").upper()
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if s in raw:
            return s
    return "INFO"

def ph(num, tag, name, color=CYAN):
    print(f"\n{color}{B}{'═'*60}{R}")
    print(f"{color}{B}  PHASE {num} / {tag} — {name}{R}")
    print(f"{color}{B}{'═'*60}{R}")

def ok(msg):   print(f"  {GREEN}✓{R} {msg}")
def warn(msg): print(f"  {YELLOW}⚠{R} {msg}")
def err(msg):  print(f"  {RED}✗{R} {msg}")
def info(msg): print(f"  {GREY}·{R} {msg}")
def cmd_print(c): print(f"  {GREY}${R} {c}")


# ─────────────────────────────────────────────────────────────────────────────
# PHASE A — INLINE OBFUSCATION SCANNER  (new, uses INLINE_RULES above)
# ─────────────────────────────────────────────────────────────────────────────
def phase_inline_scan(repo_path: str) -> List[Finding]:
    """
    Multi-rule inline regex scanner covering all 6 custom YAML rule-sets:
    eval-exec, network, obfuscation, css-chains, webworker, wasm.
    Walks every file in the repo, matches by extension, reports findings.
    """
    ph("A", "INLINE", "Integrated Obfuscation & Payload Detection", PURPLE)
    findings: List[Finding] = []

    # Build extension → rules map for O(1) lookup per file
    ext_rule_map: Dict[str, List[Dict]] = {}
    for rule in INLINE_RULES:
        for ext in rule["extensions"]:
            ext_rule_map.setdefault(ext, []).append(rule)

    file_count = 0
    match_count = 0

    SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv',
                 'vendor', 'dist', 'build', '.mypy_cache', '.pytest_cache'}

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            ext = Path(fname).suffix.lower()
            rules_for_ext = ext_rule_map.get(ext, [])
            if not rules_for_ext:
                continue
            fpath = os.path.join(root, fname)
            rel   = os.path.relpath(fpath, repo_path)
            try:
                with open(fpath, encoding="utf-8", errors="replace") as fh:
                    lines = fh.readlines()
            except Exception:
                continue

            file_count += 1
            full_text = "".join(lines)

            for rule in rules_for_ext:
                # Line-by-line matching for precise line numbers
                for lineno, line_text in enumerate(lines, 1):
                    if rule["pattern"].search(line_text):
                        findings.append(Finding(
                            phase="inline",
                            tool=f"InlineScan/{rule['category']}",
                            severity=rule["severity"],
                            title=f"[{rule['id']}] {rule['description'][:90]}",
                            description=rule["description"],
                            file=rel,
                            line=str(lineno),
                            cwe=rule["cwe"],
                            remediation=rule["remediation"]
                        ))
                        match_count += 1
                        break  # one finding per rule per file (avoid noise)

                # For multi-line patterns, also scan full text
                else:
                    if rule["pattern"].flags & re.DOTALL:
                        if rule["pattern"].search(full_text):
                            findings.append(Finding(
                                phase="inline",
                                tool=f"InlineScan/{rule['category']}",
                                severity=rule["severity"],
                                title=f"[{rule['id']}] {rule['description'][:90]}",
                                description=rule["description"],
                                file=rel,
                                cwe=rule["cwe"],
                                remediation=rule["remediation"]
                            ))
                            match_count += 1

    ok(f"Scanned {file_count} files → {match_count} pattern matches across {len(INLINE_RULES)} rules")

    # Summary by category
    cat_counts: Dict[str, int] = {}
    for f in findings:
        cat = f.tool.split("/")[-1]
        cat_counts[cat] = cat_counts.get(cat, 0) + 1
    for cat, cnt in sorted(cat_counts.items()):
        info(f"  {cat}: {cnt} findings")

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# PHASE B — SEMGREP WITH CUSTOM YAML RULES  (writes rules to disk, runs)
# ─────────────────────────────────────────────────────────────────────────────
SEMGREP_RULES_YAML = """
rules:
  - id: eval-atob-chain
    message: "eval(atob(...)) base64-decoded string executed directly."
    severity: ERROR
    languages: [javascript, typescript]
    pattern-regex: '(?:eval|window\\[["'\\''"]eval["'\\''"]\\]|\\(0,eval\\))\\s*\\(\\s*atob\\s*\\('
    metadata: {cwe: CWE-95, category: eval-exec}

  - id: js-obfuscator-hex-vars
    message: "_0x hex variable names — canonical js-obfuscator output."
    severity: WARNING
    languages: [javascript, typescript]
    pattern-regex: '\\b_0x[0-9a-fA-F]{3,8}\\b'
    metadata: {cwe: CWE-506, category: obfuscation}

  - id: base64-long-literal
    message: "Long Base64 literal (>=60 chars) — possible hidden payload."
    severity: WARNING
    languages: [javascript, typescript, python, php]
    pattern-regex: '["'\\''"][A-Za-z0-9+/]{60,}={0,2}["'\\''"]'
    metadata: {cwe: CWE-506, category: obfuscation}

  - id: hex-shellcode-array
    message: "Dense hex byte array — possible shellcode or payload staging."
    severity: ERROR
    languages: [javascript, typescript, python, php]
    pattern-regex: '(?:0x[0-9a-fA-F]{2},\\s*){12,}'
    metadata: {cwe: CWE-506, category: obfuscation}

  - id: unicode-escape-cluster
    message: "3+ consecutive Unicode/hex escapes — keyword hiding technique."
    severity: WARNING
    languages: [javascript, typescript, php]
    pattern-regex: '(?:\\\\u[0-9a-fA-F]{4}|\\\\x[0-9a-fA-F]{2}){3,}'
    metadata: {cwe: CWE-116, category: obfuscation}

  - id: mz-pe-header-embedded
    message: "MZ/PE header magic bytes — embedded Windows executable or DLL payload."
    severity: ERROR
    languages: [javascript, typescript, python, php, generic]
    pattern-regex: '(?:TVqQAA|TVoAAA|4d5a90|\\\\x4d\\\\x5a\\\\x90)'
    metadata: {cwe: CWE-506, category: obfuscation}

  - id: wasm-base64-magic
    message: "WASM magic bytes in base64 (AGFzbQ) — embedded WASM binary."
    severity: ERROR
    languages: [javascript, typescript, php, python]
    pattern-regex: 'AGFzbQ[A-Za-z0-9+/=]{4,}'
    metadata: {cwe: CWE-506, category: wasm}

  - id: css-import-external
    message: "CSS @import external domain — potential CSS injection/exfil vector."
    severity: ERROR
    languages: [generic]
    paths:
      include: ["*.css", "*.scss", "*.less", "*.html"]
    pattern-regex: '@import\\s+(?:url\\s*\\()?["\\'\\''']?https?://(?!fonts\\.googleapis\\.com|fonts\\.gstatic\\.com)'
    metadata: {cwe: CWE-830, category: css-chains}

  - id: css-expression-ie
    message: "CSS expression() — IE-era arbitrary JS execution in stylesheets."
    severity: ERROR
    languages: [generic]
    paths:
      include: ["*.css", "*.scss", "*.less"]
    pattern-regex: '(?i)\\bexpression\\s*\\('
    metadata: {cwe: CWE-79, category: css-chains}

  - id: cloud-storage-call
    message: "Direct cloud storage API call — possible data exfiltration."
    severity: ERROR
    languages: [javascript, typescript, python, php]
    pattern-regex: '(?:s3\\.amazonaws\\.com|storage\\.googleapis\\.com|blob\\.core\\.windows\\.net|api\\.dropboxapi\\.com)/'
    metadata: {cwe: CWE-200, category: network}

  - id: beacon-api-external
    message: "navigator.sendBeacon() to external URL — silent data exfiltration."
    severity: WARNING
    languages: [javascript, typescript]
    pattern-regex: 'navigator\\.sendBeacon\\s*\\(\\s*["'\\''"]https?://'
    metadata: {cwe: CWE-359, category: network}

  - id: powershell-iex-encoded
    message: "PowerShell IEX/Invoke-Expression with encoded command."
    severity: ERROR
    languages: [generic]
    paths:
      include: ["*.ps1", "*.psm1", "*.psd1"]
    pattern-regex: '(?i)\\b(?:iex|invoke-expression)\\b.*(?:\\||;)|\\-encodedcommand\\s+[A-Za-z0-9+/=]{20,}'
    metadata: {cwe: CWE-95, category: eval-exec}
"""

def phase_semgrep_custom(repo_path: str, rules_dir: str) -> List[Finding]:
    """Run semgrep with both auto config and our custom rules file."""
    ph("B", "SEMGREP", "Semgrep — Custom Rule Set (All 6 Categories)", GREEN)
    findings: List[Finding] = []

    if not tool_available("semgrep"):
        warn("semgrep not found — install: pip install semgrep")
        return findings

    # Write custom rules
    custom_yml = os.path.join(rules_dir, "reposec_custom.yml")
    with open(custom_yml, "w") as f:
        f.write(SEMGREP_RULES_YAML)

    out_f = os.path.join(rules_dir, "semgrep_custom.json")

    # Run with custom rules
    cmd = (f"semgrep --config={custom_yml} "
           f"--json --output={out_f} --quiet . 2>/dev/null")
    cmd_print(cmd)
    run(cmd, cwd=repo_path, timeout=300)

    if os.path.exists(out_f):
        try:
            with open(out_f) as f:
                data = json.load(f)
            for r in data.get("results", [])[:200]:
                sev_raw = r.get("extra", {}).get("severity", "WARNING")
                sev = normalize_sev(sev_raw)
                msg = r.get("extra", {}).get("message", r.get("check_id",""))
                metadata = r.get("extra", {}).get("metadata", {})
                cwe = metadata.get("cwe", "")
                findings.append(Finding(
                    phase="semgrep_custom",
                    tool=f"Semgrep-Custom/{metadata.get('category','unknown')}",
                    severity=sev,
                    title=msg[:120],
                    description=f"Rule: {r.get('check_id','')} | {metadata.get('category','')}",
                    file=r.get("path",""),
                    line=str(r.get("start",{}).get("line","")),
                    cwe=cwe,
                    remediation="Review the flagged pattern and apply rule-specific remediation."
                ))
            ok(f"Semgrep custom rules: {len(findings)} findings")
        except Exception as e:
            warn(f"Semgrep custom parse error: {e}")
    else:
        ok("Semgrep: no findings")

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# DISCOVERY (simplified from original)
# ─────────────────────────────────────────────────────────────────────────────
def phase_discovery_meta_only(repo_path: str) -> Dict[str, Any]:
    ph("01", "RECON", "Repository Discovery & Cataloging", CYAN)
    p = Path(repo_path)
    meta: Dict[str, Any] = {
        "path": str(p), "name": p.name, "files": 0, "dirs": 0,
        "languages": {}, "manifests": [], "sensitive": []
    }

    MANIFEST_NAMES = {"package.json","requirements.txt","go.mod","cargo.toml",
                      "pom.xml","build.gradle","dockerfile","docker-compose.yml",
                      "gemfile","pyproject.toml"}
    SENSITIVE_PAT = re.compile(
        r'(\.env$|\.pem$|\.key$|\.crt$|\.p12$|\.pfx$|secret|credential|'
        r'password|\.ovpn$|id_rsa|\.ppk$)', re.I)

    ext_counts: Dict[str, int] = {}
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if not d.startswith('.')
                   and d not in ('node_modules','__pycache__','.git','vendor','dist','build')]
        for fname in files:
            ext = Path(fname).suffix.lower().lstrip('.')
            if ext:
                ext_counts[ext] = ext_counts.get(ext, 0) + 1
            if fname.lower() in MANIFEST_NAMES:
                meta["manifests"].append(fname)
            if SENSITIVE_PAT.search(fname):
                meta["sensitive"].append(fname)
        meta["dirs"] += len(dirs)
        meta["files"] += len(files)

    meta["languages"] = dict(sorted(ext_counts.items(), key=lambda x: -x[1])[:10])
    ok(f"Cataloged {meta['files']} files across {meta['dirs']} directories")
    if meta["sensitive"]:
        warn(f"Sensitive file patterns: {', '.join(meta['sensitive'][:6])}")
    return meta


    _print_phase_summary(findings, "osint")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 03 — SCA
# ─────────────────────────────────────────────────────────────────────────────
def phase_sca(repo_path: str) -> List[Finding]:
    ph("03", "SCA", "Software Composition Analysis", ORANGE)
    findings: List[Finding] = []

    # ── Syft — SBOM generation ────────────────────────────
    if tool_available("syft"):
        sbom_f = reposec_tmp("sbom.json")
        cmd = f"syft . -o json={sbom_f} 2>/dev/null"
        cmd_print(cmd)
        run(cmd, cwd=repo_path, timeout=180)
        if os.path.exists(sbom_f):
            try:
                with open(sbom_f) as f:
                    sbom = json.load(f)
                pkg_count = len(sbom.get("artifacts", []))
                ok(f"Syft SBOM: {pkg_count} components cataloged → {sbom_f}")
            except Exception:
                ok("Syft SBOM generated")
        else:
            warn("Syft: SBOM generation failed")
    else:
        warn("syft not found — skipping SBOM")

    # ── Grype — vulnerability scan ────────────────────────
    if tool_available("grype"):
        out_f = reposec_tmp("grype.json")
        cmd = f"grype . --output json --file {out_f} 2>/dev/null"
        cmd_print(cmd)
        run(cmd, cwd=repo_path, timeout=300)
        if os.path.exists(out_f):
            try:
                with open(out_f) as f:
                    data = json.load(f)
                for match in data.get("matches", [])[:60]:
                    vuln = match.get("vulnerability", {})
                    art  = match.get("artifact", {})
                    sev  = normalize_sev(vuln.get("severity", "MEDIUM"))
                    cves = vuln.get("relatedVulnerabilities", [])
                    cve  = vuln.get("id", "")
                    if not cve.startswith("CVE") and cves:
                        cve = cves[0].get("id", "")
                    findings.append(Finding(
                        phase="sca", tool="Grype",
                        severity=sev,
                        title=f"{vuln.get('id','')} in {art.get('name','')}@{art.get('version','')}",
                        description=vuln.get("description", "")[:300],
                        package=f"{art.get('name','')}@{art.get('version','')}",
                        cve=cve,
                        remediation=f"Fixed in: {vuln.get('fix',{}).get('versions',['unknown'])[0] if vuln.get('fix',{}).get('versions') else 'check advisory'}"
                    ))
                ok(f"Grype: {len(data.get('matches', []))} vulnerabilities found")
            except Exception as e:
                warn(f"Grype parse error: {e}")
            os.remove(out_f)
        else:
            warn("Grype: scan failed")
    else:
        warn("grype not found — skipping")

    # ── OWASP Dependency-Check ────────────────────────────
    dc_cmd = None
    for c in ("dependency-check", "dependency-check.sh"):
        if tool_available(c):
            dc_cmd = c
            break
    if dc_cmd:
        out_dir = reposec_tmp("dc_report")
        cmd = (f"{dc_cmd} --scan . --format JSON "
               f"--out {out_dir} --noupdate 2>/dev/null")
        cmd_print(cmd)
        run(cmd, cwd=repo_path, timeout=600)
        report_f = f"{out_dir}/dependency-check-report.json"
        if os.path.exists(report_f):
            try:
                with open(report_f) as f:
                    data = json.load(f)
                for dep in data.get("dependencies", []):
                    for vuln in dep.get("vulnerabilities", [])[:5]:
                        sev = normalize_sev(vuln.get("severity", "MEDIUM"))
                        findings.append(Finding(
                            phase="sca", tool="OWASP Dependency-Check",
                            severity=sev,
                            title=f"{vuln.get('name','')} — {dep.get('fileName','')}",
                            description=vuln.get("description", "")[:300],
                            cve=vuln.get("name", ""),
                            package=dep.get("fileName", ""),
                            remediation="Update to patched version per NVD advisory."
                        ))
                ok(f"OWASP Dependency-Check: findings parsed")
            except Exception as e:
                warn(f"OWASP DC parse error: {e}")
        else:
            warn("OWASP Dependency-Check: report not found")
    else:
        warn("dependency-check not found — skipping")

    # ── Safety (Python) ───────────────────────────────────
    if tool_available("safety"):
        cmd = "safety check --json 2>/dev/null"
        cmd_print(cmd)
        rc, out, _ = run(cmd, cwd=repo_path, timeout=120)
        try:
            data = json.loads(out) if out.strip() else []
            vulns = data if isinstance(data, list) else data.get("vulnerabilities", [])
            for v in vulns[:30]:
                if isinstance(v, list) and len(v) >= 5:
                    findings.append(Finding(
                        phase="sca", tool="Safety-CLI",
                        severity="HIGH",
                        title=f"Vulnerable Python pkg: {v[0]}",
                        description=str(v[4])[:300],
                        package=f"{v[0]}=={v[2]}",
                        cve=str(v[4])[:20] if v[4] else "",
                        remediation=f"Upgrade {v[0]} to {v[1]}"
                    ))
                elif isinstance(v, dict):
                    findings.append(Finding(
                        phase="sca", tool="Safety-CLI",
                        severity=normalize_sev(v.get("severity","HIGH")),
                        title=f"Vulnerable Python pkg: {v.get('package_name','')}",
                        description=v.get("advisory","")[:300],
                        package=v.get("package_name",""),
                        cve=v.get("CVE",""),
                        remediation=f"Upgrade to {v.get('analyzed_requirement','latest')}"
                    ))
            ok(f"Safety: {len(vulns)} vulnerable Python packages")
        except Exception:
            ok("Safety: no vulnerabilities or requirements.txt not found")
    else:
        warn("safety not found — skipping")

    # ── pip-audit ─────────────────────────────────────────
    if tool_available("pip-audit"):
        cmd = "pip-audit --format json -r requirements.txt 2>/dev/null"
        req = Path(repo_path) / "requirements.txt"
        if req.exists():
            cmd_print(cmd)
            rc, out, _ = run(cmd, cwd=repo_path, timeout=120)
            try:
                data = json.loads(out)
                for dep in data.get("dependencies", []):
                    for vuln in dep.get("vulns", []):
                        findings.append(Finding(
                            phase="sca", tool="pip-audit",
                            severity="HIGH",
                            title=f"{vuln.get('id','')} in {dep.get('name','')}",
                            description=vuln.get("description","")[:300],
                            package=f"{dep.get('name','')}=={dep.get('version','')}",
                            cve=vuln.get("id",""),
                            remediation=f"Fix versions: {vuln.get('fix_versions', [])}"
                        ))
                ok(f"pip-audit: {sum(len(d.get('vulns',[])) for d in data.get('dependencies',[]))} vulns")
            except Exception:
                ok("pip-audit: no vulnerabilities")
        else:
            info("pip-audit: no requirements.txt found")
    else:
        warn("pip-audit not found — skipping")

    # ── cargo audit (Rust) ────────────────────────────────
    if tool_available("cargo") and (Path(repo_path) / "Cargo.toml").exists():
        cmd = "cargo audit --json 2>/dev/null"
        cmd_print(cmd)
        rc, out, _ = run(cmd, cwd=repo_path, timeout=120)
        try:
            data = json.loads(out)
            for vuln in data.get("vulnerabilities", {}).get("list", []):
                adv = vuln.get("advisory", {})
                findings.append(Finding(
                    phase="sca", tool="cargo audit",
                    severity=normalize_sev(adv.get("severity","HIGH")),
                    title=f"{adv.get('id','')} — {vuln.get('package',{}).get('name','')}",
                    description=adv.get("description","")[:300],
                    package=f"{vuln.get('package',{}).get('name','')}@{vuln.get('package',{}).get('version','')}",
                    cve=adv.get("aliases",[""])[0] if adv.get("aliases") else "",
                    remediation=f"Upgrade to {adv.get('patched_versions','latest')}"
                ))
            ok(f"cargo audit: {len(data.get('vulnerabilities',{}).get('list',[]))} issues")
        except Exception:
            ok("cargo audit: no vulnerabilities found")
    elif (Path(repo_path) / "Cargo.toml").exists():
        warn("cargo not found — skipping Rust audit")

    # ── osv-scanner ───────────────────────────────────────
    if tool_available("osv-scanner"):
        cmd = "osv-scanner --format json . 2>/dev/null"
        cmd_print(cmd)
        rc, out, _ = run(cmd, cwd=repo_path, timeout=180)
        try:
            data = json.loads(out)
            for result in data.get("results", []):
                for pkg in result.get("packages", []):
                    for vuln in pkg.get("vulnerabilities", [])[:5]:
                        sev = "MEDIUM"
                        for sev_obj in vuln.get("database_specific", {}).get("severity",[]):
                            sev = normalize_sev(sev_obj.get("type","MEDIUM"))
                        findings.append(Finding(
                            phase="sca", tool="osv-scanner",
                            severity=sev,
                            title=f"{vuln.get('id','')} in {pkg.get('package',{}).get('name','')}",
                            description=vuln.get("summary","")[:300],
                            package=pkg.get("package",{}).get("name",""),
                            cve=vuln.get("id",""),
                            remediation="Check OSV advisory for patched versions."
                        ))
            total = sum(len(p.get("vulnerabilities",[])) for r in data.get("results",[]) for p in r.get("packages",[]))
            ok(f"osv-scanner: {total} vulnerabilities")
        except Exception:
            ok("osv-scanner: clean or no lock files found")
    else:
        warn("osv-scanner not found — skipping")

    # ── Snyk ──────────────────────────────────────────────
    if tool_available("snyk"):
        cmd = "snyk code test --json-file-output=vuln.json 2>/dev/null"
        cmd_print(cmd)
        rc, out, _ = run(cmd, cwd=repo_path, timeout=180)
        try:
            data = json.loads(out)
            for vuln in data.get("vulnerabilities", [])[:40]:
                findings.append(Finding(
                    phase="sca", tool="Snyk",
                    severity=normalize_sev(vuln.get("severity","MEDIUM")),
                    title=f"{vuln.get('title','')} — {vuln.get('packageName','')}",
                    description=vuln.get("description","")[:300],
                    package=f"{vuln.get('packageName','')}@{vuln.get('version','')}",
                    cve=vuln.get("identifiers",{}).get("CVE",[""])[0],
                    cwe=vuln.get("identifiers",{}).get("CWE",[""])[0],
                    remediation=f"Upgrade to {vuln.get('fixedIn',['latest'])[0] if vuln.get('fixedIn') else 'latest'}"
                ))
            ok(f"Snyk: {len(data.get('vulnerabilities',[]))} vulnerabilities")
        except Exception:
            warn("Snyk: auth required or no manifest found (run: snyk auth)")
    else:
        warn("snyk not found — skipping")

    _print_phase_summary(findings, "sca")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 04 — SAST
# ─────────────────────────────────────────────────────────────────────────────
def phase_sast(repo_path: str) -> List[Finding]:
    ph("04", "SAST", "Static Application Security Testing", GREEN)
    findings: List[Finding] = []

    # ── Semgrep ───────────────────────────────────────────
    if tool_available("semgrep"):
        out_f = reposec_tmp("semgrep.json")
        cmd = f"semgrep --config=auto --json --output={out_f} --quiet . 2>/dev/null"
        cmd_print(cmd)
        run(cmd, cwd=repo_path, timeout=300)
        if os.path.exists(out_f):
            try:
                with open(out_f) as f:
                    data = json.load(f)
                for r in data.get("results", [])[:80]:
                    sev = normalize_sev(r.get("extra", {}).get("severity", "WARNING"))
                    msg = r.get("extra", {}).get("message", r.get("check_id",""))
                    metadata = r.get("extra", {}).get("metadata", {})
                    cwe = ""
                    cwe_list = metadata.get("cwe", [])
                    if cwe_list:
                        cwe = cwe_list[0] if isinstance(cwe_list, list) else str(cwe_list)
                    findings.append(Finding(
                        phase="sast", tool="Semgrep",
                        severity=sev,
                        title=msg[:120],
                        description=f"Rule: {r.get('check_id','')}",
                        file=r.get("path",""),
                        line=str(r.get("start",{}).get("line","")),
                        cwe=cwe,
                        remediation=metadata.get("fix","Review and remediate the flagged code pattern.")
                    ))
                ok(f"Semgrep: {len(data.get('results',[]))} findings")
            except Exception as e:
                warn(f"Semgrep parse error: {e}")
            os.remove(out_f)
        else:
            ok("Semgrep: no findings")
    else:
        warn("semgrep not found — skipping")

    # ── Bandit (Python) ───────────────────────────────────
    py_files = list(Path(repo_path).rglob("*.py"))
    if py_files and tool_available("bandit"):
        out_f = reposec_tmp("bandit.json")
        cmd = f"bandit -r . -f json -o {out_f} -q 2>/dev/null"
        cmd_print(cmd)
        run(cmd, cwd=repo_path, timeout=180)
        if os.path.exists(out_f):
            try:
                with open(out_f) as f:
                    data = json.load(f)
                SEV_MAP = {"HIGH":"HIGH","MEDIUM":"MEDIUM","LOW":"LOW"}
                for issue in data.get("results",[])[:60]:
                    sev = SEV_MAP.get(issue.get("issue_severity","LOW").upper(),"LOW")
                    findings.append(Finding(
                        phase="sast", tool="Bandit",
                        severity=sev,
                        title=issue.get("issue_text","")[:120],
                        description=f"Test: {issue.get('test_id','')} — Confidence: {issue.get('issue_confidence','')}",
                        file=os.path.relpath(issue.get("filename",""), repo_path),
                        line=str(issue.get("line_number","")),
                        cwe=issue.get("issue_cwe",{}).get("id",""),
                        remediation=f"See: {issue.get('more_info','')}"
                    ))
                ok(f"Bandit: {len(data.get('results',[]))} Python security issues")
            except Exception as e:
                warn(f"Bandit parse error: {e}")
            os.remove(out_f)
        else:
            ok("Bandit: no issues found")
    elif py_files:
        warn("bandit not found — skipping Python SAST")

    # ── Brakeman (Ruby) ───────────────────────────────────
    rb_files = list(Path(repo_path).rglob("*.rb"))
    if rb_files and tool_available("brakeman"):
        out_f = reposec_tmp("brakeman.json")
        cmd = f"brakeman -f json -o {out_f} --no-progress -q . 2>/dev/null"
        cmd_print(cmd)
        run(cmd, cwd=repo_path, timeout=180)
        if os.path.exists(out_f):
            try:
                with open(out_f) as f:
                    data = json.load(f)
                for warn_ in data.get("warnings",[])[:40]:
                    sev = normalize_sev(warn_.get("confidence","MEDIUM"))
                    findings.append(Finding(
                        phase="sast", tool="Brakeman",
                        severity=sev,
                        title=warn_.get("warning_type","") + ": " + warn_.get("message","")[:80],
                        description=warn_.get("message","")[:300],
                        file=warn_.get("file",""),
                        line=str(warn_.get("line","")),
                        cwe=warn_.get("cwe_id",""),
                        remediation="See Brakeman documentation for this warning type."
                    ))
                ok(f"Brakeman: {len(data.get('warnings',[]))} Ruby findings")
            except Exception as e:
                warn(f"Brakeman parse error: {e}")
            os.remove(out_f)
    elif rb_files:
        warn("brakeman not found — skipping Ruby SAST")

    # ── govulncheck (Go) ──────────────────────────────────
    go_files = list(Path(repo_path).rglob("*.go"))
    if go_files and tool_available("govulncheck"):
        cmd = "govulncheck -json ./... 2>/dev/null"
        cmd_print(cmd)
        rc, out, _ = run(cmd, cwd=repo_path, timeout=180)
        count = 0
        for line in out.strip().splitlines():
            try:
                d = json.loads(line)
                if "finding" in d:
                    osv = d["finding"].get("osv","")
                    trace = d["finding"].get("trace",[{}])
                    fname = trace[0].get("position","") if trace else ""
                    findings.append(Finding(
                        phase="sast", tool="govulncheck",
                        severity="HIGH",
                        title=f"Go vulnerability: {osv}",
                        description=str(d["finding"])[:300],
                        file=fname,
                        cve=osv,
                        remediation="Run: go get -u <module> to update vulnerable dependency."
                    ))
                    count += 1
            except Exception:
                pass
        ok(f"govulncheck: {count} Go vulnerabilities")
    elif go_files:
        warn("govulncheck not found — skipping Go vuln check")

    # ── Checkov (IaC) ─────────────────────────────────────
    if tool_available("checkov"):
        cmd = "checkov -d . --output json --quiet 2>/dev/null"
        cmd_print(cmd)
        rc, out, _ = run(cmd, cwd=repo_path, timeout=300)
        try:
            # Checkov may output multiple JSON objects
            for part in out.replace("}{", "}\n{").splitlines():
                try:
                    data = json.loads(part)
                    failed = data.get("results",{}).get("failed_checks",[])
                    for chk in failed[:40]:
                        sev = normalize_sev(chk.get("severity","MEDIUM"))
                        findings.append(Finding(
                            phase="sast", tool="Checkov",
                            severity=sev,
                            title=chk.get("check_id","") + ": " + chk.get("check","check")[:80],
                            description=f"Resource: {chk.get('resource','')}",
                            file=chk.get("file_path",""),
                            line=str(chk.get("file_line_range",[""])[0]),
                            remediation=f"Guideline: {chk.get('guideline','')}"
                        ))
                except Exception:
                    pass
            cnt = sum(1 for f in findings if f.tool == "Checkov")
            ok(f"Checkov: {cnt} IaC misconfigurations")
        except Exception as e:
            ok("Checkov: no IaC files found or clean")
    else:
        warn("checkov not found — skipping IaC scan")

    _print_phase_summary(findings, "sast")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 05 — CONTAINER & INFRASTRUCTURE
# ─────────────────────────────────────────────────────────────────────────────
def phase_container(repo_path: str) -> List[Finding]:
    ph("05", "INFRA", "Container & Infrastructure Scanning", CYAN)
    findings: List[Finding] = []

    # ── Trivy ─────────────────────────────────────────────
    if tool_available("trivy"):
        out_f = reposec_tmp("trivy.json")
        cmd = f"trivy fs . --format json --output {out_f} --quiet 2>/dev/null"
        cmd_print(cmd)
        run(cmd, cwd=repo_path, timeout=300)
        if os.path.exists(out_f):
            try:
                with open(out_f) as f:
                    data = json.load(f)
                for result in data.get("Results", []):
                    for vuln in result.get("Vulnerabilities", [])[:40]:
                        sev = normalize_sev(vuln.get("Severity","MEDIUM"))
                        findings.append(Finding(
                            phase="container", tool="Trivy",
                            severity=sev,
                            title=f"{vuln.get('VulnerabilityID','')} — {vuln.get('PkgName','')}",
                            description=vuln.get("Description","")[:300],
                            file=result.get("Target",""),
                            package=f"{vuln.get('PkgName','')}@{vuln.get('InstalledVersion','')}",
                            cve=vuln.get("VulnerabilityID",""),
                            remediation=f"Fixed in: {vuln.get('FixedVersion','check advisory')}"
                        ))
                    for misc in result.get("Misconfigurations",[])[:20]:
                        sev = normalize_sev(misc.get("Severity","MEDIUM"))
                        findings.append(Finding(
                            phase="container", tool="Trivy",
                            severity=sev,
                            title=f"Misconfiguration: {misc.get('ID','')} — {misc.get('Title','')}",
                            description=misc.get("Description","")[:300],
                            file=result.get("Target",""),
                            remediation=misc.get("Resolution","Review and fix the misconfiguration.")
                        ))
                ok(f"Trivy: {sum(len(r.get('Vulnerabilities',[])) for r in data.get('Results',[]))} vulns, "
                   f"{sum(len(r.get('Misconfigurations',[])) for r in data.get('Results',[]))} misconfigs")
            except Exception as e:
                warn(f"Trivy parse error: {e}")
            os.remove(out_f)
        else:
            warn("Trivy: scan failed")
    else:
        warn("trivy not found — skipping")

    # ── Checkov (Docker/K8s specific) ────────────────────
    docker_files = (list(Path(repo_path).rglob("Dockerfile*")) +
                    list(Path(repo_path).rglob("docker-compose*.yml")) +
                    list(Path(repo_path).rglob("*.k8s.yaml")))
    if docker_files:
        info(f"Docker/K8s files found: {len(docker_files)}")
        # Already covered in SAST phase, just note it here
        ok(f"Checkov IaC: {len(docker_files)} container/infra files scanned (see SAST phase)")
    else:
        info("No Dockerfile or docker-compose.yml found")

    _print_phase_summary(findings, "container")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 06 — BINARY ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────
def phase_binary(repo_path: str) -> List[Finding]:
    ph("06", "BINARY", "Binary & Compiled Artifact Analysis", RED)
    findings: List[Finding] = []

    # Find binary files
    binary_exts = {".exe",".dll",".so",".dylib",".elf",".bin",".o", ".mdy",
                   ".a",".wasm",".pyc",".class",".jar",".war",".apk"}
    binaries = []
    for root, dirs, files in os.walk(repo_path):
        # Skip noise directories
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "__pycache__")]
        for f in files:
            fpath = Path(root) / f
            if fpath.suffix.lower() in binary_exts:   # FIX: was mis-indented
                binaries.append(str(fpath))

    if not binaries:
        info("No compiled binary artifacts found in repository")
        info("Ghidra / Binary Ninja / gdb — nothing to analyse")
        return findings   # FIX: early-return only once (duplicate block removed)

    ok(f"Found {len(binaries)} binary artifact(s): "
       f"{', '.join(Path(b).name for b in binaries)}")

    # ── file + strings (basic analysis) ──────────────────────────────────────
    cmd_print("file <binaries> && strings <binaries>")

    for bpath in binaries[:10]:
        # --- file ---
        rc, out, _ = run(f"file {bpath}", timeout=10)
        if out.strip():
            info(f"file: {out.strip()[:100]}")

        # --- strings — look for suspicious patterns ---
        suspicious_pattern = (
            r"(password|secret|token|http://|https://|eval|exec|shell|cmd)"
        )
        cmd_print(f"strings {bpath} | grep -iE '{suspicious_pattern}' | head -10")
        rc, out, _ = run(
            f"strings {bpath} 2>/dev/null "
            f"| grep -iE '{suspicious_pattern}' "
            f"| head -10",
            timeout=30,
        )
        for line in out.strip().splitlines()[:5]:
            findings.append(Finding(         # FIX: closing paren was missing
                phase="binary",
                tool="strings/grep",
                severity="MEDIUM",
                title=f"Suspicious string in binary: {Path(bpath).name}",
                description=f"Pattern found: {line.strip()[:150]}",
                file=os.path.relpath(bpath, repo_path),
                remediation=(
                    "Review binary for hardcoded credentials or suspicious "
                    "function calls. Consider stripping or obfuscating where "
                    "appropriate, and store secrets in environment variables."
                ),
            ))

    # ── gdb — basic binary info ───────────────────────────────────────────────
    if tool_available("gdb"):
        for bpath in binaries[:3]:
            if Path(bpath).suffix.lower() in (".elf", ".so", ""):
                cmd_print(f"gdb -batch -ex 'info file' {bpath}")
                rc, out, _ = run(
                    f"gdb -batch -ex 'info file' -ex quit {bpath} 2>/dev/null",
                    timeout=30,
                )
                if "format" in out.lower():
                    first_line = out.splitlines()[0][:80] if out.strip() else "parsed"
                    info(f"gdb info: {first_line}")
    else:
        warn("gdb not found — skipping ELF inspection")

    # ── Ghidra advisory ───────────────────────────────────────────────────────
    if tool_available("ghidra") or tool_available("analyzeHeadless"):
        info("Ghidra: use analyzeHeadless for full decompilation (GUI recommended)")
    else:
        info(
            "Ghidra: not in PATH — for deep analysis run: "
            "analyzeHeadless <proj_dir> <proj_name> -import <binary>"
        )

    # ── Binary Ninja advisory ─────────────────────────────────────────────────
    info("Binary Ninja: launch GUI for interactive reverse engineering")

    _print_phase_summary(findings, "binary")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 07 — DAST
# ─────────────────────────────────────────────────────────────────────────────
def phase_dast(repo_path: str, target_url: str = "") -> List[Finding]:
    ph("07", "DAST", "Dynamic Application Security Testing", YELLOW)
    findings: List[Finding] = []

    if not target_url:
        info("No --target-url provided — DAST requires a running application endpoint")
        info("To enable DAST, rerun with:  --target-url https://your-app.com")
        info("Tools that will run: OWASP ZAP, Burp Suite (manual), Aikido Security")
        return findings

    ok(f"Target URL: {target_url}")

    # ── OWASP ZAP ─────────────────────────────────────────
    zap_cmd = None
    for c in ("zap.sh", "zaproxy", "zap-cli", "owasp-zap"):
        if tool_available(c):
            zap_cmd = c
            break

    if zap_cmd:
        out_f = reposec_tmp("zap_report.json")
        cmd = (f"{zap_cmd} -cmd -quickurl {target_url} "
               f"-quickout {out_f} -quickprogress 2>/dev/null")
        cmd_print(cmd)
        run(cmd, cwd=repo_path, timeout=600)
        if os.path.exists(out_f):
            try:
                with open(out_f) as f:
                    data = json.load(f)
                for site in data.get("site", []):
                    for alert in site.get("alerts", [])[:40]:
                        risk_map = {"3":"CRITICAL","2":"HIGH","1":"MEDIUM","0":"LOW"}
                        sev = risk_map.get(str(alert.get("riskcode","1")),"MEDIUM")
                        findings.append(Finding(
                            phase="dast", tool="OWASP ZAP",
                            severity=sev,
                            title=alert.get("alert","")[:120],
                            description=alert.get("desc","")[:300],
                            file=alert.get("url",""),
                            cwe=f"CWE-{alert.get('cweid','')}" if alert.get("cweid") else "",
                            remediation=alert.get("solution","")[:300]
                        ))
                ok(f"OWASP ZAP: {sum(len(s.get('alerts',[])) for s in data.get('site',[]))} alerts")
            except Exception as e:
                warn(f"ZAP parse error: {e}")
        else:
            warn("OWASP ZAP: scan failed or report not generated")
    else:
        warn("OWASP ZAP not found — install from zaproxy.org")

    info("Burp Suite: launch GUI for manual/intercepting proxy testing")
    info("Aikido Security: configure via https://app.aikido.dev for CI/CD integration")

    _print_phase_summary(findings, "dast")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 08 — RISK SCORING
# ─────────────────────────────────────────────────────────────────────────────
def phase_risk(all_findings: List[Finding]) -> Dict:
    ph("08", "REPORT", "Risk Scoring & Report Generation", ORANGE)

    counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}
    phase_scores: Dict[str, float] = {}
    phases = ["osint","sca","sast","container","binary","dast"]

    for f in all_findings:
        sev = f.sev_norm()
        counts[sev] = counts.get(sev, 0) + 1

    # Per-phase score
    for ph_id in phases:
        ph_findings = [f for f in all_findings if f.phase == ph_id]
        raw = sum(SEV_WEIGHT.get(f.sev_norm(), 0) for f in ph_findings)
        # Normalize: cap at 50 raw points → 100 score
        phase_scores[ph_id] = min(100, int((raw / 50) * 100))

    # Overall score (weighted average)
    phase_weights = {"osint":0.25,"sca":0.25,"sast":0.20,
                     "container":0.15,"binary":0.05,"dast":0.10}
    overall = min(100, int(sum(phase_scores.get(p,0) * w
                              for p, w in phase_weights.items())))

    # Grade
    grade = "A" if overall < 20 else \
            "B" if overall < 40 else \
            "C" if overall < 60 else \
            "D" if overall < 80 else "F"

    # CVSS approximation
    cvss = 0.0
    if counts["CRITICAL"] > 0: cvss = 9.0 + min(1.0, counts["CRITICAL"] * 0.1)
    elif counts["HIGH"] > 0:   cvss = 7.0 + min(2.0, counts["HIGH"] * 0.2)
    elif counts["MEDIUM"] > 0: cvss = 4.0 + min(3.0, counts["MEDIUM"] * 0.3)
    elif counts["LOW"] > 0:    cvss = 2.0 + min(2.0, counts["LOW"] * 0.4)

    result = {
        "overall": overall, "grade": grade,
        "cvss": round(cvss, 1),
        "counts": counts,
        "breakdown": phase_scores,
        "total": len(all_findings)
    }

    # Terminal summary
    sev_col = {"CRITICAL":RED,"HIGH":ORANGE,"MEDIUM":YELLOW,"LOW":GREEN,"INFO":CYAN}
    print(f"\n  {'─'*50}")
    print(f"  {B}RISK SCORE:{R}  {sev_col.get(grade,'')}{B}{overall}/100{R}  Grade: {B}{grade}{R}  CVSS: {B}{cvss}{R}")
    print(f"  {'─'*50}")
    for sev, cnt in counts.items():
        if cnt > 0:
            bar = "█" * min(30, cnt)
            print(f"  {sev_col.get(sev,'')}{sev:<10}{R} {bar} {cnt}")
    print(f"  {'─'*50}")
    print(f"  Total findings: {B}{result['total']}{R}")

    return result


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def _print_phase_summary(findings: List[Finding], phase: str):
    phase_f = [f for f in findings if f.phase == phase]
    if not phase_f:
        ok("Phase complete — no findings")
        return
    counts: Dict[str, int] = {}
    for f in phase_f:
        counts[f.sev_norm()] = counts.get(f.sev_norm(), 0) + 1
    summary = " | ".join(
        f"{SEV_COLOR.get(s,'')}{s}: {c}{R}"
        for s, c in sorted(counts.items(), key=lambda x: -SEV_ORDER.get(x[0],0))
    )
    ok(f"Phase complete — {len(phase_f)} findings  [{summary}]")


# ─────────────────────────────────────────────────────────────────────────────
# HTML REPORT
# ─────────────────────────────────────────────────────────────────────────────
def generate_html(
    all_findings: List[Finding],
    risk: Dict,
    meta: Dict,
    mermaid: str,
    repo_name: str,
    output_dir: str
) -> str:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    SEV_HEX = {"CRITICAL":"#ff3b3b","HIGH":"#ff8c00","MEDIUM":"#fbbf24",
               "LOW":"#4ade80","INFO":"#38bdf8"}
    SEV_BG  = {"CRITICAL":"#200000","HIGH":"#1f1200","MEDIUM":"#1f1a00",
               "LOW":"#001f0d","INFO":"#001825"}
    SEV_BD  = {"CRITICAL":"#6b0000","HIGH":"#6b3800","MEDIUM":"#6b5600",
               "LOW":"#006b2e","INFO":"#005a7a"}
    PHASE_COLOR = {"osint":"#c084fc","sca":"#fb923c","sast":"#4ade80",
                   "container":"#22d3ee","binary":"#f87171","dast":"#fbbf24"}

    # Gauge SVG
    score = risk["overall"]
    gauge_color = ("#ff3b3b" if score >= 80 else "#ff8c00" if score >= 60 else
                   "#fbbf24" if score >= 40 else "#4ade80" if score >= 20 else "#38bdf8")
    gauge_label = ("CRITICAL" if score >= 80 else "HIGH" if score >= 60 else
                   "MEDIUM" if score >= 40 else "LOW" if score >= 20 else "MINIMAL")
    import math
    ang = (score/100)*180 - 90
    rad = math.radians(ang - 90)
    nx = 110 + 72*math.cos(rad)
    ny = 110 + 72*math.sin(rad)
    arc = (score/100)*283

    gauge_svg = f"""
    <svg width="220" height="130" viewBox="0 0 220 130">
      <path d="M 20 110 A 90 90 0 0 1 200 110" fill="none" stroke="#151d2e" stroke-width="18" stroke-linecap="round"/>
      <path d="M 20 110 A 90 90 0 0 1 200 110" fill="none" stroke="{gauge_color}" stroke-width="18"
        stroke-linecap="round" stroke-dasharray="{arc:.1f} 283" opacity="0.85"/>
      <circle cx="110" cy="110" r="7" fill="{gauge_color}"/>
      <line x1="110" y1="110" x2="{nx:.1f}" y2="{ny:.1f}" stroke="{gauge_color}" stroke-width="3" stroke-linecap="round"/>
      <text x="110" y="82" text-anchor="middle" fill="{gauge_color}" font-size="30"
        font-weight="bold" font-family="Courier New">{score}</text>
      <text x="110" y="100" text-anchor="middle" fill="#4b5563" font-size="11" font-family="Courier New">/100</text>
      <text x="22" y="125" fill="#374151" font-size="9" font-family="Courier New">LOW</text>
      <text x="166" y="125" fill="#374151" font-size="9" font-family="Courier New">CRITICAL</text>
    </svg>
    <div style="color:{gauge_color};font-family:Courier New;font-size:16px;font-weight:bold;
      letter-spacing:4px;text-align:center;margin-top:-8px">{gauge_label} RISK</div>"""

    # Finding cards
    def finding_card(f: Finding, idx: int) -> str:
        sev = f.sev_norm()
        fc = SEV_HEX.get(sev,"#64748b")
        bg = SEV_BG.get(sev,"#0d1321")
        bd = SEV_BD.get(sev,"#1e2d40")
        pc = PHASE_COLOR.get(f.phase,"#64748b")
        extras = ""
        if f.cve:  extras += f'<span class="tag" style="color:#f87171">{escape(str(f.cve))}</span>'
        if f.cwe:  extras += f'<span class="tag" style="color:#fb923c">{escape(str(f.cwe))}</span>'
        if f.file: extras += f'<span class="tag" style="color:#64748b">📁 {escape(str(f.file))}{":"+f.line if f.line else ""}</span>'
        if f.package: extras += f'<span class="tag" style="color:#64748b">📦 {escape(f.package)}</span>'
        rem = (f'<div class="remediation" style="border-left:2px solid {fc}">'
               f'<span style="color:#4b5563;font-size:11px">Remediation: </span>'
               f'<span style="color:#94a3b8;font-size:12px">{escape(str(f.remediation))}</span></div>'
               if f.remediation else "")
        desc = (f'<div style="color:#94a3b8;font-size:12px;line-height:1.6;margin-top:8px">'
                f'{escape(f.description)}</div>'
                if f.description else "")
        return f"""
        <div class="finding" data-phase="{f.phase}" data-sev="{sev}"
          style="background:{bg};border:1px solid {bd}" onclick="toggle(this)">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px">
            <span class="sev-badge" style="background:{fc};color:#000">{sev}</span>
            <span class="tag" style="border:1px solid #1e2d40;color:#64748b">{escape(f.tool)}</span>
            <span class="tag" style="border:1px solid {pc}44;color:{pc}">{f.phase.upper()}</span>
            {extras}
            <span style="margin-left:auto;color:#374151">▼</span>
          </div>
          <div style="color:#e2e8f0;font-weight:600;font-size:13px">{escape(f.title)}</div>
          <div class="detail" style="display:none">{desc}{rem}</div>
        </div>"""

    findings_html = "\n".join(finding_card(f, i)
                              for i, f in enumerate(
                                  sorted(all_findings,
                                         key=lambda x: -SEV_ORDER.get(x.sev_norm(),0))))

    # Phase breakdown cards
    phase_breakdown_html = ""
    for ph_id, ph_score in risk["breakdown"].items():
        pc = PHASE_COLOR.get(ph_id,"#64748b")
        ph_cnt = sum(1 for f in all_findings if f.phase == ph_id)
        phase_breakdown_html += f"""
        <div class="ph-card" style="border-top:2px solid {pc}">
          <div style="color:#4b5563;font-size:9px;letter-spacing:2px;margin-bottom:8px">{ph_id.upper()}</div>
          <div style="color:{pc};font-size:26px;font-weight:bold;line-height:1">{ph_score}</div>
          <div style="color:#374151;font-size:10px;margin-bottom:8px">/100 · {ph_cnt} findings</div>
          <div style="background:#151d2e;border-radius:2px;height:3px">
            <div style="background:{pc};width:{ph_score}%;height:100%;border-radius:2px"></div>
          </div>
        </div>"""

    # Severity bars
    sev_bars_html = ""
    max_cnt = max(risk["counts"].values()) if risk["counts"] else 1
    for sev, cnt in risk["counts"].items():
        fc = SEV_HEX.get(sev,"#64748b")
        w  = int((cnt / max_cnt) * 100) if max_cnt else 0
        sev_bars_html += f"""
        <div style="margin-bottom:12px">
          <div style="display:flex;justify-content:space-between;margin-bottom:5px">
            <span style="color:{fc};font-size:11px;letter-spacing:1px">{sev}</span>
            <span style="color:#e2e8f0;font-size:13px;font-weight:bold">{cnt}</span>
          </div>
          <div style="background:#151d2e;border-radius:2px;height:5px">
            <div style="background:{fc};width:{w}%;height:100%;border-radius:2px"></div>
          </div>
        </div>"""

    # Tool availability summary
    all_tools = ["gitleaks","trufflehog","git-secrets","syft","grype","safety",
                 "pip-audit","cargo","osv-scanner","snyk","semgrep","bandit",
                 "brakeman","govulncheck","checkov","trivy","gdb","nikto"]
    tools_html = ""
    for t in all_tools:
        avail = tool_available(t)
        col = "#4ade80" if avail else "#374151"
        sym = "✓" if avail else "○"
        tools_html += f'<span style="color:{col};font-size:11px;margin:3px 8px 3px 0">{sym} {t}</span>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>RepoSec Report — {escape(repo_name)}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#070b12;color:#e2e8f0;font-family:'Courier New',monospace;font-size:13px;line-height:1.6}}
  ::-webkit-scrollbar{{width:5px}} ::-webkit-scrollbar-track{{background:#070b12}}
  ::-webkit-scrollbar-thumb{{background:#1e2d40;border-radius:3px}}
  .container{{max-width:1200px;margin:0 auto;padding:24px}}
  .topbar{{background:#0a0f1a;border-bottom:1px solid #1e2d40;padding:12px 24px;
    display:flex;align-items:center;gap:12px;position:sticky;top:0;z-index:100}}
  .dot{{width:10px;height:10px;border-radius:50%}}
  .grid-2{{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px}}
  .grid-3{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:14px}}
  .grid-6{{display:grid;grid-template-columns:repeat(6,1fr);gap:8px;margin-bottom:14px}}
  .card{{background:#0a0f1a;border:1px solid #1e2d40;border-radius:8px;padding:20px}}
  .card-title{{color:#4b5563;font-size:10px;letter-spacing:3px;margin-bottom:14px}}
  .ph-card{{background:#070b12;border:1px solid #1e2d40;border-radius:6px;padding:14px;text-align:center}}
  .finding{{border-radius:6px;padding:12px 14px;margin-bottom:8px;cursor:pointer;transition:opacity .2s}}
  .finding:hover{{opacity:.85}}
  .sev-badge{{font-size:10px;font-weight:bold;padding:2px 7px;border-radius:3px}}
  .tag{{background:#0d1321;font-size:10px;padding:2px 8px;border-radius:3px}}
  .detail{{margin-top:8px}}
  .remediation{{margin-top:10px;padding:8px 12px;background:#070b12;border-radius:4px}}
  .filters{{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px}}
  .filter-btn{{background:transparent;border:1px solid #1e2d40;color:#4b5563;
    font-family:'Courier New',monospace;font-size:10px;padding:6px 14px;
    border-radius:4px;cursor:pointer;letter-spacing:1px;transition:all .2s}}
  .filter-btn.active{{border-color:#4ade80;color:#4ade80}}
  .mmd-box{{background:#030610;border:1px solid #1e2d40;border-radius:6px;
    padding:16px;font-size:11px;color:#94a3b8;white-space:pre;overflow-x:auto;
    max-height:400px;overflow-y:auto;line-height:1.7;margin-top:10px}}
  .mermaid-wrapper{{background:#030610;border:1px solid #1e2d40;border-radius:6px;
    padding:20px;overflow-x:auto;text-align:center}}
  .mermaid svg{{max-width:100%;height:auto}}
  details summary{{outline:none;user-select:none}}
  .section{{margin-bottom:24px}}
  h2{{color:#4ade80;font-size:13px;letter-spacing:3px;margin-bottom:14px;
    padding-bottom:8px;border-bottom:1px solid #1e2d40}}
  .progress-bar{{background:#060a10;height:3px;margin-bottom:24px}}
  .progress-fill{{height:100%;background:linear-gradient(90deg,#4ade80,#38bdf8)}}
  .stat-box{{background:#070b12;border:1px solid #1e2d40;border-radius:6px;padding:12px}}
  .copy-btn{{background:#0a0f1a;border:1px solid #1e2d40;color:#94a3b8;
    font-family:'Courier New',monospace;font-size:11px;padding:7px 16px;
    border-radius:4px;cursor:pointer;float:right;margin-bottom:8px}}
  .copy-btn:hover{{border-color:#4ade80;color:#4ade80}}
  @media(max-width:700px){{.grid-2,.grid-3,.grid-6{{grid-template-columns:1fr}}}}
</style>
<script src="https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"></script>
</head>
<body>

<div class="topbar">
  <div class="dot" style="background:#f87171"></div>
  <div class="dot" style="background:#fbbf24"></div>
  <div class="dot" style="background:#4ade80"></div>
  <span style="color:#4ade80;font-size:11px;letter-spacing:3px;font-weight:bold">◈ REPOSEC ANALYZER — NO-AI EDITION</span>
  <span style="color:#1e2d40">│</span>
  <span style="color:#64748b;font-size:11px">{escape(repo_name)}</span>
  <span style="color:#1e2d40;margin-left:auto">│</span>
  <span style="color:#374151;font-size:10px">{ts}</span>
</div>

<div class="progress-bar"><div class="progress-fill" style="width:100%"></div></div>

<div class="container">

  <!-- RISK OVERVIEW -->
  <div class="section">
    <h2>◈ RISK OVERVIEW</h2>
    <div class="grid-2">
      <div class="card" style="text-align:center">
        <div class="card-title" style="text-align:center">OVERALL RISK SCORE</div>
        {gauge_svg}
        <div style="display:flex;justify-content:center;gap:40px;margin-top:20px">
          <div style="text-align:center">
            <div style="color:#4b5563;font-size:10px;letter-spacing:1px">GRADE</div>
            <div style="color:#f0f6fc;font-size:32px;font-weight:bold">{risk['grade']}</div>
          </div>
          <div style="text-align:center">
            <div style="color:#4b5563;font-size:10px;letter-spacing:1px">CVSS</div>
            <div style="color:#f0f6fc;font-size:32px;font-weight:bold">{risk['cvss']}</div>
          </div>
          <div style="text-align:center">
            <div style="color:#4b5563;font-size:10px;letter-spacing:1px">TOTAL</div>
            <div style="color:#f0f6fc;font-size:32px;font-weight:bold">{risk['total']}</div>
          </div>
        </div>
      </div>
      <div class="card">
        <div class="card-title">SEVERITY BREAKDOWN</div>
        {sev_bars_html}
      </div>
    </div>
  </div>

  <!-- PHASE BREAKDOWN -->
  <div class="section">
    <h2>◈ PHASE RISK BREAKDOWN</h2>
    <div class="grid-6">{phase_breakdown_html}</div>
  </div>

  <!-- REPO METADATA -->
  <div class="section">
    <h2>◈ REPOSITORY METADATA</h2>
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:14px">
      <div class="stat-box">
        <div style="color:#4b5563;font-size:9px;letter-spacing:2px;margin-bottom:4px">FILES</div>
        <div style="color:#38bdf8;font-size:18px;font-weight:bold">{meta.get('files',0)}</div>
      </div>
      <div class="stat-box">
        <div style="color:#4b5563;font-size:9px;letter-spacing:2px;margin-bottom:4px">DIRECTORIES</div>
        <div style="color:#c084fc;font-size:18px;font-weight:bold">{meta.get('dirs',0)}</div>
      </div>
      <div class="stat-box">
        <div style="color:#4b5563;font-size:9px;letter-spacing:2px;margin-bottom:4px">MANIFESTS</div>
        <div style="color:#fb923c;font-size:18px;font-weight:bold">{len(meta.get('manifests',[]))}</div>
      </div>
      <div class="stat-box">
        <div style="color:#4b5563;font-size:9px;letter-spacing:2px;margin-bottom:4px">SENSITIVE</div>
        <div style="color:#f87171;font-size:18px;font-weight:bold">{len(meta.get('sensitive',[]))}</div>
      </div>
    </div>
    {'<div class="card" style="margin-bottom:10px"><div class="card-title">SENSITIVE FILES DETECTED</div>' + ''.join(f'<div style="color:#f87171;font-size:11px;margin-bottom:4px">⚠ {escape(s)}</div>' for s in meta.get("sensitive",[])) + '</div>' if meta.get("sensitive") else ""}
    <div class="card">
      <div class="card-title">TOP EXTENSIONS</div>
      <div style="display:flex;flex-wrap:wrap;gap:6px">
        {''.join(f'<span class="tag" style="color:#94a3b8">.{escape(ext)} <span style="color:#64748b">×{cnt}</span></span>' for ext,cnt in list(meta.get("languages",{}).items())[:12])}
      </div>
    </div>
  </div>

  <!-- TOOLS STATUS -->
  <div class="section">
    <h2>◈ INSTALLED TOOLS</h2>
    <div class="card">{tools_html}</div>
  </div>

  <!-- FINDINGS -->
  <div class="section">
    <h2>◈ SECURITY FINDINGS ({risk['total']} total)</h2>
    <div class="filters">
      <button class="filter-btn active" onclick="filterPhase('all',this)">ALL</button>
      {''.join(f'<button class="filter-btn" onclick="filterPhase(&quot;{p}&quot;,this)" style="border-color:{PHASE_COLOR.get(p,chr(34))+"44"}">{p.upper()}</button>' for p in ["osint","sca","sast","container","binary","dast"])}
    </div>
    <div class="filters">
      <button class="filter-btn" onclick="filterSev('all',this)">ALL SEVERITY</button>
      {''.join(f'<button class="filter-btn" onclick="filterSev(&quot;{s}&quot;,this)" style="color:{SEV_HEX.get(s,chr(34))}">{s}</button>' for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"])}
    </div>
    <div id="findings-container">
      {findings_html if all_findings else '<div style="text-align:center;padding:60px;color:#4ade80">✓ No findings — clean repository</div>'}
    </div>
  </div>

  <!-- MERMAID -->
  <div class="section">
    <h2>◈ REPOSITORY STRUCTURE — MERMAID</h2>
    <div class="card">
      <div style="color:#94a3b8;font-size:12px;margin-bottom:12px">
        Rendered inline below. Edit or share at
        <a href="https://mermaid.live" target="_blank" style="color:#38bdf8">mermaid.live</a>
        or generate a PNG with
        <a href="https://github.com/mermaid-js/mermaid-cli" target="_blank"
          style="color:#38bdf8">mermaid-cli</a>
        (<code style="color:#c084fc">mmdc -i structure.mmd -o structure.svg</code>)
      </div>
      <button class="copy-btn" onclick="copyMermaid()">⎘ COPY MERMAID</button>
      <div class="mermaid-wrapper">
        <div class="mermaid">{mermaid}</div>
      </div>
      <details style="margin-top:12px">
        <summary style="color:#4b5563;font-size:11px;cursor:pointer;letter-spacing:1px;
          padding:6px 0">▸ VIEW SOURCE</summary>
        <div class="mmd-box" id="mmd-content">{escape(mermaid)}</div>
      </details>
    </div>
  </div>

<script>
  let activePhase = 'all', activeSev = 'all';

  function toggle(el) {{
    const d = el.querySelector('.detail');
    const arrow = el.querySelector('[style*="margin-left:auto"]');
    if (d.style.display === 'none' || !d.style.display) {{
      d.style.display = 'block';
      if (arrow) arrow.textContent = '▲';
    }} else {{
      d.style.display = 'none';
      if (arrow) arrow.textContent = '▼';
    }}
  }}

  function filterPhase(phase, btn) {{
    activePhase = phase;
    document.querySelectorAll('.filters')[0].querySelectorAll('.filter-btn')
      .forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    applyFilters();
  }}

  function filterSev(sev, btn) {{
    activeSev = sev;
    document.querySelectorAll('.filters')[1].querySelectorAll('.filter-btn')
      .forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    applyFilters();
  }}

  function applyFilters() {{
    document.querySelectorAll('.finding').forEach(el => {{
      const ph = el.dataset.phase, sv = el.dataset.sev;
      const show = (activePhase === 'all' || ph === activePhase) &&
                   (activeSev === 'all' || sv === activeSev);
      el.style.display = show ? 'block' : 'none';
    }});
  }}

  function copyMermaid() {{
    const text = document.getElementById('mmd-content').innerText;
    navigator.clipboard.writeText(text).then(() => {{
      const btn = document.querySelector('.copy-btn');
      btn.textContent = '✓ COPIED!';
      btn.style.color = '#4ade80';
      btn.style.borderColor = '#4ade80';
      setTimeout(() => {{
        btn.textContent = '⎘ COPY MERMAID';
        btn.style.color = '#94a3b8';
        btn.style.borderColor = '#1e2d40';
      }}, 2000);
    }});
  }}

  mermaid.initialize({{
    startOnLoad: true,
    theme: 'dark',
    themeVariables: {{
      background:          '#070b12',
      primaryColor:        '#0d1321',
      primaryTextColor:    '#c9d1d9',
      primaryBorderColor:  '#1e2d40',
      lineColor:           '#2d3f55',
      edgeLabelBackground: '#070b12',
      clusterBkg:          '#0d1321',
      titleColor:          '#4ade80',
    }}
  }});
</script>
</body>
</html>"""

    report_path = str(Path(output_dir) / "reposec_report.html")
    with open(report_path, "w") as f:
        f.write(html)
    return report_path


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="RepoSec Analyzer — No-AI Edition: full DevSecOps pipeline using real tools",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
          Examples:
            python3 reposec.py https://github.com/owner/repo
            python3 reposec.py owner/repo --output ./my-report
            python3 reposec.py /path/to/local/repo --target-url https://myapp.com
            python3 reposec.py owner/repo --skip-phases binary,dast
        """)
    )
    parser.add_argument("target",       help="GitHub URL, owner/repo, or local path")
    parser.add_argument("--output",     default="./reposec-output", help="Output directory")
    parser.add_argument("--target-url", default="",   help="Live URL for DAST scanning")
    parser.add_argument("--skip-phases",default="",   help="Comma-separated phases to skip: osint,sca,sast,container,binary,dast")
    parser.add_argument("--keep-clone", action="store_true", help="Keep cloned repo after analysis")
    args = parser.parse_args()

    banner()

    skip = set(args.skip_phases.split(",")) if args.skip_phases else set()
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    # ── Resolve repo path ─────────────────────────────────
    target = args.target.strip()
    clone_dir = None

    if target.startswith("http") or re.match(r'^[^/\s]+/[^/\s]+$', target):
        # GitHub URL or owner/repo
        m = re.search(r'github\.com/([^/\s]+)/([^/\s?#]+)', target)
        if not m:
            m2 = re.match(r'^([^/\s]+)/([^/\s]+)$', target)
            if m2:
                owner, repo_name = m2.group(1), m2.group(2)
            else:
                err("Cannot parse target. Use: https://github.com/owner/repo or owner/repo")
                sys.exit(1)
        else:
            owner, repo_name = m.group(1), m.group(2).rstrip(".git")

        repo_name = repo_name.rstrip("/").rstrip(".git")
        clone_url = f"https://github.com/{owner}/{repo_name}.git"
        clone_dir = str(out_dir / f"clone_{repo_name}")

        print(f"\n{CYAN}◈ Cloning repository{R}")
        print(f"  {GREY}${R} git clone --depth=1 {clone_url} {clone_dir}")
        if os.path.exists(clone_dir):
            info(f"Clone directory already exists — reusing")
            repo_path = clone_dir
        else:
            rc, _, stderr = run(f"git clone --depth=1 {clone_url} {clone_dir}", timeout=300)
            if rc != 0:
                err(f"git clone failed: {stderr[:200]}")
                err("Is the repository public? Check your network connection.")
                sys.exit(1)
            repo_path = clone_dir
        ok(f"Repository cloned to {repo_path}")
    else:
        repo_path = str(Path(target).resolve())
        repo_name = Path(repo_path).name
        if not os.path.isdir(repo_path):
            err(f"Path not found: {repo_path}")
            sys.exit(1)
        ok(f"Local repository: {repo_path}")

    repo_name = Path(repo_path).name
    all_findings: List[Finding] = []
    t_start = time.time()

    # ── Run phases ────────────────────────────────────────
    file_list, mermaid, meta = phase_discovery(repo_path)

    if "osint" not in skip:
        all_findings.extend(phase_osint(repo_path))

    if "sca" not in skip:
        all_findings.extend(phase_sca(repo_path))

    if "sast" not in skip:
        all_findings.extend(phase_sast(repo_path))

    if "container" not in skip:
        all_findings.extend(phase_container(repo_path))

    if "binary" not in skip:
        all_findings.extend(phase_binary(repo_path))

    if "dast" not in skip:
        all_findings.extend(phase_dast(repo_path, args.target_url))

    # ── Risk scoring ──────────────────────────────────────
    risk = phase_risk(all_findings)

    # ── Save outputs ──────────────────────────────────────
    ph("09", "OUTPUT", "Saving Reports", GREEN)

    # HTML report
    report_path = generate_html(all_findings, risk, meta, mermaid, repo_name, str(out_dir))    
    ok(f"HTML report   → {report_path}")

    # JSON findings
    json_path = str(out_dir / "findings.json")
    with open(json_path, "w") as f:
        json.dump({
            "repo": repo_name, "generated": datetime.now().isoformat(),
            "risk": risk, "meta": meta,
            "findings": [vars(f) for f in all_findings]
        }, f, indent=2)
    ok(f"JSON findings → {json_path}")

    # MMD
    mmd_path = str(out_dir / "structure.mmd")
    with open(mmd_path, "w") as f:
        f.write(mermaid)
    ok(f"Mermaid       → {mmd_path}")

    # SARIF (simple)
    sarif_path = str(out_dir / "findings.sarif")
    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "RepoSec Analyzer","version": "1.0","rules": []}},
            "results": [{
                "ruleId": f.tool,
                "level": {"CRITICAL":"error","HIGH":"error","MEDIUM":"warning",
                          "LOW":"note","INFO":"none"}.get(f.sev_norm(),"warning"),
                "message": {"text": f.title},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f.file or "unknown"},
                    "region": {"startLine": int(f.line) if str(f.line).strip().isdigit() else 1}
                }}]
            } for f in all_findings]
        }]
    }
    with open(sarif_path, "w") as f:
        json.dump(sarif, f, indent=2)
    ok(f"SARIF output  → {sarif_path}")

    # Cleanup
    if clone_dir and not args.keep_clone:
        shutil.rmtree(clone_dir, ignore_errors=True)
        info(f"Removed clone directory")

    elapsed = int(time.time() - t_start)
    print(f"\n{GREEN}{B}{'█'*60}{R}")
    print(f"{GREEN}{B}  ✓ ANALYSIS COMPLETE  {len(all_findings)} findings  {elapsed}s  {R}")
    print(f"{GREEN}{B}{'█'*60}{R}")
    print(f"\n  {CYAN}Open report:{R}  xdg-open {report_path}")
    print(f"  {CYAN}Or run:     {R}  python3 -m http.server 8080 --directory {out_dir}")
    print(f"               then browse to http://localhost:8080/reposec_report.html\n")


if __name__ == "__main__":
    main()

