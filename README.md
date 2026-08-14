# Software Vetter · RepoSec WebUI

A local React/Vite interface for running the globally installed RepoSec analyzer against GitHub and GitLab repositories.

## Requirements

- Node.js 20+
- Git
- RepoSec executable at `/usr/local/bin/reposec` (preferred) or the bundled corrected fallback engine
- Any optional scanners you want RepoSec to use (Semgrep, Trivy, Gitleaks, Grype, etc.)


## Run

```bash
npm install
npm run dev
```

Open `http://localhost:5173`.

`npm run dev` starts both:

- Vite frontend on port `5173`
- local RepoSec API on `127.0.0.1:8787`

Vite proxies `/api/*` to the local API.

## RepoSec path

The API prefers `/usr/local/bin/reposec`. It probes the executable with `--help`; if the system copy is missing or cannot start, it falls back to `tools/reposec-fixed.py`, a corrected copy of the uploaded analyzer.

Override the selection when needed:

```bash
REPOSEC_BIN=/path/to/reposec npm run dev
```

## GitHub and GitLab support

The backend validates HTTPS repository URLs, clones with `git clone --depth=1`, then passes the **local clone path** to RepoSec. This intentionally avoids RepoSec's GitHub-only URL parser and lets the same installed RepoSec command analyze GitLab repositories without modifying it.

Private repositories can work when the local Git installation already has non-interactive credentials configured. Do not paste access tokens into the WebUI URL field.

To allow a self-hosted GitLab instance:

```bash
REPOSEC_ALLOWED_GIT_HOSTS=github.com,gitlab.com,gitlab.example.com npm run dev
```

## Output

Each run is stored under `reposec-runs/<job-id>/output/` and the WebUI exposes RepoSec's:

- `reposec_report.html`
- `findings.json`
- `findings.sarif`
- `structure.mmd`

The temporary repository clone is deleted after the scan.

## Security notes

- The API uses `spawn()` with argument arrays and `shell: false` for Git and RepoSec.
- Repository URLs are restricted to configured HTTPS Git hosts and URLs containing embedded credentials are rejected.
- DAST is skipped by this WebUI because the requested workflow is repository analysis, not active testing of a live target.
- Known secret-shaped values in logs and JSON returned to the browser are redacted. RepoSec's original artifacts remain local on disk and may contain scanner-provided evidence, so protect the `reposec-runs` directory appropriately.

## Bundled RepoSec fallback

`tools/reposec-fixed.py` fixes the uploaded source's missing `Any` typing import and preserves the original discovery function expected by `main()`. The optional CodeQL runner was removed from this fallback copy. The WebUI still prefers your global `/usr/local/bin/reposec` whenever it passes the startup probe.
