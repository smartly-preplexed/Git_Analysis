# Repo Analysis

A shared-server React interface for running RepoSec against GitHub and GitLab repositories.

This release adds a bounded multi-user scan queue and per-job RepoSec isolation so multiple browsers can submit analyses to one server without sharing scanner output files.

### v1.2.1 fixes

- Fixes the RepoSec `phase_osint()` regression that returned `None` and crashed at `all_findings.extend(...)`.
- Detects an affected configured/global Python RepoSec and falls back to the corrected bundled engine.
- Browser job persistence is now optional: Chromium storage/privacy policies cannot block the progress view.
- The Run button no longer depends on the health-check request succeeding; the analysis POST is the source of truth and surfaces its own error.
- A React error boundary prevents unexpected browser-side exceptions from leaving a blank/black page.

## Chromium live-progress compatibility

Version 1.2.2 avoids returning browser scrolling API values from React Effects. This prevents recent Chromium builds, where scrolling APIs may return promises, from being mistaken for React Effect cleanup functions. Active jobs are also mirrored in the `?job=` URL so a refresh can reconnect even when session storage is unavailable.


## Recommended settings for 4 CPU cores / 16 GB RAM

Start with two concurrent scans:

```bash
export API_HOST=0.0.0.0
export API_PORT=8787
export MAX_CONCURRENT_SCANS=2
export MAX_QUEUED_SCANS=20
export ANALYSIS_TIMEOUT_MINUTES=60
export JOB_RETENTION_HOURS=24
export REPOSEC_RUN_DIR=/var/tmp/software-vetter-reposec-runs
```

`MAX_CONCURRENT_SCANS=2` is the default. If the machine becomes memory constrained during large Semgrep/Trivy/Grype jobs, reduce it to `1`.

## Install and run

```bash
npm install
npm run build
npm start
```

With `API_HOST=0.0.0.0`, users on the same network can open:

```text
http://SERVER-IP:8787
```

The Node server serves the production React build and the `/api` endpoints from the same port. `npm run dev` is still available for development and starts Vite plus the local API.

## Multi-user queue

The backend maintains a FIFO queue:

- At most `MAX_CONCURRENT_SCANS` jobs run at once.
- Up to `MAX_QUEUED_SCANS` additional jobs can wait.
- Each queued browser sees its queue position and the current number of active scan slots.
- When a running scan finishes or is cancelled, the next queued job starts automatically.
- A queued job can be cancelled without consuming a scan slot.
- A running cancellation terminates the RepoSec process group so child scanners are not intentionally left behind.
- Jobs exceeding `ANALYSIS_TIMEOUT_MINUTES` are terminated and marked failed.

The queue is in memory. Restarting the Node server clears queued/running job state. Completed artifact directories remain on disk until cleanup.

## Per-job RepoSec isolation

Each analysis gets its own workspace:

```text
/var/tmp/software-vetter-reposec-runs/<job-id>/
├── repository/   # temporary Git clone
├── tmp/          # isolated scanner temporary files
└── output/       # RepoSec HTML/JSON/SARIF/Mermaid artifacts
```

The server exports these variables only to that RepoSec job:

```text
REPOSEC_TMP_DIR=<job>/tmp
TMPDIR=<job>/tmp
TEMP=<job>/tmp
TMP=<job>/tmp
```

The bundled `tools/reposec-fixed.py` was patched so its intermediate Gitleaks, Syft, Grype, Dependency-Check, Semgrep, Bandit, Brakeman, Trivy, and ZAP report paths are created under `REPOSEC_TMP_DIR` instead of shared `/tmp/*.json` names.

The repository clone and temporary directory are removed after the job. Report artifacts are retained for `JOB_RETENTION_HOURS` (24 hours by default), after which the backend removes the whole job directory and in-memory record.

## RepoSec engine selection

For shared mode, the backend intentionally prefers the bundled isolation-safe RepoSec copy.

If you explicitly want to use your global engine:

```bash
export REPOSEC_BIN=/usr/local/bin/reposec
```

A custom/global engine is conservatively limited to **one concurrent scan** unless you explicitly declare it parallel-safe:

```bash
export REPOSEC_PARALLEL_SAFE=1
```

Only set `REPOSEC_PARALLEL_SAFE=1` if that RepoSec installation has been updated to honor `REPOSEC_TMP_DIR` for all fixed intermediate report filenames. Setting the flag on an older copy that still writes files such as `/tmp/gitleaks_report.json` defeats per-job isolation.

To make your global copy match the bundled isolation-safe version, review the bundled file and then install it if desired:

```bash
sudo install -m 0755 tools/reposec-fixed.py /usr/local/bin/reposec
export REPOSEC_BIN=/usr/local/bin/reposec
export REPOSEC_PARALLEL_SAFE=1
```

## GitHub and GitLab

The backend validates HTTPS repository URLs, clones with `git clone --depth=1`, then passes the local clone path to RepoSec. This also supports GitLab group/subgroup repository URLs even though the original RepoSec URL parser is GitHub-focused.

Private repositories can work when the server account already has non-interactive Git credentials configured. Do not paste tokens into the WebUI URL field.

To allow self-hosted GitLab:

```bash
export REPOSEC_ALLOWED_GIT_HOSTS=github.com,gitlab.com,gitlab.example.com
```

## Artifacts

A successful scan exposes:

- `reposec_report.html`
- `findings.json`
- `findings.sarif`
- `structure.mmd`

Known secret-shaped values are redacted from WebUI logs and normalized JSON returned through the job API. Raw RepoSec artifacts remain server-side files and should be treated as sensitive security-analysis output.

## Production exposure

For a trusted LAN, binding `API_HOST=0.0.0.0` is enough to make the service reachable. For a broader network, place it behind Nginx/Caddy or another reverse proxy with TLS and authentication.

The app itself does not provide user authentication. Anyone who can reach the server can submit an allowed GitHub/GitLab URL for analysis, so network access control is important.

## Environment variables

See `.env.example` for the complete set:

- `API_HOST`
- `API_PORT`
- `MAX_CONCURRENT_SCANS`
- `MAX_QUEUED_SCANS`
- `ANALYSIS_TIMEOUT_MINUTES`
- `JOB_RETENTION_HOURS`
- `REPOSEC_RUN_DIR`
- `REPOSEC_ALLOWED_GIT_HOSTS`
- `REPOSEC_BIN`
- `REPOSEC_PARALLEL_SAFE`

## Development

```bash
npm run dev
```

Vite listens on port `5173` and proxies `/api` to port `8787`. Scan workspaces remain outside the Vite source tree, so a target repository's `tsconfig.json` cannot trigger a WebUI full reload.
