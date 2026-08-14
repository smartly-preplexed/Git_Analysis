# Changelog

## 1.2.2

- Fixed Chromium progress-view crashes caused by implicitly returning `scrollIntoView()` from a React Effect.
- Live audit auto-scroll now updates the log container directly and never returns a browser API value from an Effect.
- Active analysis job IDs are mirrored into the `?job=` URL so refresh/recovery works even when session storage is blocked.
- Browser error screen can remount the WebUI without killing or restarting the server-side scan and now exposes a stack trace for diagnostics.

## 1.2.1

- Fix `phase_osint()` returning `None`, which caused `TypeError: 'NoneType' object is not iterable`.
- Detect the affected global/custom RepoSec source and automatically fall back to the corrected bundled engine.
- Make `sessionStorage` optional so Chromium privacy/enterprise storage restrictions cannot prevent the progress view from opening.
- Move to the progress view before attempting job-ID persistence.


## 1.2.0

- Added FIFO multi-user analysis queue.
- Defaulted to 2 concurrent scans and 20 waiting jobs for a 4-core / 16 GB host.
- Added queue position and server-capacity reporting to the WebUI.
- Added queued-job and running-job cancellation.
- Added process-group termination so RepoSec child scanners are stopped on cancellation/timeout.
- Added a configurable 60-minute per-scan timeout.
- Added 24-hour completed-job retention and automatic cleanup.
- Added per-job `tmp/` directories and exports for `REPOSEC_TMP_DIR`, `TMPDIR`, `TEMP`, and `TMP`.
- Patched bundled RepoSec intermediate reports to use the per-job temp directory instead of shared `/tmp/*.json` paths.
- Shared mode now prefers the bundled isolation-safe RepoSec engine.
- Custom/global RepoSec engines are automatically limited to one concurrent scan unless `REPOSEC_PARALLEL_SAFE=1` is explicitly set.
- Added production static serving from the Node API server so `npm run build && npm start` can serve multiple browsers without Vite.
- Added dynamic scheduler information to `/api/health` and cached expensive engine/Git health probes for 60 seconds.
- Kept scan workspaces outside the Vite source tree to prevent target `tsconfig.json` files from reloading the WebUI.
