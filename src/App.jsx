import { useEffect, useMemo, useRef, useState } from 'react'

const DEFAULT_PHASES = {
  osint: true,
  sca: true,
  sast: true,
  container: true,
  binary: true,
}

const PHASES = [
  { id: 'osint', label: 'Secrets & credentials', detail: 'Gitleaks, Trufflehog, git-secrets, pattern scans' },
  { id: 'sca', label: 'Dependencies & CVEs', detail: 'Syft, Grype, OSV, pip-audit, Safety and ecosystem checks' },
  { id: 'sast', label: 'Static code security', detail: 'Semgrep, Bandit, Brakeman, govulncheck and Checkov' },
  { id: 'container', label: 'Containers & IaC', detail: 'Trivy filesystem and infrastructure configuration checks' },
  { id: 'binary', label: 'Binary artifacts', detail: 'file, strings and available binary inspection tooling' },
]

const PIPELINE = [
  ['clone', 'Clone'],
  ['discovery', 'Discover'],
  ['osint', 'Secrets'],
  ['sca', 'SCA'],
  ['sast', 'SAST'],
  ['container', 'Infra'],
  ['binary', 'Binary'],
  ['report', 'Report'],
]

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
const EMPTY_FINDINGS = []
const ACTIVE_JOB_KEY = 'software-vetter.active-analysis-id'

function readActiveJobId() {
  // URL state is the primary reconnect mechanism because it works even when
  // sessionStorage is blocked by browser privacy or enterprise policy.
  try {
    const fromUrl = new URL(globalThis.location.href).searchParams.get('job')
    if (fromUrl) return fromUrl
  } catch {
    // Fall through to optional session storage.
  }

  try {
    return globalThis.sessionStorage?.getItem(ACTIVE_JOB_KEY) || null
  } catch {
    return null
  }
}

function persistActiveJobId(jobId) {
  if (!jobId) return

  try {
    globalThis.sessionStorage?.setItem(ACTIVE_JOB_KEY, jobId)
  } catch {
    // Storage is an optional convenience only.
  }

  try {
    const url = new URL(globalThis.location.href)
    url.searchParams.set('job', jobId)
    globalThis.history?.replaceState?.(null, '', url)
  } catch {
    // A scan must never depend on URL/history mutation succeeding.
  }
}

function clearActiveJobId() {
  try {
    globalThis.sessionStorage?.removeItem(ACTIVE_JOB_KEY)
  } catch {
    // Storage may be unavailable.
  }

  try {
    const url = new URL(globalThis.location.href)
    url.searchParams.delete('job')
    globalThis.history?.replaceState?.(null, '', url)
  } catch {
    // Ignore history restrictions.
  }
}

function providerFor(value) {
  try {
    const host = new URL(value).hostname.toLowerCase()
    if (host.includes('gitlab')) return 'GitLab'
    if (host.includes('github')) return 'GitHub'
    return host || 'Git'
  } catch {
    return 'GitHub / GitLab'
  }
}

function formatDate(value) {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString()
}

function riskTone(score = 0) {
  if (score >= 80) return 'critical'
  if (score >= 60) return 'high'
  if (score >= 40) return 'medium'
  if (score >= 20) return 'low'
  return 'minimal'
}

function App() {
  const [view, setView] = useState('submit')
  const [repoUrl, setRepoUrl] = useState('')
  const [phases, setPhases] = useState(DEFAULT_PHASES)
  const [health, setHealth] = useState(null)
  const [job, setJob] = useState(null)
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => {
    let cancelled = false
    const refreshHealth = () => {
      fetch('/api/health', { cache: 'no-store' })
        .then((res) => res.json())
        .then((payload) => { if (!cancelled) setHealth(payload) })
        .catch(() => { if (!cancelled) setHealth({ ok: false, reposec: { available: false }, git: { available: false } }) })
    }
    refreshHealth()
    const timer = setInterval(refreshHealth, 5000)
    return () => { cancelled = true; clearInterval(timer) }
  }, [])

  // Restore the active job after a browser refresh/HMR reload. This keeps a
  // long RepoSec scan visible even if the WebUI itself reloads unexpectedly.
  useEffect(() => {
    const activeJobId = readActiveJobId()
    if (!activeJobId) return

    let cancelled = false
    fetch(`/api/analyses/${activeJobId}`)
      .then(async (res) => {
        if (!res.ok) throw new Error('saved analysis is no longer available')
        return res.json()
      })
      .then((savedJob) => {
        if (cancelled) return
        setJob(savedJob)
        setView(savedJob.status === 'completed' ? 'report' : 'progress')
      })
      .catch(() => {
        clearActiveJobId()
      })

    return () => { cancelled = true }
  }, [])

  useEffect(() => {
    if (!job?.id || ['completed', 'failed', 'cancelled'].includes(job.status)) return undefined
    const timer = setInterval(async () => {
      try {
        const res = await fetch(`/api/analyses/${job.id}`)
        if (!res.ok) throw new Error(`Analysis status request failed (${res.status})`)
        const next = await res.json()
        setJob(next)
        persistActiveJobId(next.id)
        if (next.status === 'completed') setView('report')
      } catch {
        // Keep the last known job visible; the next poll may recover.
      }
    }, 900)
    return () => clearInterval(timer)
  }, [job?.id, job?.status])

  async function startAnalysis(event) {
    event?.preventDefault()
    setError('')
    setSubmitting(true)
    try {
      const res = await fetch('/api/analyses', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ repoUrl, phases }),
      })
      const responseText = await res.text()
      let payload = {}
      try {
        payload = responseText ? JSON.parse(responseText) : {}
      } catch {
        throw new Error(`Analysis API returned an invalid response (${res.status}).`)
      }
      if (!res.ok) throw new Error(payload.error || `Unable to start analysis (${res.status}).`)
      if (!payload.id) throw new Error('Analysis API did not return a job ID.')
      setJob(payload)
      setView('progress')
      persistActiveJobId(payload.id)
    } catch (err) {
      setError(err.message)
    } finally {
      setSubmitting(false)
    }
  }

  async function cancelAnalysis() {
    if (!job?.id) return
    const res = await fetch(`/api/analyses/${job.id}`, { method: 'DELETE' })
    const payload = await res.json()
    setJob(payload)
  }

  function reset() {
    clearActiveJobId()
    setJob(null)
    setError('')
    setView('submit')
  }

  const navReportEnabled = job?.status === 'completed'

  return (
    <div className="app-shell">
      <Header
        view={view}
        setView={setView}
        health={health}
        progressEnabled={Boolean(job)}
        reportEnabled={navReportEnabled}
        onReset={reset}
      />

      <main className="page-shell">
        {view === 'submit' && (
          <SubmitView
            repoUrl={repoUrl}
            setRepoUrl={setRepoUrl}
            phases={phases}
            setPhases={setPhases}
            health={health}
            error={error}
            submitting={submitting}
            onSubmit={startAnalysis}
          />
        )}

        {view === 'progress' && job && (
          <ProgressView job={job} onCancel={cancelAnalysis} onReport={() => setView('report')} />
        )}

        {view === 'report' && job?.result && (
          <ReportView job={job} onNewScan={reset} />
        )}
      </main>

      <FooterConsole job={job} />
    </div>
  )
}

function Header({ view, setView, health, progressEnabled, reportEnabled, onReset }) {
  const status = health === null ? 'checking' : health.ok ? 'online' : 'offline'
  return (
    <header className="topbar">
      <button className="brand" onClick={onReset} aria-label="Software Vetter home">
        <span className="brand-mark">◇</span>
        <span>
          <strong>SOFTWARE VETTER</strong>
          <small>REPOSEC WEBUI</small>
        </span>
      </button>

      <nav className="nav-tabs" aria-label="Primary">
        <button className={view === 'submit' ? 'active' : ''} onClick={() => setView('submit')}>SUBMIT</button>
        <button className={view === 'progress' ? 'active' : ''} disabled={!progressEnabled} onClick={() => setView('progress')}>PROGRESS</button>
        <button className={view === 'report' ? 'active' : ''} disabled={!reportEnabled} onClick={() => setView('report')}>REPORT</button>
      </nav>

      <div className={`engine-status ${status}`}>
        <span className="status-dot" />
        <div>
          <strong>{status === 'online' ? 'ENGINE READY' : status === 'checking' ? 'CHECKING ENGINE' : 'ENGINE OFFLINE'}</strong>
          <small>{health?.scheduler ? `${health.scheduler.maxConcurrent} scan slots · ${health.scheduler.queued} queued` : (health?.reposec?.path || '/usr/local/bin/reposec')}</small>
        </div>
      </div>
    </header>
  )
}

function SubmitView({ repoUrl, setRepoUrl, phases, setPhases, health, error, submitting, onSubmit }) {
  const provider = providerFor(repoUrl)
  const enabledCount = Object.values(phases).filter(Boolean).length
  const ready = Boolean(repoUrl.trim()) && enabledCount > 0 && !submitting

  return (
    <section className="submit-layout">
      <div className="hero-copy">
        <div className="eyebrow"><span /> LOCAL-FIRST REPOSITORY SECURITY ANALYSIS</div>
        <h1>Inspect a GitHub or GitLab repository before you trust it.</h1>
        <p>
          Software Vetter clones the repository locally, hands it to your installed RepoSec engine,
          then turns RepoSec findings into a live, searchable security report.
        </p>
        <div className="hero-badges">
          <span>GITHUB + GITLAB</span>
          <span>REPOSEC NATIVE</span>
          <span>LOCAL EXECUTION</span>
          <span>NO MOCK DATA</span>
        </div>
      </div>

      <form className="submit-card" onSubmit={onSubmit}>
        <div className="card-kicker">NEW ANALYSIS</div>
        <h2>Repository target</h2>
        <label className="field-label" htmlFor="repo-url">HTTPS repository URL</label>
        <div className="repo-input-wrap">
          <span className="repo-glyph">⌘</span>
          <input
            id="repo-url"
            value={repoUrl}
            onChange={(event) => setRepoUrl(event.target.value)}
            placeholder="https://github.com/owner/repo"
            spellCheck="false"
            autoComplete="off"
          />
          <span className="provider-chip">{provider}</span>
        </div>
        <div className="field-help">Public repositories work immediately. Private repositories use your machine's existing Git credentials.</div>
        {health?.scheduler && (
          <div className="capacity-strip">
            <span><b>{health.scheduler.maxConcurrent}</b> concurrent scan slots</span>
            <span><b>{health.scheduler.maxQueued}</b> queue capacity</span>
            <span><b>{health.timeoutMinutes}</b> min timeout</span>
          </div>
        )}

        <div className="section-heading">
          <span>SCAN SCOPE</span>
          <small>{enabledCount} / {PHASES.length} enabled</small>
        </div>
        <div className="phase-options">
          {PHASES.map((phase) => (
            <label key={phase.id} className={`phase-option ${phases[phase.id] ? 'selected' : ''}`}>
              <input
                type="checkbox"
                checked={phases[phase.id]}
                onChange={() => setPhases((current) => ({ ...current, [phase.id]: !current[phase.id] }))}
              />
              <span className="fake-check">✓</span>
              <span className="phase-copy">
                <strong>{phase.label}</strong>
                <small>{phase.detail}</small>
              </span>
            </label>
          ))}
        </div>

        {!health?.ok && health !== null && (
          <div className="notice danger">
            <strong>Local engine unavailable.</strong>
            <span>
              RepoSec: {health?.reposec?.available ? 'found' : 'not found'} · Git: {health?.git?.available ? 'found' : 'not found'}.
              The API expects {health?.reposec?.path || '/usr/local/bin/reposec'}.
            </span>
          </div>
        )}
        {error && <div className="notice danger"><strong>Unable to start.</strong><span>{error}</span></div>}

        <button className="primary-action" disabled={!ready} type="submit">
          <span>{submitting ? 'STARTING…' : 'RUN REPOSEC ANALYSIS'}</span>
          <b>→</b>
        </button>
        <p className="consent-note">Only scan repositories you are authorized to inspect. Repository code is cloned and parsed locally by the scanners installed on this machine.</p>
      </form>

      <div className="workflow-strip">
        {[
          ['01', 'Clone', 'GitHub / GitLab'],
          ['02', 'Scan', 'RepoSec pipeline'],
          ['03', 'Score', 'Risk + severity'],
          ['04', 'Review', 'Findings + artifacts'],
        ].map(([num, title, detail]) => (
          <div className="workflow-step" key={num}>
            <span>{num}</span>
            <div><strong>{title}</strong><small>{detail}</small></div>
          </div>
        ))}
      </div>
    </section>
  )
}

function ProgressView({ job, onCancel, onReport }) {
  const activeIndex = PIPELINE.findIndex(([id]) => id === job.stage)
  const complete = job.status === 'completed'
  const queued = job.status === 'queued'
  const terminal = ['failed', 'cancelled'].includes(job.status)

  return (
    <section className="progress-layout">
      <div className="page-heading">
        <div>
          <div className="eyebrow"><span /> ANALYSIS JOB {job.id}</div>
          <h1>{job.repoName}</h1>
          <p>{job.provider} · {job.repoUrl}</p>
        </div>
        <div className={`job-state ${job.status}`}>{job.status.toUpperCase()}</div>
      </div>

      <div className="progress-card">
        {queued && (
          <div className="queue-banner">
            <div>
              <small>WAITING FOR CAPACITY</small>
              <strong>Queue position #{job.queuePosition || 1}</strong>
            </div>
            <span>{job.scheduler?.active || 0} / {job.scheduler?.maxConcurrent || 1} scan slots active</span>
          </div>
        )}
        <div className="progress-topline">
          <div>
            <small>CURRENT STAGE</small>
            <strong>{job.stageLabel}</strong>
          </div>
          <div className="progress-number">{job.progress}%</div>
        </div>
        <div className="bar"><div style={{ width: `${job.progress}%` }} /></div>

        <div className="pipeline-grid">
          {PIPELINE.map(([id, label], index) => {
            const skipped = ['osint', 'sca', 'sast', 'container', 'binary'].includes(id) && !job.enabledPhases.includes(id)
            const done = complete || index < activeIndex
            const active = !queued && !complete && index === activeIndex && !terminal
            return (
              <div key={id} className={`pipeline-step ${done ? 'done' : ''} ${active ? 'active' : ''} ${skipped ? 'skipped' : ''}`}>
                <span className="pipeline-node">{skipped ? '–' : done ? '✓' : index + 1}</span>
                <strong>{label}</strong>
                <small>{skipped ? 'SKIPPED' : done ? 'DONE' : active ? 'RUNNING' : queued ? 'QUEUED' : 'WAITING'}</small>
              </div>
            )
          })}
        </div>
      </div>

      <div className="progress-columns">
        <div className="terminal-card">
          <div className="terminal-title"><span>LIVE AUDIT STREAM</span><small>{job.logs.length} events</small></div>
          <LogStream logs={job.logs} />
        </div>
        <aside className="job-details">
          <div className="detail-card">
            <span>PROVIDER</span><strong>{job.provider}</strong>
          </div>
          <div className="detail-card">
            <span>{queued ? 'QUEUED AT' : 'STARTED'}</span><strong>{formatDate(queued ? job.createdAt : job.startedAt)}</strong>
          </div>
          <div className="detail-card">
            <span>{queued ? 'QUEUE POSITION' : 'SERVER SLOTS'}</span>
            <strong>{queued ? `#${job.queuePosition || 1}` : `${job.scheduler?.active || 0} / ${job.scheduler?.maxConcurrent || 1}`}</strong>
          </div>
          <div className="detail-card">
            <span>SCOPES</span><strong>{job.enabledPhases.length}</strong>
          </div>
          <div className="detail-card">
            <span>JOB ID</span><strong className="mono-small">{job.id}</strong>
          </div>
          {job.error && <div className="notice danger"><strong>{job.status.toUpperCase()}</strong><span>{job.error}</span></div>}
          {!complete && !terminal && <button className="secondary-action danger-text" onClick={onCancel}>CANCEL ANALYSIS</button>}
          {complete && <button className="primary-action" onClick={onReport}><span>OPEN SECURITY REPORT</span><b>→</b></button>}
        </aside>
      </div>
    </section>
  )
}

function LogStream({ logs }) {
  const streamRef = useRef(null)
  const safeLogs = Array.isArray(logs) ? logs : EMPTY_FINDINGS

  useEffect(() => {
    // Do not implicitly return scrollIntoView(). New Chromium builds return a
    // Promise from scrolling APIs; React would interpret that return value as
    // an Effect cleanup function and later throw "... is not a function".
    // Directly updating the scroll container is synchronous and browser-neutral.
    const stream = streamRef.current
    if (!stream) return
    stream.scrollTop = stream.scrollHeight
  }, [safeLogs.length])

  return (
    <div className="log-stream" ref={streamRef}>
      {safeLogs.length === 0 && <div className="log-placeholder">Waiting for analyzer output…</div>}
      {safeLogs.map((entry, index) => (
        <div className={`log-row ${entry?.source || 'system'}`} key={`${entry?.at || 'log'}-${index}`}>
          <span>{entry?.at ? new Date(entry.at).toLocaleTimeString([], { hour12: false }) : '--:--:--'}</span>
          <b>{entry?.source || 'system'}</b>
          <code>{entry?.message || ''}</code>
        </div>
      ))}
    </div>
  )
}

function ReportView({ job, onNewScan }) {
  const result = job.result
  const risk = result.risk || {}
  const findings = Array.isArray(result.findings) ? result.findings : EMPTY_FINDINGS
  const meta = result.meta || {}
  const [severity, setSeverity] = useState('ALL')
  const [phase, setPhase] = useState('ALL')
  const [query, setQuery] = useState('')
  const [expanded, setExpanded] = useState(null)

  const filtered = useMemo(() => findings.filter((finding) => {
    const sev = String(finding.severity || 'INFO').toUpperCase()
    if (severity !== 'ALL' && sev !== severity) return false
    if (phase !== 'ALL' && String(finding.phase || '').toUpperCase() !== phase) return false
    if (query.trim()) {
      const haystack = [finding.title, finding.description, finding.file, finding.tool, finding.cve, finding.cwe, finding.package].join(' ').toLowerCase()
      if (!haystack.includes(query.toLowerCase())) return false
    }
    return true
  }), [findings, severity, phase, query])

  const phaseNames = [...new Set(findings.map((finding) => String(finding.phase || '').toUpperCase()).filter(Boolean))]
  const score = Number(risk.overall || 0)
  const tone = riskTone(score)
  const toolNames = [...new Set(findings.map((finding) => finding.tool).filter(Boolean))]

  return (
    <section className="report-layout">
      <div className="report-header">
        <div>
          <div className="eyebrow"><span /> REPOSEC ANALYSIS COMPLETE</div>
          <h1>{result.repo || job.repoName}</h1>
          <p>{job.repoUrl} · generated {formatDate(result.generated)}</p>
        </div>
        <div className="report-actions">
          <button className="secondary-action" onClick={onNewScan}>NEW SCAN</button>
          <a className="primary-link" href={job.artifacts.html} target="_blank" rel="noreferrer">OPEN HTML REPORT ↗</a>
        </div>
      </div>

      <div className="risk-grid">
        <div className={`risk-score-card ${tone}`}>
          <div className="card-kicker">OVERALL RISK</div>
          <div className="risk-orb" style={{ '--risk': `${score * 3.6}deg` }}>
            <div><strong>{score}</strong><span>/100</span></div>
          </div>
          <div className="risk-label">{tone.toUpperCase()} RISK</div>
          <div className="risk-secondary"><span>GRADE <b>{risk.grade || '—'}</b></span><span>CVSS <b>{risk.cvss ?? '—'}</b></span></div>
        </div>

        <div className="severity-card">
          <div className="card-kicker">SEVERITY BREAKDOWN</div>
          <div className="severity-grid">
            {SEVERITIES.map((sev) => <SeverityStat key={sev} severity={sev} count={risk.counts?.[sev] || 0} />)}
          </div>
          <div className="finding-total"><span>TOTAL FINDINGS</span><strong>{risk.total ?? findings.length}</strong></div>
        </div>

        <div className="repo-meta-card">
          <div className="card-kicker">REPOSITORY PROFILE</div>
          <MetaRow label="Files" value={meta.files ?? '—'} />
          <MetaRow label="Directories" value={meta.dirs ?? '—'} />
          <MetaRow label="Manifests" value={meta.manifests?.length ?? 0} />
          <MetaRow label="Sensitive names" value={meta.sensitive?.length ?? 0} warn={Boolean(meta.sensitive?.length)} />
          <MetaRow label="Provider" value={job.provider} />
        </div>
      </div>

      <div className="phase-breakdown">
        {Object.entries(risk.breakdown || {}).map(([name, value]) => (
          <div className="phase-risk" key={name}>
            <div><span>{name.toUpperCase()}</span><strong>{value}</strong></div>
            <div className="mini-bar"><i style={{ width: `${Math.min(100, Number(value) || 0)}%` }} /></div>
          </div>
        ))}
      </div>

      <div className="results-panel">
        <div className="results-toolbar">
          <div>
            <div className="card-kicker">FINDINGS EXPLORER</div>
            <h2>{filtered.length} matching findings</h2>
          </div>
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search CVE, CWE, file, package, tool…" />
        </div>

        <div className="filter-row">
          <div className="filter-group">
            {['ALL', ...SEVERITIES].map((item) => <button key={item} className={severity === item ? 'active' : ''} onClick={() => setSeverity(item)}>{item}</button>)}
          </div>
          <div className="filter-group phases">
            {['ALL', ...phaseNames].map((item) => <button key={item} className={phase === item ? 'active' : ''} onClick={() => setPhase(item)}>{item}</button>)}
          </div>
        </div>

        <div className="findings-list">
          {filtered.length === 0 && <div className="empty-state">No findings match the current filters.</div>}
          {filtered.map((finding, index) => {
            const sev = String(finding.severity || 'INFO').toUpperCase()
            const key = `${finding.tool}-${finding.file}-${finding.line}-${index}`
            const open = expanded === key
            return (
              <article className={`finding-row sev-${sev.toLowerCase()}`} key={key}>
                <button className="finding-main" onClick={() => setExpanded(open ? null : key)}>
                  <span className={`severity-pill sev-${sev.toLowerCase()}`}>{sev}</span>
                  <span className="finding-copy">
                    <strong>{finding.title || 'Untitled finding'}</strong>
                    <small>{finding.tool || 'RepoSec'} · {String(finding.phase || 'analysis').toUpperCase()}</small>
                  </span>
                  <span className="finding-location">{finding.file ? `${finding.file}${finding.line ? `:${finding.line}` : ''}` : finding.package || finding.cve || '—'}</span>
                  <span className="chevron">{open ? '⌃' : '⌄'}</span>
                </button>
                {open && (
                  <div className="finding-detail">
                    <div>
                      <span>DESCRIPTION</span>
                      <p>{finding.description || 'No extended description supplied by the scanner.'}</p>
                    </div>
                    <div>
                      <span>REMEDIATION</span>
                      <p>{finding.remediation || 'Review the finding and apply the relevant secure coding or upgrade guidance.'}</p>
                    </div>
                    <div className="finding-tags">
                      {finding.cve && <b>{finding.cve}</b>}
                      {finding.cwe && <b>{finding.cwe}</b>}
                      {finding.package && <b>{finding.package}</b>}
                    </div>
                  </div>
                )}
              </article>
            )
          })}
        </div>
      </div>

      <div className="report-bottom-grid">
        <div className="artifact-card">
          <div className="card-kicker">REPOSEC ARTIFACTS</div>
          <Artifact href={job.artifacts.html} label="Interactive HTML report" ext="HTML" />
          <Artifact href={job.artifacts.json} label="Normalized findings" ext="JSON" />
          <Artifact href={job.artifacts.sarif} label="Security analysis interchange" ext="SARIF" />
          <Artifact href={job.artifacts.mermaid} label="Repository structure" ext="MMD" />
        </div>
        <div className="artifact-card">
          <div className="card-kicker">TOOLS OBSERVED IN FINDINGS</div>
          <div className="tool-cloud">
            {toolNames.length ? toolNames.map((tool) => <span key={tool}>{tool}</span>) : <span>RepoSec completed with no reported findings</span>}
          </div>
          {meta.sensitive?.length > 0 && (
            <div className="sensitive-box">
              <strong>Sensitive filename patterns</strong>
              {meta.sensitive.slice(0, 12).map((item) => <code key={item}>{item}</code>)}
            </div>
          )}
        </div>
      </div>
    </section>
  )
}

function SeverityStat({ severity, count }) {
  return <div className={`severity-stat sev-${severity.toLowerCase()}`}><span>{severity}</span><strong>{count}</strong></div>
}

function MetaRow({ label, value, warn }) {
  return <div className="meta-row"><span>{label}</span><strong className={warn ? 'warn' : ''}>{value}</strong></div>
}

function Artifact({ href, label, ext }) {
  return <a className="artifact-row" href={href} target={ext === 'HTML' ? '_blank' : undefined} rel="noreferrer"><span><b>{ext}</b>{label}</span><strong>↗</strong></a>
}

function FooterConsole({ job }) {
  const [open, setOpen] = useState(false)
  if (!job) return null
  return (
    <div className={`footer-console ${open ? 'open' : ''}`}>
      <button className="console-toggle" onClick={() => setOpen((value) => !value)}>
        <span><i /> AUDIT CONSOLE</span>
        <span>{job.logs.length} EVENTS {open ? '⌄' : '⌃'}</span>
      </button>
      {open && <LogStream logs={job.logs} />}
    </div>
  )
}

export default App
