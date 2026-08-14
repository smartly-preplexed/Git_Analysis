import http from 'node:http'
import { spawn } from 'node:child_process'
import { access, mkdir, readFile, rm, stat } from 'node:fs/promises'
import { constants as fsConstants } from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import crypto from 'node:crypto'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const PROJECT_DIR = path.resolve(__dirname, '..')
const PORT = numberEnv('API_PORT', 8787, 1, 65535)
const HOST = process.env.API_HOST || '127.0.0.1'
const DIST_DIR = path.join(PROJECT_DIR, 'dist')
const CONFIGURED_REPOSEC_BIN = process.env.REPOSEC_BIN || ''
const SYSTEM_REPOSEC_BIN = '/usr/local/bin/reposec'
const BUNDLED_REPOSEC_BIN = path.join(PROJECT_DIR, 'tools', 'reposec-fixed.py')
const RUN_ROOT = path.resolve(process.env.REPOSEC_RUN_DIR || path.join(tmpdir(), 'software-vetter-reposec-runs'))
const REQUESTED_MAX_CONCURRENT = numberEnv('MAX_CONCURRENT_SCANS', 2, 1, 16)
const MAX_QUEUED_SCANS = numberEnv('MAX_QUEUED_SCANS', 20, 1, 500)
const ANALYSIS_TIMEOUT_MS = numberEnv('ANALYSIS_TIMEOUT_MINUTES', 60, 1, 1440) * 60 * 1000
const JOB_RETENTION_MS = numberEnv('JOB_RETENTION_HOURS', 24, 1, 720) * 60 * 60 * 1000
const CUSTOM_ENGINE_PARALLEL_SAFE = /^(1|true|yes)$/i.test(process.env.REPOSEC_PARALLEL_SAFE || '')
const ALLOWED_HOSTS = new Set(
  (process.env.REPOSEC_ALLOWED_GIT_HOSTS || 'github.com,gitlab.com')
    .split(',')
    .map((host) => host.trim().toLowerCase())
    .filter(Boolean),
)

const PHASE_ORDER = ['clone', 'discovery', 'osint', 'sca', 'sast', 'container', 'binary', 'report']
const PHASE_LABELS = {
  clone: 'Clone repository',
  discovery: 'Repository discovery',
  osint: 'Secrets & credential scan',
  sca: 'Software composition analysis',
  sast: 'Static application security testing',
  container: 'Container & infrastructure scan',
  binary: 'Binary artifact inspection',
  report: 'Risk scoring & report generation',
}

const jobs = new Map()
const pendingQueue = []
let activeScans = 0
let engineCache = null
let healthCache = null
let healthCacheAt = 0
let effectiveMaxConcurrent = REQUESTED_MAX_CONCURRENT

function numberEnv(name, fallback, min, max) {
  const parsed = Number(process.env[name])
  if (!Number.isFinite(parsed)) return fallback
  return Math.max(min, Math.min(max, Math.floor(parsed)))
}

function json(res, status, payload) {
  const body = JSON.stringify(payload)
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
  })
  res.end(body)
}

async function parseBody(req) {
  let raw = ''
  for await (const chunk of req) {
    raw += chunk
    if (raw.length > 64 * 1024) throw new Error('Request body too large')
  }
  if (!raw) return {}
  return JSON.parse(raw)
}

function validateRepoUrl(value) {
  let parsed
  try {
    parsed = new URL(String(value || '').trim())
  } catch {
    throw new Error('Enter a valid GitHub or GitLab HTTPS repository URL.')
  }

  if (parsed.protocol !== 'https:') throw new Error('Repository URL must use HTTPS.')
  if (parsed.username || parsed.password) throw new Error('Do not put credentials or access tokens in the repository URL.')

  const host = parsed.hostname.toLowerCase()
  if (!ALLOWED_HOSTS.has(host)) {
    throw new Error(`Git host "${host}" is not allowed. Configure REPOSEC_ALLOWED_GIT_HOSTS to add it.`)
  }

  const parts = parsed.pathname.replace(/^\/+|\/+$/g, '').split('/').filter(Boolean)
  if (parts.length < 2) throw new Error('Repository URL must include an owner/group and repository name.')

  parsed.search = ''
  parsed.hash = ''
  parsed.pathname = `/${parts.join('/')}`
  return parsed.toString().replace(/\/$/, '')
}

function providerFromUrl(repoUrl) {
  const host = new URL(repoUrl).hostname.toLowerCase()
  return host.includes('gitlab') ? 'GitLab' : host.includes('github') ? 'GitHub' : host
}

function stripAnsi(value) {
  // eslint-disable-next-line no-control-regex
  return String(value || '').replace(/\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])/g, '')
}

function redactSensitive(value) {
  return String(value || '')
    .replace(/(gh[pousr]_[A-Za-z0-9_]{20,})/g, '[REDACTED_GITHUB_TOKEN]')
    .replace(/((?:AKIA|ABIA|ACCA)[0-9A-Z]{16})/g, '[REDACTED_AWS_KEY]')
    .replace(/(xox[baprs]-[A-Za-z0-9-]{10,})/g, '[REDACTED_SLACK_TOKEN]')
    .replace(/((?:Match|Raw|Secret|Password|Token|API[_ -]?Key)\s*[:=]\s*)[^\s|,;]+/gi, '$1[REDACTED]')
}

function sanitizeDeep(value) {
  if (typeof value === 'string') return redactSensitive(value)
  if (Array.isArray(value)) return value.map(sanitizeDeep)
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, sanitizeDeep(item)]))
  }
  return value
}

function pushLog(job, source, chunk) {
  const lines = stripAnsi(chunk).split(/\r?\n/).map((line) => redactSensitive(line)).filter(Boolean)
  for (const line of lines) {
    job.logs.push({ at: new Date().toISOString(), source, message: line.slice(0, 1000) })
    if (job.logs.length > 500) job.logs.shift()
    updateStageFromLine(job, line)
  }
}

function setStage(job, stage) {
  if (!PHASE_ORDER.includes(stage)) return
  job.stage = stage
  const index = PHASE_ORDER.indexOf(stage)
  job.progress = Math.max(job.progress || 0, Math.round((index / (PHASE_ORDER.length - 1)) * 100))
}

function updateStageFromLine(job, line) {
  const normalized = line.toLowerCase()
  if (normalized.includes('phase 01') || normalized.includes('repository discovery')) setStage(job, 'discovery')
  else if (normalized.includes('phase 02') || normalized.includes('secret & credential')) setStage(job, 'osint')
  else if (normalized.includes('phase 03') || normalized.includes('software composition')) setStage(job, 'sca')
  else if (normalized.includes('phase 04') || normalized.includes('static application security')) setStage(job, 'sast')
  else if (normalized.includes('phase 05') || normalized.includes('container & infrastructure')) setStage(job, 'container')
  else if (normalized.includes('phase 06') || normalized.includes('binary & compiled')) setStage(job, 'binary')
  else if (normalized.includes('phase 08') || normalized.includes('phase 09') || normalized.includes('risk scoring') || normalized.includes('saving reports')) setStage(job, 'report')
}

function queuePosition(job) {
  if (job.status !== 'queued') return null
  const position = pendingQueue.indexOf(job.id)
  return position >= 0 ? position + 1 : null
}

function schedulerSnapshot() {
  return {
    active: activeScans,
    maxConcurrent: effectiveMaxConcurrent,
    queued: pendingQueue.length,
    maxQueued: MAX_QUEUED_SCANS,
  }
}

function publicJob(job) {
  return {
    id: job.id,
    status: job.status,
    repoUrl: job.repoUrl,
    provider: job.provider,
    repoName: job.repoName,
    enginePath: job.enginePath || engineCache?.path || null,
    createdAt: job.createdAt,
    startedAt: job.startedAt,
    finishedAt: job.finishedAt,
    stage: job.stage,
    stageLabel: job.status === 'queued' ? 'Waiting for an analysis slot' : PHASE_LABELS[job.stage] || job.stage,
    progress: job.status === 'completed' ? 100 : job.progress,
    enabledPhases: job.enabledPhases,
    logs: job.logs,
    error: job.error,
    result: job.result,
    queuePosition: queuePosition(job),
    scheduler: schedulerSnapshot(),
    artifacts: job.status === 'completed' ? {
      html: `/api/analyses/${job.id}/artifacts/reposec_report.html`,
      json: `/api/analyses/${job.id}/artifacts/findings.json`,
      sarif: `/api/analyses/${job.id}/artifacts/findings.sarif`,
      mermaid: `/api/analyses/${job.id}/artifacts/structure.mmd`,
    } : null,
  }
}

function spawnProcess(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      ...options,
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let stdout = ''
    let stderr = ''
    child.stdout?.on('data', (chunk) => { stdout += chunk.toString() })
    child.stderr?.on('data', (chunk) => { stderr += chunk.toString() })
    child.once('error', reject)
    child.once('close', (code, signal) => resolve({ code, signal, stdout, stderr }))
  })
}

async function binaryAvailable(binary) {
  try {
    await access(binary, fsConstants.X_OK)
    return true
  } catch {
    return false
  }
}

async function hasKnownBrokenOsintReturn(binary) {
  // v1.2 briefly shipped a Python RepoSec variant whose phase_osint() fell
  // through without returning its findings list. Detect that exact source-level
  // regression and fall back to the bundled corrected engine before a job starts.
  try {
    const source = await readFile(binary, 'utf8')
    const start = source.indexOf('def phase_osint(')
    if (start < 0) return false
    const tail = source.slice(start)
    const candidates = [tail.indexOf('\nINLINE_RULES:'), tail.indexOf('\ndef phase_'), tail.indexOf('\n# ──')]
      .filter((index) => index > 0)
    const end = candidates.length ? Math.min(...candidates) : Math.min(tail.length, 20000)
    const block = tail.slice(0, end)
    return !/\breturn\s+findings\b/.test(block)
  } catch {
    return false
  }
}

async function resolveRepoSecBinary() {
  if (engineCache) return engineCache

  // The bundled engine is patched to use REPOSEC_TMP_DIR for every intermediate
  // report. Prefer it in shared mode. A custom/global engine is allowed when the
  // operator explicitly selects it, but parallel use requires REPOSEC_PARALLEL_SAFE=1.
  const candidates = CONFIGURED_REPOSEC_BIN
    ? [CONFIGURED_REPOSEC_BIN, BUNDLED_REPOSEC_BIN]
    : [BUNDLED_REPOSEC_BIN, SYSTEM_REPOSEC_BIN]

  let compatibilityFallbackFrom = null
  for (const candidate of candidates) {
    if (!(await binaryAvailable(candidate))) continue
    if (await hasKnownBrokenOsintReturn(candidate)) {
      compatibilityFallbackFrom = candidate
      continue
    }
    const probe = await spawnProcess(candidate, ['--help']).catch(() => ({ code: 1 }))
    if (probe.code !== 0) continue

    const bundled = path.resolve(candidate) === path.resolve(BUNDLED_REPOSEC_BIN)
    const parallelSafe = bundled || CUSTOM_ENGINE_PARALLEL_SAFE
    engineCache = { path: candidate, bundled, parallelSafe, compatibilityFallbackFrom }
    effectiveMaxConcurrent = parallelSafe ? REQUESTED_MAX_CONCURRENT : 1
    return engineCache
  }

  engineCache = { path: candidates[0], bundled: false, parallelSafe: false, compatibilityFallbackFrom }
  effectiveMaxConcurrent = 1
  return engineCache
}

function terminateProcessTree(child, signal = 'SIGTERM') {
  if (!child?.pid) return
  try {
    if (process.platform !== 'win32') process.kill(-child.pid, signal)
    else child.kill(signal)
  } catch {
    try { child.kill(signal) } catch { /* already stopped */ }
  }
}

function requestStop(job, reason, status) {
  job.terminationReason = reason
  job.status = status
  job.error = reason
  job.finishedAt = new Date().toISOString()
  if (job.process) {
    terminateProcessTree(job.process, 'SIGTERM')
    const forceTimer = setTimeout(() => terminateProcessTree(job.process, 'SIGKILL'), 3000)
    forceTimer.unref?.()
  }
}

async function runAnalysis(job) {
  const jobDir = path.join(RUN_ROOT, job.id)
  const cloneDir = path.join(jobDir, 'repository')
  const outputDir = path.join(jobDir, 'output')
  const tempDir = path.join(jobDir, 'tmp')
  job.jobDir = jobDir
  job.cloneDir = cloneDir
  job.outputDir = outputDir
  job.tempDir = tempDir

  const timeoutHandle = setTimeout(() => {
    const reason = `Analysis exceeded the ${Math.round(ANALYSIS_TIMEOUT_MS / 60000)} minute server timeout.`
    pushLog(job, 'system', `TIMEOUT: ${reason}`)
    requestStop(job, reason, 'failed')
  }, ANALYSIS_TIMEOUT_MS)
  timeoutHandle.unref?.()

  try {
    job.status = 'cloning'
    job.startedAt = new Date().toISOString()
    setStage(job, 'clone')
    await mkdir(outputDir, { recursive: true })
    await mkdir(tempDir, { recursive: true })

    const engine = await resolveRepoSecBinary()
    const reposecBin = engine.path
    job.enginePath = reposecBin
    if (!(await binaryAvailable(reposecBin))) {
      throw new Error(`RepoSec executable was not found or is not executable at ${reposecBin}. Set REPOSEC_BIN if yours is elsewhere.`)
    }

    pushLog(job, 'system', `Analysis slot acquired (${activeScans}/${effectiveMaxConcurrent} active).`)
    pushLog(job, 'system', `Isolated temp workspace: ${tempDir}`)
    pushLog(job, 'system', `Cloning ${job.provider} repository ${job.repoUrl}`)

    const clone = spawn('git', ['clone', '--depth=1', '--no-tags', '--', job.repoUrl, cloneDir], {
      shell: false,
      detached: process.platform !== 'win32',
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, GIT_TERMINAL_PROMPT: '0', TMPDIR: tempDir, TEMP: tempDir, TMP: tempDir },
    })
    job.process = clone
    clone.stdout.on('data', (chunk) => pushLog(job, 'git', chunk))
    clone.stderr.on('data', (chunk) => pushLog(job, 'git', chunk))
    const cloneCode = await new Promise((resolve, reject) => {
      clone.once('error', reject)
      clone.once('close', resolve)
    })
    job.process = null
    if (job.status === 'cancelled') return
    if (job.terminationReason) throw new Error(job.terminationReason)
    if (cloneCode !== 0) throw new Error('git clone failed. Confirm the repository is reachable and your Git credentials are configured for private repositories.')

    const repoStat = await stat(cloneDir)
    if (!repoStat.isDirectory()) throw new Error('Repository clone did not create a directory.')

    job.status = 'running'
    setStage(job, 'discovery')
    pushLog(job, 'system', `Starting RepoSec via ${reposecBin}`)

    const allPhases = ['osint', 'sca', 'sast', 'container', 'binary']
    const skipped = allPhases.filter((phase) => !job.enabledPhases.includes(phase))
    skipped.push('dast')

    const args = [cloneDir, '--output', outputDir, '--skip-phases', [...new Set(skipped)].join(',')]
    const scanner = spawn(reposecBin, args, {
      shell: false,
      detached: process.platform !== 'win32',
      stdio: ['ignore', 'pipe', 'pipe'],
      env: {
        ...process.env,
        PYTHONUNBUFFERED: '1',
        REPOSEC_TMP_DIR: tempDir,
        TMPDIR: tempDir,
        TEMP: tempDir,
        TMP: tempDir,
      },
    })
    job.process = scanner
    scanner.stdout.on('data', (chunk) => pushLog(job, 'reposec', chunk))
    scanner.stderr.on('data', (chunk) => pushLog(job, 'reposec', chunk))

    const scanCode = await new Promise((resolve, reject) => {
      scanner.once('error', reject)
      scanner.once('close', resolve)
    })
    job.process = null
    if (job.status === 'cancelled') return
    if (job.terminationReason) throw new Error(job.terminationReason)
    if (scanCode !== 0) throw new Error(`RepoSec exited with code ${scanCode}. See the audit console for details.`)

    setStage(job, 'report')
    const resultPath = path.join(outputDir, 'findings.json')
    const rawResult = JSON.parse(await readFile(resultPath, 'utf8'))
    job.result = sanitizeDeep(rawResult)
    job.repoName = rawResult.repo || job.repoName
    job.status = 'completed'
    job.progress = 100
    job.finishedAt = new Date().toISOString()
    pushLog(job, 'system', 'Analysis complete. RepoSec artifacts are ready.')
  } catch (error) {
    if (job.status !== 'cancelled') {
      job.status = 'failed'
      job.error = job.terminationReason || error?.message || String(error)
      job.finishedAt = new Date().toISOString()
      pushLog(job, 'system', `ERROR: ${job.error}`)
    }
  } finally {
    clearTimeout(timeoutHandle)
    job.process = null
    if (job.cloneDir) await rm(job.cloneDir, { recursive: true, force: true }).catch(() => {})
    if (job.tempDir) await rm(job.tempDir, { recursive: true, force: true }).catch(() => {})
  }
}

function scheduleQueue() {
  while (activeScans < effectiveMaxConcurrent && pendingQueue.length > 0) {
    const id = pendingQueue.shift()
    const job = jobs.get(id)
    if (!job || job.status !== 'queued') continue

    activeScans += 1
    runAnalysis(job)
      .catch((error) => {
        job.status = 'failed'
        job.error = error?.message || String(error)
        job.finishedAt = new Date().toISOString()
        pushLog(job, 'system', `ERROR: ${job.error}`)
      })
      .finally(() => {
        activeScans = Math.max(0, activeScans - 1)
        scheduleQueue()
      })
  }
}

function enqueueJob(job) {
  if (pendingQueue.length >= MAX_QUEUED_SCANS) {
    const error = new Error(`Analysis queue is full (${MAX_QUEUED_SCANS} waiting). Try again after a running scan finishes.`)
    error.statusCode = 429
    throw error
  }
  pendingQueue.push(job.id)
  pushLog(job, 'system', `Queued for analysis. Server capacity: ${effectiveMaxConcurrent} concurrent scan(s).`)
  setImmediate(scheduleQueue)
}

async function healthPayload() {
  const now = Date.now()
  if (!healthCache || now - healthCacheAt > 60_000) {
    const engine = await resolveRepoSecBinary()
    const reposec = await binaryAvailable(engine.path)
    const probe = reposec ? await spawnProcess(engine.path, ['--help']).catch(() => ({ code: 1 })) : { code: 1 }
    const gitCheck = await spawnProcess('git', ['--version']).catch(() => ({ code: 1, stdout: '', stderr: '' }))
    healthCache = {
      ok: reposec && probe.code === 0 && gitCheck.code === 0,
      reposec: {
        path: engine.path,
        available: reposec && probe.code === 0,
        bundledFallback: engine.bundled,
        parallelSafe: engine.parallelSafe,
        compatibilityFallbackFrom: engine.compatibilityFallbackFrom || null,
      },
      git: { available: gitCheck.code === 0, version: stripAnsi(gitCheck.stdout).trim() },
      allowedHosts: [...ALLOWED_HOSTS],
      timeoutMinutes: Math.round(ANALYSIS_TIMEOUT_MS / 60000),
    }
    healthCacheAt = now
  }
  return { ...healthCache, scheduler: schedulerSnapshot() }
}

function artifactInfo(name) {
  const map = {
    'reposec_report.html': ['text/html; charset=utf-8', 'inline'],
    'findings.json': ['application/json; charset=utf-8', 'attachment'],
    'findings.sarif': ['application/sarif+json; charset=utf-8', 'attachment'],
    'structure.mmd': ['text/plain; charset=utf-8', 'attachment'],
  }
  return map[name] || null
}


function contentTypeFor(filePath) {
  const ext = path.extname(filePath).toLowerCase()
  return {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.ico': 'image/x-icon',
    '.woff': 'font/woff',
    '.woff2': 'font/woff2',
  }[ext] || 'application/octet-stream'
}

async function serveWebApp(url, res) {
  let requestPath
  try {
    requestPath = decodeURIComponent(url.pathname)
  } catch {
    return false
  }

  const relative = requestPath === '/' ? 'index.html' : requestPath.replace(/^\/+/, '')
  const candidate = path.resolve(DIST_DIR, relative)
  const distPrefix = `${path.resolve(DIST_DIR)}${path.sep}`
  let filePath = candidate

  if (candidate !== path.resolve(DIST_DIR, 'index.html') && !candidate.startsWith(distPrefix)) return false

  try {
    const info = await stat(filePath)
    if (!info.isFile()) throw new Error('not a file')
  } catch {
    // SPA fallback for client-side routes. Do not hide missing asset requests.
    if (path.extname(relative)) return false
    filePath = path.join(DIST_DIR, 'index.html')
  }

  try {
    const body = await readFile(filePath)
    res.writeHead(200, {
      'content-type': contentTypeFor(filePath),
      'content-length': body.length,
      'cache-control': path.basename(filePath) === 'index.html' ? 'no-cache' : 'public, max-age=3600',
      'x-content-type-options': 'nosniff',
    })
    res.end(body)
    return true
  } catch {
    return false
  }
}

async function cleanupExpiredJobs() {
  const cutoff = Date.now() - JOB_RETENTION_MS
  for (const [id, job] of jobs.entries()) {
    if (!['completed', 'failed', 'cancelled'].includes(job.status)) continue
    const finished = new Date(job.finishedAt || job.createdAt).getTime()
    if (!Number.isFinite(finished) || finished > cutoff) continue
    jobs.delete(id)
    if (job.jobDir) await rm(job.jobDir, { recursive: true, force: true }).catch(() => {})
  }
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`)

    if (req.method === 'GET' && url.pathname === '/api/health') {
      return json(res, 200, await healthPayload())
    }

    if (req.method === 'POST' && url.pathname === '/api/analyses') {
      await resolveRepoSecBinary()
      const body = await parseBody(req)
      const repoUrl = validateRepoUrl(body.repoUrl)
      const requested = body.phases && typeof body.phases === 'object' ? body.phases : {}
      const enabledPhases = ['osint', 'sca', 'sast', 'container', 'binary'].filter((phase) => requested[phase] !== false)
      if (enabledPhases.length === 0) throw new Error('Enable at least one RepoSec scan phase.')

      const parsed = new URL(repoUrl)
      const repoName = parsed.pathname.split('/').filter(Boolean).at(-1)?.replace(/\.git$/i, '') || 'repository'
      const id = `${Date.now().toString(36)}-${crypto.randomBytes(12).toString('hex')}`
      const job = {
        id,
        repoUrl,
        provider: providerFromUrl(repoUrl),
        repoName,
        enabledPhases,
        status: 'queued',
        stage: 'clone',
        progress: 0,
        createdAt: new Date().toISOString(),
        startedAt: null,
        finishedAt: null,
        logs: [],
        error: null,
        result: null,
        process: null,
        terminationReason: null,
      }
      jobs.set(id, job)
      try {
        enqueueJob(job)
      } catch (error) {
        jobs.delete(id)
        throw error
      }
      return json(res, 202, publicJob(job))
    }

    const jobMatch = url.pathname.match(/^\/api\/analyses\/([A-Za-z0-9-]+)$/)
    if (jobMatch && req.method === 'GET') {
      const job = jobs.get(jobMatch[1])
      if (!job) return json(res, 404, { error: 'Analysis job not found.' })
      return json(res, 200, publicJob(job))
    }

    if (jobMatch && req.method === 'DELETE') {
      const job = jobs.get(jobMatch[1])
      if (!job) return json(res, 404, { error: 'Analysis job not found.' })
      if (['completed', 'failed', 'cancelled'].includes(job.status)) return json(res, 200, publicJob(job))

      if (job.status === 'queued') {
        const index = pendingQueue.indexOf(job.id)
        if (index >= 0) pendingQueue.splice(index, 1)
        job.status = 'cancelled'
        job.finishedAt = new Date().toISOString()
        job.error = 'Analysis cancelled while waiting in queue.'
        pushLog(job, 'system', 'Queued analysis cancelled.')
        setImmediate(scheduleQueue)
      } else {
        pushLog(job, 'system', 'Cancellation requested. Stopping RepoSec and child scanners.')
        requestStop(job, 'Analysis cancelled by user.', 'cancelled')
      }
      return json(res, 200, publicJob(job))
    }

    const artifactMatch = url.pathname.match(/^\/api\/analyses\/([A-Za-z0-9-]+)\/artifacts\/([^/]+)$/)
    if (artifactMatch && req.method === 'GET') {
      const job = jobs.get(artifactMatch[1])
      const name = artifactMatch[2]
      const info = artifactInfo(name)
      if (!job || job.status !== 'completed' || !info) return json(res, 404, { error: 'Artifact not found.' })
      const filePath = path.join(job.outputDir, name)
      const body = await readFile(filePath)
      res.writeHead(200, {
        'content-type': info[0],
        'content-length': body.length,
        'content-disposition': `${info[1]}; filename="${name}"`,
        'x-content-type-options': 'nosniff',
        'cache-control': 'private, no-store',
      })
      return res.end(body)
    }

    if (req.method === 'GET' && !url.pathname.startsWith('/api/')) {
      if (await serveWebApp(url, res)) return
    }

    return json(res, 404, { error: 'Not found.' })
  } catch (error) {
    return json(res, error?.statusCode || 400, { error: error?.message || String(error) })
  }
})

await mkdir(RUN_ROOT, { recursive: true })
const startupEngine = await resolveRepoSecBinary()
const cleanupTimer = setInterval(() => cleanupExpiredJobs().catch(() => {}), 30 * 60 * 1000)
cleanupTimer.unref?.()

server.listen(PORT, HOST, () => {
  console.log(`Software Vetter RepoSec server listening on http://${HOST}:${PORT}`)
  console.log(`RepoSec engine: ${startupEngine.path}${startupEngine.bundled ? ' (bundled isolation-safe)' : ''}`)
  if (startupEngine.compatibilityFallbackFrom) {
    console.warn(`WARNING: ${startupEngine.compatibilityFallbackFrom} has the phase_osint return regression; using ${startupEngine.path} instead.`)
  }
  if (!startupEngine.parallelSafe && REQUESTED_MAX_CONCURRENT > 1) {
    console.warn('WARNING: custom/global RepoSec was not marked parallel-safe; concurrency has been reduced to 1.')
    console.warn('Set REPOSEC_PARALLEL_SAFE=1 only after that engine honors per-job REPOSEC_TMP_DIR/TMPDIR.')
  }
  console.log(`Analysis workspace: ${RUN_ROOT}`)
  console.log(`Scan scheduler: ${effectiveMaxConcurrent} concurrent, ${MAX_QUEUED_SCANS} queued max, ${Math.round(ANALYSIS_TIMEOUT_MS / 60000)} minute timeout`)
})
