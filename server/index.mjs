import http from 'node:http'
import { spawn } from 'node:child_process'
import { access, mkdir, readFile, rm, stat } from 'node:fs/promises'
import { constants as fsConstants } from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import crypto from 'node:crypto'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const PROJECT_DIR = path.resolve(__dirname, '..')
const PORT = Number(process.env.API_PORT || 8787)
const CONFIGURED_REPOSEC_BIN = process.env.REPOSEC_BIN || ''
const SYSTEM_REPOSEC_BIN = '/usr/local/bin/reposec'
const BUNDLED_REPOSEC_BIN = path.join(PROJECT_DIR, 'tools', 'reposec-fixed.py')
const RUN_ROOT = path.resolve(process.env.REPOSEC_RUN_DIR || path.join(PROJECT_DIR, 'reposec-runs'))
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

  if (parsed.protocol !== 'https:') {
    throw new Error('Repository URL must use HTTPS.')
  }
  if (parsed.username || parsed.password) {
    throw new Error('Do not put credentials or access tokens in the repository URL.')
  }

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

function publicJob(job) {
  return {
    id: job.id,
    status: job.status,
    repoUrl: job.repoUrl,
    provider: job.provider,
    repoName: job.repoName,
    enginePath: job.enginePath || null,
    createdAt: job.createdAt,
    startedAt: job.startedAt,
    finishedAt: job.finishedAt,
    stage: job.stage,
    stageLabel: PHASE_LABELS[job.stage] || job.stage,
    progress: job.status === 'completed' ? 100 : job.progress,
    enabledPhases: job.enabledPhases,
    logs: job.logs,
    error: job.error,
    result: job.result,
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

async function resolveRepoSecBinary() {
  const candidates = CONFIGURED_REPOSEC_BIN
    ? [CONFIGURED_REPOSEC_BIN]
    : [SYSTEM_REPOSEC_BIN, BUNDLED_REPOSEC_BIN]

  for (const candidate of candidates) {
    if (!(await binaryAvailable(candidate))) continue
    const probe = await spawnProcess(candidate, ['--help']).catch(() => ({ code: 1 }))
    if (probe.code === 0) return candidate
  }
  return candidates[0]
}

async function runAnalysis(job) {
  const jobDir = path.join(RUN_ROOT, job.id)
  const cloneDir = path.join(jobDir, 'repository')
  const outputDir = path.join(jobDir, 'output')
  job.jobDir = jobDir
  job.cloneDir = cloneDir
  job.outputDir = outputDir

  try {
    job.status = 'cloning'
    job.startedAt = new Date().toISOString()
    setStage(job, 'clone')
    await mkdir(outputDir, { recursive: true })

    const reposecBin = await resolveRepoSecBinary()
    job.enginePath = reposecBin
    if (!(await binaryAvailable(reposecBin))) {
      throw new Error(`RepoSec executable was not found or is not executable at ${reposecBin}. Set REPOSEC_BIN if yours is elsewhere.`)
    }

    pushLog(job, 'system', `Cloning ${job.provider} repository ${job.repoUrl}`)
    const clone = spawn('git', ['clone', '--depth=1', '--no-tags', '--', job.repoUrl, cloneDir], {
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, GIT_TERMINAL_PROMPT: '0' },
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
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, PYTHONUNBUFFERED: '1' },
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
      job.error = error?.message || String(error)
      job.finishedAt = new Date().toISOString()
      pushLog(job, 'system', `ERROR: ${job.error}`)
    }
  } finally {
    job.process = null
    if (job.cloneDir) {
      await rm(job.cloneDir, { recursive: true, force: true }).catch(() => {})
    }
  }
}

async function healthPayload() {
  const reposecPath = await resolveRepoSecBinary()
  const reposec = await binaryAvailable(reposecPath)
  const probe = reposec ? await spawnProcess(reposecPath, ['--help']).catch(() => ({ code: 1 })) : { code: 1 }
  const gitCheck = await spawnProcess('git', ['--version']).catch(() => ({ code: 1, stdout: '', stderr: '' }))
  return {
    ok: reposec && probe.code === 0 && gitCheck.code === 0,
    reposec: { path: reposecPath, available: reposec && probe.code === 0, bundledFallback: reposecPath === BUNDLED_REPOSEC_BIN },
    git: { available: gitCheck.code === 0, version: stripAnsi(gitCheck.stdout).trim() },
    allowedHosts: [...ALLOWED_HOSTS],
  }
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

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`)

    if (req.method === 'GET' && url.pathname === '/api/health') {
      return json(res, 200, await healthPayload())
    }

    if (req.method === 'POST' && url.pathname === '/api/analyses') {
      const body = await parseBody(req)
      const repoUrl = validateRepoUrl(body.repoUrl)
      const requested = body.phases && typeof body.phases === 'object' ? body.phases : {}
      const enabledPhases = ['osint', 'sca', 'sast', 'container', 'binary'].filter((phase) => requested[phase] !== false)
      if (enabledPhases.length === 0) throw new Error('Enable at least one RepoSec scan phase.')

      const parsed = new URL(repoUrl)
      const repoName = parsed.pathname.split('/').filter(Boolean).at(-1)?.replace(/\.git$/i, '') || 'repository'
      const id = `${Date.now().toString(36)}-${crypto.randomBytes(4).toString('hex')}`
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
      }
      jobs.set(id, job)
      queueMicrotask(() => runAnalysis(job))
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
      job.status = 'cancelled'
      job.finishedAt = new Date().toISOString()
      job.error = 'Analysis cancelled by user.'
      if (job.process && !job.process.killed) job.process.kill('SIGTERM')
      pushLog(job, 'system', 'Analysis cancelled.')
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
      })
      return res.end(body)
    }

    return json(res, 404, { error: 'Not found.' })
  } catch (error) {
    return json(res, 400, { error: error?.message || String(error) })
  }
})

await mkdir(RUN_ROOT, { recursive: true })
server.listen(PORT, '127.0.0.1', () => {
  console.log(`Software Vetter RepoSec API listening on http://127.0.0.1:${PORT}`)
  console.log(`RepoSec preference: ${CONFIGURED_REPOSEC_BIN || SYSTEM_REPOSEC_BIN} (bundled fallback available)`)
})
