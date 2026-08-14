import { spawn } from 'node:child_process'
import process from 'node:process'

const children = []

function start(name, command, args) {
  const child = spawn(command, args, {
    stdio: 'inherit',
    env: process.env,
  })
  children.push(child)
  child.on('exit', (code, signal) => {
    if (code && code !== 0) {
      console.error(`[${name}] exited with code ${code}${signal ? ` (${signal})` : ''}`)
      shutdown(code)
    }
  })
  return child
}

function shutdown(code = 0) {
  for (const child of children) {
    if (!child.killed) child.kill('SIGTERM')
  }
  setTimeout(() => process.exit(code), 150).unref()
}

process.on('SIGINT', () => shutdown(0))
process.on('SIGTERM', () => shutdown(0))

start('api', process.execPath, ['server/index.mjs'])
start('vite', process.execPath, ['node_modules/vite/bin/vite.js'])
