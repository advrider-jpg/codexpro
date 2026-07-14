import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'codexpro-lifecycle-'));

function availablePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      server.close(() => resolve(address.port));
    });
  });
}

async function waitFor(predicate, timeoutMs, label) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`Timed out waiting for ${label}.`);
}

function directChildPids(parentPid) {
  const result = process.platform === 'win32'
    ? spawnSync('powershell.exe', [
        '-NoProfile',
        '-Command',
        `Get-CimInstance Win32_Process -Filter \"ParentProcessId = ${parentPid}\" | Select-Object -ExpandProperty ProcessId`
      ], { encoding: 'utf8' })
    : spawnSync('ps', ['-o', 'pid=', '--ppid', String(parentPid)], { encoding: 'utf8' });
  if (result.status !== 0) {
    throw new Error(`Could not inspect the launcher process tree: ${result.stderr || result.stdout || `exit ${result.status}`}`);
  }
  return result.stdout.trim().split(/\s+/).filter(Boolean).map(Number);
}

function killPid(pid, tree = false) {
  if (process.platform === 'win32') {
    const args = ['/PID', String(pid)];
    if (tree) args.push('/T');
    args.push('/F');
    return spawnSync('taskkill.exe', args, { encoding: 'utf8', stdio: tree ? 'ignore' : 'pipe' });
  }
  try {
    process.kill(pid, 'SIGKILL');
    return { status: 0, stdout: '', stderr: '' };
  } catch (error) {
    return { status: 1, stdout: '', stderr: error instanceof Error ? error.message : String(error) };
  }
}

let launcher;
try {
  const port = await availablePort();
  launcher = spawn(process.execPath, [
    'scripts/codexpro.mjs',
    'start',
    '--root', workspaceRoot,
    '--tunnel', 'none',
    '--port', String(port),
    '--no-copy-url'
  ], {
    cwd: projectRoot,
    env: { ...process.env, NO_COLOR: '1' },
    stdio: ['pipe', 'pipe', 'pipe']
  });

  let output = '';
  launcher.stdout.on('data', (chunk) => { output += String(chunk); });
  launcher.stderr.on('data', (chunk) => { output += String(chunk); });
  await waitFor(() => output.includes('Local MCP ready'), 20_000, 'local MCP readiness');

  const pids = directChildPids(launcher.pid);
  if (pids.length !== 1) throw new Error(`Expected one local MCP child, found ${JSON.stringify(pids)}.`);
  const killed = killPid(pids[0]);
  if (killed.status !== 0) {
    throw new Error(`Could not fault-inject the local MCP child: ${killed.stderr || killed.stdout || `exit ${killed.status}`}`);
  }

  const exit = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Launcher did not fail closed after local MCP child death.')), 10_000);
    launcher.once('exit', (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal });
    });
  });
  if (exit.code !== 1) throw new Error(`Expected launcher exit 1, got ${JSON.stringify(exit)}.`);
  if (!output.includes('local MCP server exited unexpectedly')) {
    throw new Error(`Launcher omitted the failure diagnostic. Output:\n${output}`);
  }

  const portOpen = await new Promise((resolve) => {
    const socket = net.connect({ host: '127.0.0.1', port });
    socket.once('connect', () => { socket.destroy(); resolve(true); });
    socket.once('error', () => resolve(false));
  });
  if (portOpen) throw new Error(`Port ${port} remained open after launcher failure.`);
  console.log('✓ lifecycle smoke passed');
} finally {
  if (launcher && launcher.exitCode === null && launcher.signalCode === null) killPid(launcher.pid, true);
  fs.rmSync(workspaceRoot, { recursive: true, force: true });
}
