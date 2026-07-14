import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { StringDecoder } from "node:string_decoder";
import type { CodexProConfig } from "./config.js";
import type { Workspace } from "./guard.js";
import { CodexProError, PathGuard } from "./guard.js";
import { redactSensitiveText } from "./redact.js";

export interface BashResult {
  command: string;
  cwd: string;
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  durationMs: number;
  stdout: string;
  stderr: string;
  truncated: boolean;
  backend: string;
  spawnError?: string;
  bashSessionId?: string;
}

const SAFE_ALLOWED_PREFIXES = [
  "pwd", "ls", "find", "git status", "git diff", "git log", "git show", "git branch", "git rev-parse", "git ls-files",
  "npm test", "npm run test", "npm run typecheck", "npm run lint", "npm run build", "npm run check",
  "pnpm test", "pnpm run test", "pnpm run typecheck", "pnpm run lint", "pnpm run build", "pnpm run check",
  "yarn test", "yarn run test", "yarn run typecheck", "yarn run lint", "yarn run build", "yarn run check",
  "bun test", "bun run test", "bun run typecheck", "bun run lint", "bun run build", "bun run check",
  "pytest", "python -m pytest", "python3 -m pytest", "uv run pytest", "go test", "cargo test", "cargo check", "cargo clippy",
  "tsc", "npx tsc", "eslint", "npx eslint", "biome check", "npx biome check"
];

const SAFE_BLOCKED_PATTERNS = [
  /(^|\s)rm\s+/, /(^|\s)mv\s+/, /(^|\s)cp\s+/, /(^|\s)dd\s+/, /(^|\s)sudo\s+/, /(^|\s)chmod\s+/, /(^|\s)chown\s+/,
  /(^|\s)kill\s+/, /(^|\s)pkill\s+/, /(^|\s)curl\s+/, /(^|\s)wget\s+/, /(^|\s)ssh\s+/, /(^|\s)scp\s+/, /(^|\s)rsync\s+/,
  /(^|\s)docker\s+/, /(^|\s)podman\s+/, /(^|\s)git\s+push\b/, /(^|\s)git\s+reset\b/, /(^|\s)git\s+clean\b/,
  /(^|\s)git\s+checkout\b/, /(^|\s)git\s+switch\b/, /(^|\s)git\s+restore\b/, /(^|\s)(npm|pnpm|yarn)\s+publish\b/,
  /(^|\s)--no-index\b/, /(^|\s)--fix\b/, /(^|\s)(\/|~(?:\/|\s|$))/, /(^|\s)\.\.(?:\/|\s|$)/, /\$/,
  /(^|[\s:])(?:\.env(?:[./\s:]|$)|\.git(?:[\/\s:]|$)|node_modules(?:[\/\s:]|$)|\.ssh(?:[\/\s:]|$)|id_rsa(?:[.\s:]|$)|id_ed25519(?:[.\s:]|$)|[^\s:]*(?:\.pem|\.key)(?:[\s:]|$))/,
  /(^|\s)['"]?-exec(?:['"]|\s|$)/, /(^|\s)['"]?-execdir(?:['"]|\s|$)/, /(^|\s)['"]?-delete(?:['"]|\s|$)/,
  /(^|\s)['"]?-ok(?:['"]|\s|$)/, /(^|\s)['"]?-okdir(?:['"]|\s|$)/, /(^|\s)['"]?-fprint0?(?:['"]|\s|$)/,
  /(^|\s)['"]?-fprintf(?:['"]|\s|$)/, /(^|\s)['"]?-fls(?:['"]|\s|$)/, /(^|\s)['"]?--output(?:=|['"]|\s|$)/,
  /(^|\s)(sed|perl)\s+.*(^|\s)-i(\s|$)/, /(^|\s)(cat|grep|rg|head|tail|wc)\s+/, /[\r\n]/
];

function compact(command: string): string { return command.trim().replace(/\s+/g, " "); }
function startsWithAllowedPrefix(command: string): boolean {
  const normalized = compact(command);
  return isAllowedPackageScript(normalized) || SAFE_ALLOWED_PREFIXES.some((prefix) => normalized === prefix || normalized.startsWith(`${prefix} `));
}
function isAllowedPackageScript(command: string): boolean {
  return /^(?:npm|pnpm|yarn|bun)\s+(?:test|run\s+(?:test|typecheck|lint|build|check)(?::[A-Za-z0-9._-]+)*)(?:\s+--\s+[A-Za-z0-9._:= -]+)?$/.test(command);
}
function hasUnquotedShellOperator(command: string): boolean {
  let quote: "'" | '"' | undefined;
  let escaping = false;
  for (const char of command) {
    if (escaping) { escaping = false; continue; }
    if (char === "\\" && quote !== "'") { escaping = true; continue; }
    if (quote) { if (char === quote) quote = undefined; continue; }
    if (char === "'" || char === '"') { quote = char; continue; }
    if (";&|<>`".includes(char)) return true;
  }
  return false;
}
function assertSafeCommand(config: CodexProConfig, command: string): void {
  if (config.bashMode === "off") {
    throw new CodexProError("bash tool is disabled. Start with CODEXPRO_BASH_MODE=safe or CODEXPRO_BASH_MODE=full to enable it.");
  }
  if (config.bashMode === "full") return;
  const raw = command.trim();
  const normalized = compact(command);
  if (hasUnquotedShellOperator(raw)) {
    throw new CodexProError(`Command is blocked in CODEXPRO_BASH_MODE=safe: ${normalized}`);
  }
  for (const pattern of SAFE_BLOCKED_PATTERNS) if (pattern.test(raw) || pattern.test(normalized)) {
    throw new CodexProError(`Command is blocked in CODEXPRO_BASH_MODE=safe: ${normalized}`);
  }
  if (!startsWithAllowedPrefix(normalized)) {
    throw new CodexProError(
      `Command is not in the safe bash allowlist: ${normalized}\n` +
        "Allowed examples: ls, find, git status, git diff, npm test, npm run typecheck, npm run build:clients, pytest, go test, cargo test. Use read/search tools for file contents. " +
        "Use CODEXPRO_BASH_MODE=full for trusted local automation."
    );
  }
}
function assertBashSession(config: CodexProConfig, sessionId?: string): string | undefined {
  const requested = sessionId?.trim();
  if (!config.bashSessionId) {
    if (config.requireBashSession) throw new CodexProError("bash session guard is enabled but no server bash session id is configured.");
    return undefined;
  }
  if (!requested && config.requireBashSession) throw new CodexProError(`bash session id is required. Retry with session_id="${config.bashSessionId}".`);
  if (requested && requested !== config.bashSessionId) throw new CodexProError(`bash session id mismatch. This CodexPro server accepts session_id="${config.bashSessionId}".`);
  return config.bashSessionId;
}

export function executionBackend(): string { return process.platform === "win32" ? "native_windows_direct" : "unix_bash"; }
function makeEnv(config: CodexProConfig): NodeJS.ProcessEnv {
  if (config.inheritEnv) return { ...process.env, NO_COLOR: "1", CI: process.env.CI ?? "1" };
  if (process.platform === "win32") {
    const root = process.env.SystemRoot ?? "C:\\Windows";
    return {
      PATH: process.env.PATH ?? `${root}\\System32;${root}`,
      PATHEXT: process.env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD",
      SystemRoot: root, WINDIR: process.env.WINDIR ?? root,
      ComSpec: process.env.ComSpec ?? `${root}\\System32\\cmd.exe`,
      TEMP: process.env.TEMP ?? os.tmpdir(), TMP: process.env.TMP ?? os.tmpdir(),
      USERPROFILE: process.env.USERPROFILE ?? os.homedir(), HOME: process.env.USERPROFILE ?? os.homedir(), PYTHONUTF8: "1",
      TERM: "dumb", NO_COLOR: "1", CI: "1"
    };
  }
  return { PATH: process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin", HOME: process.env.HOME ?? "", USER: process.env.USER ?? "", SHELL: process.env.SHELL ?? "/bin/bash", TMPDIR: process.env.TMPDIR ?? "/tmp", TERM: "dumb", NO_COLOR: "1", CI: "1" };
}
function parseCommand(command: string): string[] {
  const args: string[] = [];
  let current = "";
  let quote: "'" | '"' | undefined;
  const input = command.trim();
  for (let index = 0; index < input.length; index += 1) {
    const char = input[index];
    if (quote === "'") {
      if (char === quote) quote = undefined;
      else current += char;
      continue;
    }
    if (quote === '"') {
      if (char === quote) {
        quote = undefined;
      } else if (char === "\\" && (input[index + 1] === '"' || input[index + 1] === "\\")) {
        current += input[index + 1];
        index += 1;
      } else {
        current += char;
      }
      continue;
    }
    if (char === "'" || char === '"') {
      quote = char;
    } else if (/\s/.test(char)) {
      if (current) {
        args.push(current);
        current = "";
      }
    } else {
      current += char;
    }
  }
  if (quote) throw new CodexProError("Command contains an unterminated quote.");
  if (current) args.push(current);
  if (!args.length) throw new CodexProError("command is required.");
  return args;
}

function windowsShellCommandAllowed(command: string): boolean {
  const normalized = compact(command);
  if (isAllowedPackageScript(normalized)) return true;
  return /^(?:npx\s+(?:tsc|eslint|biome\s+check))(?:\s+[A-Za-z0-9._:=\\/ -]+)*$/.test(normalized);
}
function resolveExecutable(command: string, env: NodeJS.ProcessEnv): string {
  if (path.isAbsolute(command) || command.includes(path.sep) || (process.platform === "win32" && command.includes("/"))) {
    if (fs.existsSync(command)) return command;
    throw new CodexProError(`process_spawn_failed: executable not found: ${path.basename(command)}`);
  }
  const extensions = process.platform === "win32" ? (env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD").split(";") : [""];
  for (const entry of (env.PATH ?? "").split(path.delimiter).filter(Boolean)) for (const extension of extensions) {
    const candidate = path.join(entry, process.platform === "win32" && !path.extname(command) ? `${command}${extension.toLowerCase()}` : command);
    if (fs.existsSync(candidate)) return candidate;
  }
  throw new CodexProError(`process_spawn_failed: executable not found: ${command}`);
}
function terminateProcessTree(child: ReturnType<typeof spawn>): void {
  if (!child.pid) return;
  if (process.platform === "win32") { const killer = spawn("taskkill.exe", ["/PID", String(child.pid), "/T", "/F"], { windowsHide: true, stdio: "ignore" }); killer.unref(); }
  else { try { process.kill(-child.pid, "SIGTERM"); } catch { child.kill("SIGTERM"); } setTimeout(() => { try { process.kill(-child.pid!, "SIGKILL"); } catch {} }, 1_500).unref(); }
}
function trimOutput(value: string, maxBytes: number): { value: string; truncated: boolean } {
  const buffer = Buffer.from(value, "utf8"); if (buffer.byteLength <= maxBytes) return { value, truncated: false };
  return { value: `${buffer.subarray(0, maxBytes).toString("utf8")}\n...[output truncated to ${maxBytes} bytes]`, truncated: true };
}

export async function runBash(config: CodexProConfig, guard: PathGuard, workspace: Workspace, command: string, options: { cwd?: string; timeoutMs?: number; sessionId?: string } = {}): Promise<BashResult> {
  if (!command?.trim()) throw new CodexProError("command is required.");
  const bashSessionId = assertBashSession(config, options.sessionId);
  assertSafeCommand(config, command);
  const cwd = guard.resolve(workspace, options.cwd ?? ".").absPath;
  const timeoutMs = Math.max(1_000, Math.min(options.timeoutMs ?? 30_000, 180_000));
  const start = Date.now();
  const backend = executionBackend();
  const env = makeEnv(config);

  if (process.platform === "win32" && compact(command).toLowerCase() === "pwd") {
    return {
      command,
      cwd: path.relative(workspace.root, cwd) || ".",
      exitCode: 0,
      signal: null,
      durationMs: Date.now() - start,
      stdout: `${cwd}\n`,
      stderr: "",
      truncated: false,
      backend,
      ...(bashSessionId ? { bashSessionId } : {})
    };
  }

  let executable: string;
  let childArgs: string[];
  let shell: string | false = false;
  if (process.platform === "win32" && config.bashMode === "full") {
    executable = command;
    childArgs = [];
    shell = env.ComSpec ?? "cmd.exe";
  } else if (process.platform === "win32") {
    const argv = parseCommand(command);
    const resolvedExecutable = resolveExecutable(argv[0], env);
    if (/\.(?:cmd|bat)$/i.test(resolvedExecutable)) {
      if (!windowsShellCommandAllowed(command)) {
        throw new CodexProError(
          "Windows command shims are allowed in safe mode only for validated package-manager verification commands."
        );
      }
      executable = command;
      childArgs = [];
      shell = env.ComSpec ?? "cmd.exe";
    } else {
      executable = resolvedExecutable;
      childArgs = argv.slice(1);
    }
  } else {
    executable = fs.existsSync("/bin/bash") ? "/bin/bash" : "bash";
    childArgs = ["-lc", command];
  }

  return new Promise((resolve) => {
    const child = spawn(executable, childArgs, {
      cwd,
      env,
      shell,
      windowsHide: true,
      detached: process.platform !== "win32",
      stdio: ["ignore", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    let killedByTimeout = false;
    let outputLimitReached = false;
    let settled = false;
    const stdoutDecoder = new StringDecoder("utf8");
    const stderrDecoder = new StringDecoder("utf8");
    const timer = setTimeout(() => {
      killedByTimeout = true;
      terminateProcessTree(child);
    }, timeoutMs);
    timer.unref();
    child.stdout!.on("data", (chunk) => {
      stdout += stdoutDecoder.write(chunk);
      if (Buffer.byteLength(stdout, "utf8") > config.maxOutputBytes * 2 && !outputLimitReached) {
        outputLimitReached = true;
        terminateProcessTree(child);
      }
    });
    child.stderr!.on("data", (chunk) => {
      stderr += stderrDecoder.write(chunk);
      if (Buffer.byteLength(stderr, "utf8") > config.maxOutputBytes * 2 && !outputLimitReached) {
        outputLimitReached = true;
        terminateProcessTree(child);
      }
    });
    child.once("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const message = error instanceof Error ? error.message : String(error);
      resolve({
        command,
        cwd: path.relative(workspace.root, cwd) || ".",
        exitCode: null,
        signal: null,
        durationMs: Date.now() - start,
        stdout: redactSensitiveText(stdout),
        stderr: redactSensitiveText(`${stderr}\n[codexpro] process_spawn_failed: ${message}`),
        truncated: false,
        backend,
        spawnError: message,
        ...(bashSessionId ? { bashSessionId } : {})
      });
    });
    child.once("close", (exitCode, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      stdout += stdoutDecoder.end();
      stderr += stderrDecoder.end();
      if (killedByTimeout) stderr += `\n[codexpro] Command timed out after ${timeoutMs} ms.`;
      if (outputLimitReached) stderr += "\n[codexpro] Output limit reached; process tree terminated.";
      const out = trimOutput(redactSensitiveText(stdout), config.maxOutputBytes);
      const err = trimOutput(redactSensitiveText(stderr), config.maxOutputBytes);
      resolve({
        command,
        cwd: path.relative(workspace.root, cwd) || ".",
        exitCode,
        signal,
        durationMs: Date.now() - start,
        stdout: out.value,
        stderr: err.value,
        truncated: out.truncated || err.truncated,
        backend,
        ...(bashSessionId ? { bashSessionId } : {})
      });
    });
  });
}
