import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { assertCodexProReleaseEnvironment } from "./release-guard.mjs";

const npmCli = process.env.npm_execpath ?? join(dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js");
const npmCommand = process.platform === "win32" ? process.execPath : "npm";
const npmArgs = (args) => process.platform === "win32" ? [npmCli, ...args] : args;

function runNpm(args, root) {
  const result = spawnSync(npmCommand, npmArgs(args), {
    cwd: root,
    stdio: "inherit",
    env: { ...process.env, INIT_CWD: root }
  });
  if (result.error) throw new Error(`npm ${args[0]} could not start: ${result.error.message}`);
  if (result.status !== 0) process.exit(result.status ?? 1);
}

try {
  const release = assertCodexProReleaseEnvironment();
  const publishArgs = process.argv.slice(2);
  if (publishArgs.some((arg) => arg === "--ignore-scripts" || arg.startsWith("--ignore-scripts="))) {
    throw new Error("--ignore-scripts is not allowed for CodexPro releases.");
  }

  runNpm(["run", "release:check"], release.root);
  runNpm(["publish", "--tag", "latest", ...publishArgs], release.root);
} catch (error) {
  console.error(`[release publish] ${error.message}`);
  process.exitCode = 1;
}
