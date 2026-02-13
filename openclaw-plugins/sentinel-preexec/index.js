import readline from "node:readline";
import { spawn } from "node:child_process";

const DEFAULT_RISKY_TOOLS = ["exec", "process", "write", "edit", "apply_patch"];
const DEFAULT_TIMEOUT_SECONDS = 120;

export function toToolSet(raw) {
  if (!Array.isArray(raw)) return null;
  const values = raw
    .map((v) => String(v || "").trim().toLowerCase())
    .filter(Boolean);
  if (values.length === 0) return null;
  return new Set(values);
}

export function resolveRiskyTools(pluginConfig) {
  const fromCfg = toToolSet(pluginConfig?.tools);
  if (fromCfg) return fromCfg;
  const raw = process.env.SENTINEL_OPENCLAW_INTERCEPT_TOOLS?.trim();
  if (!raw) return new Set(DEFAULT_RISKY_TOOLS);
  return new Set(
    raw
      .split(",")
      .map((v) => v.trim().toLowerCase())
      .filter(Boolean),
  );
}

export function resolveTimeoutMs(pluginConfig) {
  const rawCfg = Number(pluginConfig?.timeoutSeconds);
  if (Number.isFinite(rawCfg) && rawCfg > 0) return Math.floor(rawCfg * 1000);
  const raw = Number(process.env.SENTINEL_OPENCLAW_INTERCEPT_TIMEOUT_SECONDS || "");
  if (Number.isFinite(raw) && raw > 0) return Math.floor(raw * 1000);
  return DEFAULT_TIMEOUT_SECONDS * 1000;
}

export function resolveFallback(pluginConfig) {
  const cfg = String(pluginConfig?.fallback || "").trim().toLowerCase();
  if (cfg === "allow") return "allow";
  if (cfg === "block") return "block";
  const env = String(process.env.SENTINEL_OPENCLAW_INTERCEPT_FALLBACK || "block")
    .trim()
    .toLowerCase();
  return env === "allow" ? "allow" : "block";
}

function runCommand(cmd, args, timeoutMs) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    let err = "";
    let done = false;
    const finish = (result) => {
      if (done) return;
      done = true;
      resolve(result);
    };
    const timer = setTimeout(() => {
      try {
        child.kill("SIGTERM");
      } catch {}
      finish({ code: 124, stdout: out, stderr: err });
    }, timeoutMs);
    child.stdout?.on("data", (chunk) => {
      out += String(chunk);
    });
    child.stderr?.on("data", (chunk) => {
      err += String(chunk);
    });
    child.on("error", () => {
      clearTimeout(timer);
      finish({ code: 127, stdout: out, stderr: err });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      finish({ code: code ?? 1, stdout: out, stderr: err });
    });
  });
}

async function popupDecision(toolName, timeoutMs) {
  const msg = `Sentinel: allow OpenClaw tool '${toolName}'?`;
  if (process.platform === "darwin") {
    const script = `display dialog "${msg.replaceAll('"', '\\"')}" with title "Sentinel OpenClaw Guard" buttons {"Allow","Block"} default button "Block"`;
    const result = await runCommand("osascript", ["-e", script], timeoutMs);
    const output = `${result.stdout || ""}\n${result.stderr || ""}`;
    if (output.includes("Allow")) return "allow";
    if (output.includes("Block")) return "block";
    return null;
  }
  if (process.platform === "linux") {
    const result = await runCommand(
      "zenity",
      [
        "--question",
        "--title=Sentinel OpenClaw Guard",
        `--text=${msg}`,
        "--ok-label=Allow",
        "--cancel-label=Block",
      ],
      timeoutMs,
    );
    if (result.code === 0) return "allow";
    if (result.code !== 127) return "block";
    return null;
  }
  if (process.platform === "win32") {
    const escapedMsg = msg.replaceAll("'", "''");
    const ps = [
      "[void][Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');",
      `$r=[System.Windows.Forms.MessageBox]::Show('${escapedMsg}','Sentinel OpenClaw Guard',[System.Windows.Forms.MessageBoxButtons]::YesNo,[System.Windows.Forms.MessageBoxIcon]::Warning);`,
      "if ($r -eq [System.Windows.Forms.DialogResult]::Yes) { exit 0 } else { exit 1 }",
    ].join(" ");
    const result = await runCommand("powershell", ["-NoProfile", "-Command", ps], timeoutMs);
    return result.code === 0 ? "allow" : "block";
  }
  return null;
}

async function terminalDecision(toolName, timeoutMs) {
  if (!process.stdin.isTTY || !process.stdout.isTTY) return null;
  return await new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      try {
        rl.close();
      } catch {}
      resolve(value);
    };
    const timer = setTimeout(() => finish(null), timeoutMs);
    rl.question(
      `[Sentinel] Allow tool '${toolName}'? Type 'allow' or 'block' [block]: `,
      (answer) => {
        clearTimeout(timer);
        const raw = String(answer || "")
          .trim()
          .toLowerCase();
        if (raw === "allow" || raw === "a" || raw === "yes" || raw === "y") {
          finish("allow");
          return;
        }
        finish("block");
      },
    );
  });
}

async function firstDecision(toolName, timeoutMs) {
  return await new Promise((resolve) => {
    let pending = 2;
    let done = false;
    const finish = (value) => {
      if (done) return;
      done = true;
      resolve(value);
    };
    const onResult = (value) => {
      if (done) return;
      if (value === "allow" || value === "block") {
        finish(value);
        return;
      }
      pending -= 1;
      if (pending <= 0) finish(null);
    };
    popupDecision(toolName, timeoutMs).then(onResult).catch(() => onResult(null));
    terminalDecision(toolName, timeoutMs).then(onResult).catch(() => onResult(null));
    setTimeout(() => finish(null), timeoutMs + 500);
  });
}

export default function register(api) {
  api.on("before_tool_call", async (event) => {
    const toolName = String(event?.toolName || "")
      .trim()
      .toLowerCase();
    if (!toolName) return {};

    const riskyTools = resolveRiskyTools(api.pluginConfig || {});
    if (!riskyTools.has(toolName)) return {};

    const timeoutMs = resolveTimeoutMs(api.pluginConfig || {});
    const fallback = resolveFallback(api.pluginConfig || {});
    const decision = (await firstDecision(toolName, timeoutMs)) || fallback;
    if (decision === "allow") return {};
    return {
      block: true,
      blockReason: `Sentinel blocked tool '${toolName}' before execution`,
    };
  });
}
