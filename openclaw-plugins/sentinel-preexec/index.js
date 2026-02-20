import readline from "node:readline";
import { spawn } from "node:child_process";

const DEFAULT_RISKY_TOOLS = ["exec", "process", "write", "edit", "apply_patch"];
const DEFAULT_TIMEOUT_SECONDS = 120;
const DEFAULT_DECISION_COOLDOWN_SECONDS = 15;
const DEFAULT_MAX_PROCESS_POLLS_PER_SESSION = 2;
const DEFAULT_OPA_URL = "http://127.0.0.1:8181";
const DEFAULT_OPA_DECISION_PATH = "/v1/data/sentinel/authz/decision";
const DEFAULT_OPA_TIMEOUT_MS = 1500;

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

export function resolveDecisionCooldownMs(pluginConfig) {
  const rawCfg = Number(pluginConfig?.decisionCooldownSeconds);
  if (Number.isFinite(rawCfg) && rawCfg >= 0) return Math.floor(rawCfg * 1000);
  const rawEnv = process.env.SENTINEL_OPENCLAW_INTERCEPT_DECISION_COOLDOWN_SECONDS;
  if (rawEnv == null || String(rawEnv).trim() === "") {
    return DEFAULT_DECISION_COOLDOWN_SECONDS * 1000;
  }
  const raw = Number(rawEnv);
  if (Number.isFinite(raw) && raw >= 0) return Math.floor(raw * 1000);
  return DEFAULT_DECISION_COOLDOWN_SECONDS * 1000;
}

export function resolveOpaConfig(pluginConfig) {
  const enabledRaw = pluginConfig?.opaEnabled;
  let enabled = true;
  if (typeof enabledRaw === "boolean") {
    enabled = enabledRaw;
  } else if (process.env.SENTINEL_OPA_ENABLED != null) {
    const envValue = String(process.env.SENTINEL_OPA_ENABLED).trim().toLowerCase();
    enabled = envValue === "1" || envValue === "true" || envValue === "yes" || envValue === "on";
  }

  const opaUrl = String(pluginConfig?.opaUrl || process.env.SENTINEL_OPA_URL || DEFAULT_OPA_URL).trim();
  const opaDecisionPath = String(
    pluginConfig?.opaDecisionPath || process.env.SENTINEL_OPA_DECISION_PATH || DEFAULT_OPA_DECISION_PATH,
  ).trim();

  const timeoutRaw = Number(pluginConfig?.opaTimeoutMs ?? process.env.SENTINEL_OPA_TIMEOUT_MS ?? DEFAULT_OPA_TIMEOUT_MS);
  const opaTimeoutMs = Number.isFinite(timeoutRaw) && timeoutRaw > 0 ? Math.floor(timeoutRaw) : DEFAULT_OPA_TIMEOUT_MS;

  const failModeRaw = String(
    pluginConfig?.opaFailMode || process.env.SENTINEL_OPENCLAW_OPA_FAIL_MODE || "block",
  )
    .trim()
    .toLowerCase();
  const opaFailMode = failModeRaw === "allow" ? "allow" : "block";

  return {
    enabled,
    opaUrl,
    opaDecisionPath,
    opaTimeoutMs,
    opaFailMode,
  };
}

export function readCachedDecision(cache, toolName, nowMs) {
  const entry = cache.get(toolName);
  if (!entry) return null;
  if (entry.expiresAt <= nowMs) {
    cache.delete(toolName);
    return null;
  }
  return entry.decision === "allow" || entry.decision === "block" ? entry.decision : null;
}

export function storeCachedDecision(cache, toolName, decision, nowMs, cooldownMs) {
  if (cooldownMs <= 0) return;
  if (decision !== "allow" && decision !== "block") return;
  cache.set(toolName, { decision, expiresAt: nowMs + cooldownMs });
}

function normalizeForKey(value, maxLen = 180) {
  return String(value || "")
    .trim()
    .replace(/\s+/g, " ")
    .slice(0, maxLen);
}

function firstToken(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  const token = raw.split(/\s+/)[0] || "";
  if (!token) return "";
  const parts = token.split(/[\\/]/);
  return parts[parts.length - 1] || token;
}

function intentForExecutable(exe) {
  const name = String(exe || "").trim().toLowerCase();
  if (!name) return "";
  const mapping = {
    ps: "process enumeration",
    top: "process monitoring",
    htop: "process monitoring",
    pgrep: "process lookup",
    kill: "process termination",
    pkill: "process termination",
    curl: "network fetch",
    wget: "network fetch",
    ssh: "remote shell access",
    scp: "remote file copy",
    rsync: "file sync/transfer",
    nc: "raw socket/network probing",
    nmap: "port scanning",
    python: "script execution",
    python3: "script execution",
    node: "script execution",
    bash: "shell script execution",
    sh: "shell script execution",
    zsh: "shell script execution",
    open: "app/browser launch",
  };
  return mapping[name] || "system command execution";
}

export function inferToolHint(event, toolName) {
  const params = event?.params && typeof event.params === "object" ? event.params : {};
  const callId = String(event?.toolCallId || event?.tool_call_id || "").trim();
  if (toolName === "exec" || toolName === "process") {
    const command = String(params.command || params.cmd || params.program || "").trim();
    if (command) {
      const exe = firstToken(command);
      if (exe) return `Executable hint: ${exe} (${intentForExecutable(exe)}) | Command: ${command.slice(0, 160)}`;
      return `Command: ${command.slice(0, 180)}`;
    }
    if (Array.isArray(params.argv) && params.argv.length > 0) {
      const exe = firstToken(params.argv[0]);
      if (exe) {
        const preview = params.argv.map((v) => String(v)).slice(0, 6).join(" ");
        return `Executable hint: ${exe} (${intentForExecutable(exe)}) | Argv: ${preview.slice(0, 160)}`;
      }
    }
  }
  if (toolName === "write" || toolName === "edit" || toolName === "apply_patch") {
    const path = String(params.path || params.file || params.target || "").trim();
    if (path) return `File target: ${path.slice(0, 180)}`;
  }
  if (callId) return `Invocation ID: ${callId}`;
  return "";
}

export function inferDecisionFingerprint(event, toolName) {
  const params = event?.params && typeof event.params === "object" ? event.params : {};
  if (toolName === "exec" || toolName === "process") {
    const command = normalizeForKey(params.command || params.cmd || params.program, 220);
    if (command) {
      const exe = firstToken(command).toLowerCase();
      return exe ? `exe:${exe}|cmd:${command}` : `cmd:${command}`;
    }
    if (Array.isArray(params.argv) && params.argv.length > 0) {
      const argv = params.argv.map((v) => String(v || "")).filter(Boolean);
      if (argv.length > 0) {
        const exe = firstToken(argv[0]).toLowerCase();
        const preview = normalizeForKey(argv.slice(0, 8).join(" "), 220);
        return exe ? `exe:${exe}|argv:${preview}` : `argv:${preview}`;
      }
    }
    return "generic";
  }
  if (toolName === "write" || toolName === "edit" || toolName === "apply_patch") {
    const target = normalizeForKey(params.path || params.file || params.target, 220);
    return target ? `path:${target}` : "generic";
  }
  if (toolName === "browser") {
    const action = normalizeForKey(params.action || params.op || "", 40) || "unknown";
    const targetUrl = normalizeForKey(params.targetUrl || params.url || "", 220);
    if (targetUrl) return `action:${action}|url:${targetUrl}`;
    return `action:${action}`;
  }
  return "generic";
}

export function buildDecisionCacheKey(event, toolName, sessionKey = "global") {
  const scope = normalizeForKey(sessionKey, 120) || "global";
  const fingerprint = inferDecisionFingerprint(event, toolName);
  return `${scope}|${toolName}|${fingerprint}`;
}

function resolveMaxProcessPolls(pluginConfig) {
  const rawCfg = Number(pluginConfig?.maxProcessPollsPerSession);
  if (Number.isFinite(rawCfg) && rawCfg >= 0) return Math.floor(rawCfg);
  const rawEnv = Number(process.env.SENTINEL_OPENCLAW_MAX_PROCESS_POLLS_PER_SESSION || "");
  if (Number.isFinite(rawEnv) && rawEnv >= 0) return Math.floor(rawEnv);
  return DEFAULT_MAX_PROCESS_POLLS_PER_SESSION;
}

export function isProcessPollInvocation(event) {
  const toolName = String(event?.toolName || "")
    .trim()
    .toLowerCase();
  if (toolName !== "process") return false;
  const params = event?.params && typeof event.params === "object" ? event.params : {};
  const action = normalizeForKey(params.action || params.op || params.command || "", 40).toLowerCase();
  if (action === "poll") return true;
  const command = normalizeForKey(params.command || params.cmd || "", 80).toLowerCase();
  if (command.startsWith("poll")) return true;
  return false;
}

export function normalizeKnownToolArgs(event) {
  const toolName = String(event?.toolName || "")
    .trim()
    .toLowerCase();
  if (toolName !== "web_search") return false;
  const params = event?.params;
  if (!params || typeof params !== "object" || Array.isArray(params)) return false;
  const query = String(params.query || "").trim();
  if (query) return false;
  const q = String(params.q || "").trim();
  if (!q) return false;
  event.params = { ...params, query: q };
  delete event.params.q;
  return true;
}

export function buildOpaInput(event, ctx, toolName) {
  const params = event?.params && typeof event.params === "object" ? event.params : {};
  const toolCallId = String(event?.toolCallId || event?.tool_call_id || "").trim();
  const sessionKey = String(ctx?.sessionKey || "global");
  return {
    actor: {
      type: "agent",
      id: String(ctx?.agentId || "openclaw-agent"),
      session: sessionKey,
    },
    runtime: {
      source: "openclaw-preexec",
      environment: String(process.env.SENTINEL_ENVIRONMENT || "development"),
      production_mode: String(process.env.SENTINEL_PRODUCTION || "").trim().toLowerCase() === "true",
    },
    action: {
      type: "tool_call",
      operation: "before_tool_call",
      target: toolName,
      tool: toolName,
      args: [],
      metadata: {
        toolCallId,
        params,
      },
    },
    context: {
      workspace_root: String(ctx?.workspaceRoot || process.cwd()),
      cwd: process.cwd(),
      network: {},
      request_id: toolCallId || `${Date.now()}`,
      timestamp: new Date().toISOString(),
    },
  };
}

export async function queryOpaDecision(opaConfig, inputPayload, fetchImpl = globalThis.fetch) {
  if (!opaConfig?.enabled) {
    return { status: "disabled" };
  }
  if (typeof fetchImpl !== "function") {
    return { status: "error", error: "fetch_unavailable" };
  }

  const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
  const timeout = setTimeout(() => {
    try {
      controller?.abort();
    } catch {}
  }, opaConfig.opaTimeoutMs);

  try {
    const base = String(opaConfig.opaUrl || "").replace(/\/$/, "");
    const path = String(opaConfig.opaDecisionPath || "");
    const endpoint = `${base}${path.startsWith("/") ? path : `/${path}`}`;
    const response = await fetchImpl(endpoint, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({ input: inputPayload }),
      signal: controller?.signal,
    });

    if (!response?.ok) {
      return { status: "error", error: `http_${response?.status || "unknown"}` };
    }
    const payload = await response.json();
    const result = payload?.result;
    if (!result || typeof result.allow !== "boolean") {
      return { status: "error", error: "invalid_response" };
    }
    const tags = Array.isArray(result.tags) ? result.tags.map((v) => String(v)) : [];
    return {
      status: "ok",
      allow: result.allow,
      reason: String(result.reason || ""),
      tags,
    };
  } catch (error) {
    return {
      status: "error",
      error: String(error?.message || error || "opa_error"),
    };
  } finally {
    clearTimeout(timeout);
  }
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

async function popupDecision(toolName, timeoutMs, hint = "") {
  const detail = hint ? `\n${hint}` : "";
  const msg = `Sentinel: allow OpenClaw tool '${toolName}'?${detail}`;
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

async function terminalDecision(toolName, timeoutMs, hint = "") {
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
    const detail = hint ? ` (${hint})` : "";
    rl.question(
      `[Sentinel] Allow tool '${toolName}'${detail}? Type 'allow' or 'block' [block]: `,
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

async function firstDecision(toolName, timeoutMs, hint = "") {
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
    popupDecision(toolName, timeoutMs, hint).then(onResult).catch(() => onResult(null));
    terminalDecision(toolName, timeoutMs, hint).then(onResult).catch(() => onResult(null));
    setTimeout(() => finish(null), timeoutMs + 500);
  });
}

export default function register(api) {
  const decisionCache = new Map();
  const processPollCounts = new Map();
  api.on("before_tool_call", async (event, ctx) => {
    const toolName = String(event?.toolName || "")
      .trim()
      .toLowerCase();
    if (!toolName) return {};

    if (normalizeKnownToolArgs(event)) {
      api.logger?.info?.("sentinel-preexec: normalized web_search args (q -> query)");
    }

    const riskyTools = resolveRiskyTools(api.pluginConfig || {});
    if (!riskyTools.has(toolName)) return {};

    const opaCfg = resolveOpaConfig(api.pluginConfig || {});
    const opaInput = buildOpaInput(event, ctx, toolName);
    const opaDecision = await queryOpaDecision(opaCfg, opaInput);
    if (opaDecision.status === "ok") {
      api.logger?.info?.(
        `source=openclaw-preexec opa_decision=${opaDecision.allow ? "allow" : "deny"} tool=${toolName} reason=${(opaDecision.reason || "").slice(0, 220)}`,
      );
      if (!opaDecision.allow) {
        const reason = opaDecision.reason || `OPA denied tool '${toolName}'`;
        return {
          block: true,
          blockReason: reason,
        };
      }
    } else if (opaDecision.status === "error") {
      api.logger?.warn?.(
        `source=openclaw-preexec opa_decision=error fail_mode=${opaCfg.opaFailMode} tool=${toolName} reason=${String(opaDecision.error || "").slice(0, 220)}`,
      );
      if (opaCfg.opaFailMode === "block") {
        return {
          block: true,
          blockReason: `Sentinel blocked tool '${toolName}' (OPA unavailable and fail_mode=block)`,
        };
      }
    }

    const sessionKey = String(ctx?.sessionKey || "global");
    if (isProcessPollInvocation(event)) {
      const maxPolls = resolveMaxProcessPolls(api.pluginConfig || {});
      const currentPolls = (processPollCounts.get(sessionKey) || 0) + 1;
      processPollCounts.set(sessionKey, currentPolls);
      if (maxPolls >= 0 && currentPolls > maxPolls) {
        return {
          block: true,
          blockReason:
            "Sentinel blocked repeated process polling. Summarize available results and return a final user response.",
        };
      }
    } else if (toolName !== "process") {
      processPollCounts.set(sessionKey, 0);
    }

    const cacheKey = buildDecisionCacheKey(event, toolName, sessionKey);
    const cooldownMs = resolveDecisionCooldownMs(api.pluginConfig || {});
    const nowMs = Date.now();
    const cachedDecision = readCachedDecision(decisionCache, cacheKey, nowMs);
    if (cachedDecision === "allow") {
      api.logger?.info?.(
        `sentinel-preexec: allow (cached) session=${sessionKey} tool=${toolName} key=${cacheKey.slice(0, 220)}`,
      );
      return {};
    }
    if (cachedDecision === "block") {
      api.logger?.warn?.(
        `sentinel-preexec: block (cached) session=${sessionKey} tool=${toolName} key=${cacheKey.slice(0, 220)}`,
      );
      return {
        block: true,
        blockReason: `Sentinel blocked tool '${toolName}' (recent operator decision cache)`,
      };
    }

    const timeoutMs = resolveTimeoutMs(api.pluginConfig || {});
    const fallback = resolveFallback(api.pluginConfig || {});
    const hint = inferToolHint(event, toolName);
    const userDecision = await firstDecision(toolName, timeoutMs, hint);
    const decision = userDecision || fallback;
    const path = userDecision ? "operator" : `fallback:${fallback}`;
    api.logger?.info?.(
      `sentinel-preexec: decision=${decision} path=${path} session=${sessionKey} tool=${toolName} hint=${(hint || "").slice(0, 220)}`,
    );
    storeCachedDecision(decisionCache, cacheKey, decision, nowMs, cooldownMs);
    if (decision === "allow") return {};
    const suffix = userDecision
      ? "operator denied"
      : `no approval response within ${Math.floor(timeoutMs / 1000)}s; fallback=${fallback}`;
    return {
      block: true,
      blockReason: `Sentinel blocked tool '${toolName}' before execution (${suffix})`,
    };
  });
}
