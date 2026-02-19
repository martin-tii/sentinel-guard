import readline from "node:readline";
import { spawn } from "node:child_process";
import { createHmac, randomBytes } from "node:crypto";

const DEFAULT_RISKY_TOOLS = ["exec", "process", "write", "edit", "apply_patch"];
const DEFAULT_TIMEOUT_SECONDS = 120;
const DEFAULT_DECISION_COOLDOWN_SECONDS = 15;
const DEFAULT_MAX_PROCESS_POLLS_PER_SESSION = 2;
const DEFAULT_TELEGRAM_POLL_INTERVAL_MS = 1500;

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

export function parseNumericIdSet(raw) {
  if (Array.isArray(raw)) {
    const values = raw.map((v) => Number(v)).filter((v) => Number.isFinite(v));
    return new Set(values);
  }
  const text = String(raw || "").trim();
  if (!text) return new Set();
  return new Set(
    text
      .split(",")
      .map((v) => Number(v.trim()))
      .filter((v) => Number.isFinite(v)),
  );
}

function resolveTelegramApprovalConfig(pluginConfig) {
  const cfg = pluginConfig?.telegramApproval || {};
  const enabledCfg = cfg.enabled;
  const enabledEnv = String(process.env.SENTINEL_OPENCLAW_TELEGRAM_APPROVAL_ENABLED || "")
    .trim()
    .toLowerCase();
  const enabled =
    enabledCfg === true ||
    enabledEnv === "1" ||
    enabledEnv === "true" ||
    enabledEnv === "yes" ||
    enabledEnv === "on";
  if (!enabled) return { enabled: false, ready: false };

  const botToken = String(
    cfg.botToken || process.env.SENTINEL_OPENCLAW_TELEGRAM_APPROVAL_BOT_TOKEN || "",
  ).trim();
  const chatId = String(cfg.chatId || process.env.SENTINEL_OPENCLAW_TELEGRAM_APPROVAL_CHAT_ID || "").trim();
  const signingSecret = String(
    cfg.signingSecret || process.env.SENTINEL_OPENCLAW_TELEGRAM_APPROVAL_SIGNING_SECRET || "",
  ).trim();
  const approverUserIds = parseNumericIdSet(
    cfg.approverUserIds || process.env.SENTINEL_OPENCLAW_TELEGRAM_APPROVAL_USER_IDS || "",
  );
  const apiBase = String(cfg.apiBase || process.env.SENTINEL_OPENCLAW_TELEGRAM_API_BASE || "https://api.telegram.org").trim();
  const pollIntervalMsRaw = Number(cfg.pollIntervalMs ?? process.env.SENTINEL_OPENCLAW_TELEGRAM_POLL_INTERVAL_MS ?? "");
  const pollIntervalMs =
    Number.isFinite(pollIntervalMsRaw) && pollIntervalMsRaw >= 250
      ? Math.floor(pollIntervalMsRaw)
      : DEFAULT_TELEGRAM_POLL_INTERVAL_MS;

  if (!botToken || !chatId || !signingSecret) {
    return {
      enabled: true,
      ready: false,
      reason:
        "telegram approval enabled but missing botToken/chatId/signingSecret (use dedicated approval bot token)",
    };
  }
  return {
    enabled: true,
    ready: true,
    botToken,
    chatId,
    signingSecret,
    approverUserIds,
    apiBase,
    pollIntervalMs,
  };
}

export function signTelegramApproval(approvalId, decision, signingSecret) {
  return createHmac("sha256", String(signingSecret))
    .update(`${String(approvalId)}|${String(decision)}`)
    .digest("hex")
    .slice(0, 12);
}

export function buildTelegramCallbackData(approvalId, decision, signingSecret) {
  const mode = decision === "allow" ? "a" : "b";
  const sig = signTelegramApproval(approvalId, decision, signingSecret);
  return `sg2|${mode}|${approvalId}|${sig}`;
}

export function parseTelegramCallbackData(raw) {
  const text = String(raw || "").trim();
  const m = text.match(/^sg2\|(a|b)\|([a-f0-9]{12})\|([a-f0-9]{12})$/);
  if (!m) return null;
  const mode = m[1] === "a" ? "allow" : "block";
  return { decision: mode, approvalId: m[2], sig: m[3] };
}

async function sleepMs(delayMs) {
  await new Promise((resolve) => setTimeout(resolve, delayMs));
}

async function telegramApiRequest(cfg, method, payload, timeoutMs) {
  const endpoint = `${cfg.apiBase.replace(/\/+$/, "")}/bot${cfg.botToken}/${method}`;
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), Math.max(500, timeoutMs));
  try {
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload || {}),
      signal: ctl.signal,
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok || body?.ok !== true) {
      const reason = String(body?.description || `HTTP ${res.status}`);
      return { ok: false, reason };
    }
    return { ok: true, result: body.result };
  } catch (err) {
    return { ok: false, reason: String(err) };
  } finally {
    clearTimeout(timer);
  }
}

const telegramOffsets = new Map();

function normalizeChatId(value) {
  return String(value == null ? "" : value).trim();
}

async function telegramDecision(toolName, timeoutMs, hint = "", sessionKey = "global", pluginConfig = {}, logger = null) {
  const cfg = resolveTelegramApprovalConfig(pluginConfig);
  if (!cfg.enabled) return null;
  if (!cfg.ready) {
    logger?.warn?.(`sentinel-preexec: ${cfg.reason}`);
    return null;
  }

  const approvalId = randomBytes(6).toString("hex");
  const allowData = buildTelegramCallbackData(approvalId, "allow", cfg.signingSecret);
  const blockData = buildTelegramCallbackData(approvalId, "block", cfg.signingSecret);
  const message = [
    `Sentinel approval required`,
    `Session: ${sessionKey}`,
    `Tool: ${toolName}`,
    hint ? `Hint: ${hint}` : "",
    `Approval ID: ${approvalId}`,
    `Timeout: ${Math.floor(timeoutMs / 1000)}s`,
  ]
    .filter(Boolean)
    .join("\n");

  const sendResult = await telegramApiRequest(
    cfg,
    "sendMessage",
    {
      chat_id: cfg.chatId,
      text: message,
      reply_markup: {
        inline_keyboard: [[
          { text: "Allow", callback_data: allowData },
          { text: "Block", callback_data: blockData },
        ]],
      },
      disable_web_page_preview: true,
    },
    Math.min(5000, timeoutMs),
  );
  if (!sendResult.ok) {
    logger?.warn?.(`sentinel-preexec: telegram approval send failed (${sendResult.reason})`);
    return null;
  }

  const startedAt = Date.now();
  let offset = telegramOffsets.get(cfg.botToken);
  while (Date.now() - startedAt < timeoutMs) {
    const remainingMs = timeoutMs - (Date.now() - startedAt);
    const pollSeconds = Math.max(1, Math.min(10, Math.floor(remainingMs / 1000)));
    const poll = await telegramApiRequest(
      cfg,
      "getUpdates",
      {
        offset,
        timeout: pollSeconds,
        allowed_updates: ["callback_query"],
      },
      remainingMs + 1500,
    );
    if (!poll.ok) {
      logger?.warn?.(`sentinel-preexec: telegram approval poll failed (${poll.reason})`);
      await sleepMs(cfg.pollIntervalMs);
      continue;
    }
    const updates = Array.isArray(poll.result) ? poll.result : [];
    for (const update of updates) {
      if (Number.isFinite(update?.update_id)) {
        offset = Number(update.update_id) + 1;
      }
      const cb = update?.callback_query;
      if (!cb) continue;
      const parsed = parseTelegramCallbackData(cb?.data);
      if (!parsed || parsed.approvalId !== approvalId) continue;
      const expectedSig = signTelegramApproval(parsed.approvalId, parsed.decision, cfg.signingSecret);
      if (parsed.sig !== expectedSig) {
        await telegramApiRequest(cfg, "answerCallbackQuery", {
          callback_query_id: cb.id,
          text: "Invalid signature",
          show_alert: true,
        }, 3000);
        continue;
      }
      const fromUserId = Number(cb?.from?.id);
      if (cfg.approverUserIds.size > 0 && !cfg.approverUserIds.has(fromUserId)) {
        await telegramApiRequest(cfg, "answerCallbackQuery", {
          callback_query_id: cb.id,
          text: "You are not an approved operator.",
          show_alert: true,
        }, 3000);
        continue;
      }
      const cbChatId = normalizeChatId(cb?.message?.chat?.id);
      if (cbChatId && normalizeChatId(cfg.chatId) !== cbChatId) {
        await telegramApiRequest(cfg, "answerCallbackQuery", {
          callback_query_id: cb.id,
          text: "Approval came from unexpected chat.",
          show_alert: true,
        }, 3000);
        continue;
      }
      await telegramApiRequest(cfg, "answerCallbackQuery", {
        callback_query_id: cb.id,
        text: parsed.decision === "allow" ? "Approved" : "Blocked",
      }, 3000);
      try {
        const chatIdForEdit = cb?.message?.chat?.id;
        const msgId = cb?.message?.message_id;
        if (chatIdForEdit != null && msgId != null) {
          await telegramApiRequest(
            cfg,
            "editMessageReplyMarkup",
            { chat_id: chatIdForEdit, message_id: msgId, reply_markup: { inline_keyboard: [] } },
            3000,
          );
        }
      } catch {}
      telegramOffsets.set(cfg.botToken, offset);
      return parsed.decision;
    }
    telegramOffsets.set(cfg.botToken, offset);
    await sleepMs(cfg.pollIntervalMs);
  }
  return null;
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

async function firstDecision(toolName, timeoutMs, hint = "", sessionKey = "global", pluginConfig = {}, logger = null) {
  return await new Promise((resolve) => {
    let pending = 3;
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
    telegramDecision(toolName, timeoutMs, hint, sessionKey, pluginConfig, logger)
      .then(onResult)
      .catch(() => onResult(null));
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
    const userDecision = await firstDecision(
      toolName,
      timeoutMs,
      hint,
      sessionKey,
      api.pluginConfig || {},
      api.logger,
    );
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
