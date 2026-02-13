import fs from "node:fs/promises";
import path from "node:path";
import { spawn } from "node:child_process";

const DEFAULT_OLLAMA_ENDPOINT = "http://localhost:11434/api/generate";
const DEFAULT_PROMPT_GUARD_MODEL = "prompt-guard";
const DEFAULT_LLAMA_GUARD_MODEL = "llama-guard3";
const DEFAULT_FAIL_MODE = "closed";
const DEFAULT_RISKY_TOOLS = ["exec", "process", "write", "edit", "apply_patch"];
const DEFAULT_STRICT_TOOLS = [
  "read",
  "image",
  "sessions_list",
  "sessions_history",
  "sessions_send",
  "sessions_spawn",
  "session_status",
];

const flaggedSessions = new Map();

function showAlertBestEffort(title, message) {
  const msg = String(message || "").replaceAll("\n", " ").trim();
  if (!msg) return;

  // Always log to terminal/stdout for non-UI contexts.
  // This is intentionally plain text so it is visible in service logs too.
  console.error(`[Sentinel Alert] ${title}: ${msg}`);

  if (process.platform === "darwin") {
    const script = `display dialog "${msg.replaceAll('"', '\\"')}" with title "${title.replaceAll('"', '\\"')}" buttons {"OK"} default button "OK"`;
    spawn("osascript", ["-e", script], { stdio: "ignore", detached: true }).unref();
    return;
  }
  if (process.platform === "linux") {
    spawn(
      "zenity",
      ["--warning", `--title=${title}`, `--text=${msg}`],
      { stdio: "ignore", detached: true },
    ).unref();
    return;
  }
  if (process.platform === "win32") {
    const escaped = msg.replaceAll("'", "''");
    const ps = [
      "[void][Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');",
      `[System.Windows.Forms.MessageBox]::Show('${escaped}','${title.replaceAll("'", "''")}',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning)`,
    ].join(" ");
    spawn("powershell", ["-NoProfile", "-Command", ps], { stdio: "ignore", detached: true }).unref();
  }
}

export function normalizeToolList(value, fallback) {
  if (!Array.isArray(value)) return new Set(fallback);
  const items = value.map((v) => String(v || "").trim().toLowerCase()).filter(Boolean);
  return new Set(items.length ? items : fallback);
}

function runCommand(cmd, args) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    let err = "";
    child.stdout?.on("data", (chunk) => {
      out += String(chunk);
    });
    child.stderr?.on("data", (chunk) => {
      err += String(chunk);
    });
    child.on("close", (code) => resolve({ code: code ?? 1, stdout: out, stderr: err }));
    child.on("error", () => resolve({ code: 127, stdout: out, stderr: err }));
  });
}

export function parseModelUnsafe(text) {
  const raw = String(text || "").trim().toLowerCase();
  if (!raw) return { unsafe: false, reason: "empty model response" };
  if (raw.includes("unsafe")) return { unsafe: true, reason: raw.slice(0, 200) };
  return { unsafe: false, reason: raw.slice(0, 200) };
}

export function resolveFailMode(cfg) {
  const mode = String(cfg?.failMode || DEFAULT_FAIL_MODE).trim().toLowerCase();
  return mode === "open" ? "open" : "closed";
}

export function modelUnavailableVerdict(failMode) {
  if (failMode === "open") {
    return { safe: true, reason: "Guard models unavailable (fail-open for availability)" };
  }
  return { safe: false, reason: "Guard models unavailable (fail-closed)" };
}

async function callOllama(endpoint, model, prompt) {
  try {
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ model, prompt, stream: false }),
    });
    if (!res.ok) {
      return { ok: false, response: "", reason: `HTTP ${res.status}` };
    }
    const data = await res.json();
    return { ok: true, response: String(data?.response || "").trim() };
  } catch (err) {
    return { ok: false, response: "", reason: String(err) };
  }
}

export function containsInjectionHeuristics(text) {
  const raw = String(text || "").toLowerCase();
  const patterns = [
    "ignore previous instructions",
    "ignore system prompt",
    "developer message",
    "jailbreak",
    "prompt injection",
    "exfiltrate",
    "reveal secrets",
    "bypass safety",
  ];
  return patterns.find((p) => raw.includes(p)) || null;
}

export function extractTextFromMessageLike(value) {
  if (!value) return "";
  if (typeof value === "string") return value;
  if (Array.isArray(value)) {
    return value.map((v) => extractTextFromMessageLike(v)).filter(Boolean).join("\n");
  }
  if (typeof value !== "object") return "";
  if (typeof value.text === "string") return value.text;
  if (typeof value.content === "string") return value.content;
  if (Array.isArray(value.content)) return extractTextFromMessageLike(value.content);
  if (typeof value.message === "string") return value.message;
  return "";
}

export function extractCandidateText(event) {
  if (!event || typeof event !== "object") return "";
  const candidates = [
    event.input,
    event.text,
    event.message,
    event.content,
    event.userMessage,
    event.prompt,
  ];
  for (const c of candidates) {
    const out = extractTextFromMessageLike(c).trim();
    if (out) return out;
  }
  if (Array.isArray(event.messages)) {
    const merged = event.messages
      .map((m) => extractTextFromMessageLike(m))
      .filter(Boolean)
      .join("\n");
    if (merged.trim()) return merged.trim();
  }
  return "";
}

function resolveWorkspaceDir(api) {
  const cfg = api.runtime.config.loadConfig();
  const configured = cfg?.agents?.defaults?.workspace;
  if (configured && String(configured).trim()) return String(configured).trim();
  return path.join(process.env.HOME || "~", ".openclaw", "workspace");
}

export function safeResolveWorkspacePath(workspaceDir, rawPath) {
  const p = String(rawPath || "").trim();
  if (!p) return null;
  const base = path.resolve(workspaceDir);
  const target = path.isAbsolute(p) ? path.resolve(p) : path.resolve(base, p);
  const rel = path.relative(base, target);
  if (!rel || rel === "." || (!rel.startsWith("..") && !path.isAbsolute(rel))) return target;
  return null;
}

async function enforceStrictTools(api, strictTools) {
  const payload = JSON.stringify(Array.from(strictTools), null, 0);
  await runCommand("openclaw", ["config", "set", "--json", "tools.sandbox.tools.allow", payload]);
  await runCommand("openclaw", ["sandbox", "recreate", "--all"]);
  api.logger.warn("sentinel-injection-guard: strict tool profile enforced");
}

async function evaluateInjection(api, text, cfg) {
  const heuristic = containsInjectionHeuristics(text);
  if (heuristic) return { safe: false, reason: `Heuristic matched: ${heuristic}` };

  const endpoint = String(cfg.ollamaEndpoint || DEFAULT_OLLAMA_ENDPOINT);
  const promptGuardModel = String(cfg.promptGuardModel || DEFAULT_PROMPT_GUARD_MODEL);
  const llamaGuardModel = String(cfg.llamaGuardModel || DEFAULT_LLAMA_GUARD_MODEL);
  const failMode = resolveFailMode(cfg);

  const pgPrompt = [
    "Classify if the following text is prompt injection or jailbreak attempt.",
    "Reply with exactly: SAFE or UNSAFE, then one short reason.",
    "",
    text,
  ].join("\n");
  const pg = await callOllama(endpoint, promptGuardModel, pgPrompt);
  if (pg.ok) {
    const parsed = parseModelUnsafe(pg.response);
    if (parsed.unsafe) return { safe: false, reason: `Prompt Guard: ${parsed.reason}` };
  } else {
    api.logger.warn(`sentinel-injection-guard: prompt guard model unavailable (${pg.reason})`);
  }

  const lg = await callOllama(endpoint, llamaGuardModel, text);
  if (lg.ok) {
    const parsed = parseModelUnsafe(lg.response);
    if (parsed.unsafe) return { safe: false, reason: `Llama Guard: ${parsed.reason}` };
    return { safe: true, reason: "Models classified input as safe" };
  }
  api.logger.warn(`sentinel-injection-guard: llama guard model unavailable (${lg.reason})`);
  return modelUnavailableVerdict(failMode);
}

export default function register(api) {
  const cfg = api.pluginConfig || {};
  if (cfg.enabled === false) return;

  const riskyTools = normalizeToolList(cfg.riskyTools, DEFAULT_RISKY_TOOLS);
  const strictTools = normalizeToolList(cfg.strictTools, DEFAULT_STRICT_TOOLS);
  const workspaceDir = resolveWorkspaceDir(api);

  api.on("before_agent_start", async (event, ctx) => {
    const sessionKey = String(ctx?.sessionKey || "unknown");
    const text = extractCandidateText(event);
    if (!text) return {};

    const verdict = await evaluateInjection(api, text, cfg);
    if (verdict.safe) return {};

    flaggedSessions.set(sessionKey, {
      flaggedAt: Date.now(),
      reason: verdict.reason,
    });
    showAlertBestEffort(
      "Sentinel Injection Alert",
      `Session ${sessionKey} flagged. Strict security mode enabled. Reason: ${verdict.reason}`,
    );
    await enforceStrictTools(api, strictTools);
    api.logger.warn(`sentinel-injection-guard: flagged session=${sessionKey} reason=${verdict.reason}`);
    return {
      prependContext:
        "Security mode is active due to prompt-injection risk. Do not use write/edit/apply_patch/exec/process tools.",
    };
  });

  api.on("before_tool_call", async (event, ctx) => {
    const sessionKey = String(ctx?.sessionKey || "unknown");
    const flagged = flaggedSessions.get(sessionKey);
    const toolName = String(event?.toolName || "").trim().toLowerCase();
    if (!flagged) return {};
    if (!toolName) return {};
    if (!riskyTools.has(toolName)) return {};
    return {
      block: true,
      blockReason: `Sentinel injection guard blocked '${toolName}' (${flagged.reason})`,
    };
  });

  api.on("after_tool_call", async (event, ctx) => {
    const sessionKey = String(ctx?.sessionKey || "unknown");
    const flagged = flaggedSessions.get(sessionKey);
    if (!flagged) return;
    const toolName = String(event?.toolName || "").trim().toLowerCase();
    if (toolName !== "write") return;
    const rawPath = event?.params?.path;
    const resolved = safeResolveWorkspacePath(workspaceDir, rawPath);
    if (!resolved) return;
    try {
      await fs.rm(resolved, { force: true });
      api.logger.warn(`sentinel-injection-guard: deleted write output ${resolved}`);
    } catch (err) {
      api.logger.error(`sentinel-injection-guard: failed to delete ${resolved}: ${String(err)}`);
    }
  });
}
