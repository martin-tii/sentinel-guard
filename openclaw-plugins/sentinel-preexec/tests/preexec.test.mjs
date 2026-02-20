import test from "node:test";
import assert from "node:assert/strict";

import {
  buildOpaInput,
  buildDecisionCacheKey,
  inferDecisionFingerprint,
  inferToolHint,
  isProcessPollInvocation,
  normalizeKnownToolArgs,
  queryOpaDecision,
  readCachedDecision,
  resolveOpaConfig,
  resolveFallback,
  resolveDecisionCooldownMs,
  resolveRiskyTools,
  resolveTimeoutMs,
  storeCachedDecision,
  toToolSet,
} from "../index.js";

test("toToolSet normalizes and rejects empty arrays", () => {
  assert.equal(toToolSet(null), null);
  const result = toToolSet([" Exec ", "", "process"]);
  assert.deepEqual([...result], ["exec", "process"]);
});

test("resolveRiskyTools prefers plugin config over env", () => {
  process.env.SENTINEL_OPENCLAW_INTERCEPT_TOOLS = "write";
  const tools = resolveRiskyTools({ tools: ["exec", "process"] });
  assert.equal(tools.has("exec"), true);
  assert.equal(tools.has("process"), true);
  assert.equal(tools.has("write"), false);
});

test("resolveRiskyTools falls back to env when config not set", () => {
  process.env.SENTINEL_OPENCLAW_INTERCEPT_TOOLS = "write,edit";
  const tools = resolveRiskyTools({});
  assert.equal(tools.has("write"), true);
  assert.equal(tools.has("edit"), true);
});

test("resolveTimeoutMs honors config then env then default", () => {
  process.env.SENTINEL_OPENCLAW_INTERCEPT_TIMEOUT_SECONDS = "30";
  assert.equal(resolveTimeoutMs({ timeoutSeconds: 5 }), 5000);
  assert.equal(resolveTimeoutMs({}), 30000);
  delete process.env.SENTINEL_OPENCLAW_INTERCEPT_TIMEOUT_SECONDS;
  assert.equal(resolveTimeoutMs({}), 120000);
});

test("resolveFallback honors config and defaults to secure block", () => {
  process.env.SENTINEL_OPENCLAW_INTERCEPT_FALLBACK = "allow";
  assert.equal(resolveFallback({ fallback: "allow" }), "allow");
  assert.equal(resolveFallback({ fallback: "block" }), "block");
  delete process.env.SENTINEL_OPENCLAW_INTERCEPT_FALLBACK;
  assert.equal(resolveFallback({}), "block");
});

test("resolveDecisionCooldownMs honors config then env then default", () => {
  process.env.SENTINEL_OPENCLAW_INTERCEPT_DECISION_COOLDOWN_SECONDS = "9";
  assert.equal(resolveDecisionCooldownMs({ decisionCooldownSeconds: 2 }), 2000);
  assert.equal(resolveDecisionCooldownMs({}), 9000);
  delete process.env.SENTINEL_OPENCLAW_INTERCEPT_DECISION_COOLDOWN_SECONDS;
  assert.equal(resolveDecisionCooldownMs({}), 15000);
});

test("decision cache stores and expires by cooldown", () => {
  const cache = new Map();
  const now = 1000;
  storeCachedDecision(cache, "exec", "allow", now, 5000);
  assert.equal(readCachedDecision(cache, "exec", now + 1000), "allow");
  assert.equal(readCachedDecision(cache, "exec", now + 6000), null);
});

test("inferToolHint extracts executable from command-like params", () => {
  assert.equal(
    inferToolHint({ params: { command: "open -a Safari https://example.com" } }, "exec"),
    "Executable hint: open (app/browser launch) | Command: open -a Safari https://example.com",
  );
  assert.equal(
    inferToolHint({ params: { argv: ["/usr/bin/ssh", "host"] } }, "exec"),
    "Executable hint: ssh (remote shell access) | Argv: /usr/bin/ssh host",
  );
});

test("inferToolHint extracts file targets for write tools", () => {
  assert.equal(
    inferToolHint({ params: { path: "/etc/sshd_config" } }, "write"),
    "File target: /etc/sshd_config",
  );
});

test("inferToolHint falls back to invocation id", () => {
  assert.equal(
    inferToolHint({ toolCallId: "exec_1771217960664_6" }, "exec"),
    "Invocation ID: exec_1771217960664_6",
  );
});

test("normalizeKnownToolArgs rewrites web_search q to query", () => {
  const event = { toolName: "web_search", params: { q: "gyms in Abu Dhabi", page: 1 } };
  const changed = normalizeKnownToolArgs(event);
  assert.equal(changed, true);
  assert.equal(event.params.query, "gyms in Abu Dhabi");
  assert.equal("q" in event.params, false);
});

test("decision fingerprint isolates exec approvals by executable", () => {
  const safari = inferDecisionFingerprint(
    { params: { command: 'open -a Safari "https://example.com"' } },
    "exec",
  );
  const ssh = inferDecisionFingerprint({ params: { command: "ssh prod" } }, "exec");
  assert.notEqual(safari, ssh);
});

test("decision cache key scopes by session and operation", () => {
  const keyA = buildDecisionCacheKey(
    { params: { command: 'open -a Safari "https://example.com"' } },
    "exec",
    "agent:main:main",
  );
  const keyB = buildDecisionCacheKey(
    { params: { command: "ssh prod" } },
    "exec",
    "agent:main:main",
  );
  const keyC = buildDecisionCacheKey(
    { params: { command: "ssh prod" } },
    "exec",
    "agent:other:main",
  );
  assert.notEqual(keyA, keyB);
  assert.notEqual(keyB, keyC);
});

test("isProcessPollInvocation detects process poll calls", () => {
  assert.equal(
    isProcessPollInvocation({ toolName: "process", params: { action: "poll", session: "abc" } }),
    true,
  );
  assert.equal(
    isProcessPollInvocation({ toolName: "process", params: { command: "poll neat-seaslug" } }),
    true,
  );
  assert.equal(
    isProcessPollInvocation({ toolName: "process", params: { action: "list" } }),
    false,
  );
});

test("resolveOpaConfig provides secure defaults", () => {
  const cfg = resolveOpaConfig({});
  assert.equal(cfg.enabled, true);
  assert.equal(cfg.opaUrl, "http://127.0.0.1:8181");
  assert.equal(cfg.opaDecisionPath, "/v1/data/sentinel/authz/decision");
  assert.equal(cfg.opaTimeoutMs, 1500);
  assert.equal(cfg.opaFailMode, "block");
});

test("queryOpaDecision returns allow result for valid OPA payload", async () => {
  const cfg = resolveOpaConfig({ opaEnabled: true });
  const fakeFetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({ result: { allow: true, reason: "ok", tags: ["allow"] } }),
  });
  const result = await queryOpaDecision(cfg, { action: { type: "tool_call" } }, fakeFetch);
  assert.equal(result.status, "ok");
  assert.equal(result.allow, true);
  assert.equal(result.reason, "ok");
});

test("queryOpaDecision handles OPA errors", async () => {
  const cfg = resolveOpaConfig({ opaEnabled: true });
  const fakeFetch = async () => ({
    ok: false,
    status: 503,
    json: async () => ({}),
  });
  const result = await queryOpaDecision(cfg, { action: { type: "tool_call" } }, fakeFetch);
  assert.equal(result.status, "error");
});

test("buildOpaInput shapes canonical tool_call payload", () => {
  const event = { toolName: "exec", toolCallId: "abc", params: { command: "ls" } };
  const ctx = { sessionKey: "agent:main", agentId: "main", workspaceRoot: "/tmp/work" };
  const input = buildOpaInput(event, ctx, "exec");
  assert.equal(input.action.type, "tool_call");
  assert.equal(input.action.tool, "exec");
  assert.equal(input.actor.session, "agent:main");
  assert.equal(input.context.workspace_root, "/tmp/work");
});
