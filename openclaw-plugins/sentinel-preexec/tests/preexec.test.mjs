import test from "node:test";
import assert from "node:assert/strict";

import {
  buildDecisionCacheKey,
  buildTelegramCallbackData,
  inferDecisionFingerprint,
  inferToolHint,
  isProcessPollInvocation,
  normalizeKnownToolArgs,
  parseNumericIdSet,
  parseTelegramCallbackData,
  readCachedDecision,
  resolveFallback,
  resolveDecisionCooldownMs,
  resolveRiskyTools,
  resolveTimeoutMs,
  signTelegramApproval,
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

test("parseNumericIdSet accepts arrays and csv", () => {
  assert.deepEqual([...parseNumericIdSet([123, "456", "x"])], [123, 456]);
  assert.deepEqual([...parseNumericIdSet("111, 222, nope")], [111, 222]);
});

test("telegram callback data is signed and parseable", () => {
  const token = buildTelegramCallbackData("a1b2c3d4e5f6", "allow", "secret-key");
  const parsed = parseTelegramCallbackData(token);
  assert.equal(parsed?.approvalId, "a1b2c3d4e5f6");
  assert.equal(parsed?.decision, "allow");
  const expected = signTelegramApproval("a1b2c3d4e5f6", "allow", "secret-key");
  assert.equal(parsed?.sig, expected);
});

test("telegram callback supports block decision encoding", () => {
  const token = buildTelegramCallbackData("001122334455", "block", "secret-key");
  const parsed = parseTelegramCallbackData(token);
  assert.equal(parsed?.approvalId, "001122334455");
  assert.equal(parsed?.decision, "block");
});

test("telegram callback parser rejects malformed payloads", () => {
  assert.equal(parseTelegramCallbackData(""), null);
  assert.equal(parseTelegramCallbackData("sg2|x|bad|bad"), null);
  assert.equal(parseTelegramCallbackData("sg2|a|short|123456789012"), null);
  assert.equal(parseTelegramCallbackData("legacy|a|a1b2c3d4e5f6|deadbeefcafe"), null);
});

test("telegram callback signatures are secret-bound", () => {
  const sigA = signTelegramApproval("a1b2c3d4e5f6", "allow", "secret-a");
  const sigB = signTelegramApproval("a1b2c3d4e5f6", "allow", "secret-b");
  assert.notEqual(sigA, sigB);
});
