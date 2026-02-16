import test from "node:test";
import assert from "node:assert/strict";

import {
  readCachedDecision,
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
