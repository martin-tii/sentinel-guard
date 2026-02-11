# Security Assessment: Sentinel Guard

## Scope
This assessment covers the current implementation in `src/`, container runtime files (`Dockerfile`, `docker-compose.yml`, `seccomp/`), and default policy behavior (`sentinel.yaml`).
Last updated: 2026-02-11.

## What It Is (Security-Wise)
- A Python runtime guardrail layer that intercepts file, command, and network operations using monkey patching.
- A policy enforcement engine based on allowlists and explicit deny paths.
- A human-approval escalation mechanism for blocked high-risk actions.
- An isolation-first execution path (`sentinel-isolate`) that runs agent commands inside a hardened Docker container.

## What It Is Not
- Not a hard boundary in in-process mode; code in the same interpreter can potentially tamper with protections.
- Not a full EDR/kernel-level security product.
- Not a complete outbound policy engine with deep URL/path/method semantics across all protocols.
- Not a guarantee against compromise unless container isolation mode is consistently enforced.

## Current Security Posture

### Strengths
- Defense-in-depth design: policy checks + optional AI risk scoring + human approval + container hardening.
- Command policy is shell-aware and blocks common chaining/injection operators in `shell=True` mode.
- Socket-level fail-safe exists for non-HTTP egress paths.
- Policy-file tampering bypass has been removed from runtime file interception.
- Disable switch now requires explicit dual-control flags (`SENTINEL_DISABLE` + `SENTINEL_ALLOW_DISABLE`).
- Runtime AI action adjudication now combines heuristics with model review for medium/high-risk actions.
- Host policy now supports strict exact-match mode and optional per-host scheme/port constraints.
- Runtime tamper detection verifies critical hook bindings and fails closed on drift.
- Startup attestation output is emitted at activation with policy/integrity state.
- High-assurance policy controls now support SHA256/HMAC verification and runtime immutability checks.
- Production mode enforces signed policy verification + immutable policy checks.
- Container runtime hardening includes:
  - read-only root filesystem
  - dropped Linux capabilities
  - `no-new-privileges`
  - seccomp allowlist profile (`SCMP_ACT_ERRNO` default + explicit allowed syscalls)
  - process/memory/CPU limits
  - strict mode with `network_mode: none` as the default demo posture

### Implemented High-Priority Features
- Seccomp moved from allow-by-default to allowlist profile (`SCMP_ACT_ERRNO` default + explicit allowed syscalls).
- Production guidance and demo path default to strict/no-network execution.
- Runtime tamper detection and drift fail-close enforcement are active.
- Immutable/signed policy options are implemented, with production-mode hard-fail requirements.
- Production isolated execution blocks networked mode unless an explicit exception flag is set.

### Remaining Risks and Gaps

#### P1: In-Process Tamper Surface
In compatibility mode, protection depends on monkey-patched runtime functions and process integrity.

Impact:
- Advanced adversarial code may bypass or restore original functions.

#### P2: Seccomp Workload Tuning Risk
The seccomp profile is now allowlist-based, but may still require per-workload tightening/validation.

Impact:
- Overly broad syscall allowance can increase attack surface; overly strict rules can break workloads.

#### P2: Policy Integrity Operationalization
Signed/immutable policy verification is enforced in production mode, but non-production environments may still run without integrity controls.

Impact:
- Inconsistent deployment configuration can reduce integrity guarantees across environments.

#### P2: Residual Evasion Risk in Judge Pipeline
Model adjudication now covers medium/high-risk actions, but low-risk actions still bypass model checks by threshold.

Impact:
- Carefully crafted low-signal malicious actions may evade deeper review.

## Threat Model Notes

### Better Covered
- Naive command injection patterns.
- Unauthorized file/network usage under strict policy.
- Opportunistic phishing-style outbound requests.
- Casual misuse by benign-but-buggy agent code.
- Runtime high-risk command decisions with explicit model adjudication.
- Over-broad host trust via implicit subdomain matching (now configurable and strict by default).
- Runtime hook drift detection and fail-closed tamper response.
- Policy integrity verification through hash/HMAC and immutable drift checks.

### Less Covered
- Same-process malicious code with deliberate anti-instrumentation behavior.
- Kernel/container escape class threats (partially mitigated only in isolated mode).
- Supply chain compromise in dependencies or base images.
- Covert exfiltration via approved channels.

## Hardening Priorities

### Immediate (High Priority)
1. Tune seccomp allowlist per target workload and verify with strict-mode integration tests.
2. Add policy for mandatory model adjudication on selected action classes (even below threshold).
3. Add richer outbound policy controls (scheme/path/method categories where feasible).
4. Add hardened deployment profile for CI/CD and production templates.

### Near Term
1. Expand runtime coverage tests for bypass attempts and race conditions.
2. Add attestable boot/runtime state export format for external verifiers.
3. Add explicit data exfiltration controls (destination class + payload sensitivity policies).
4. Add supply-chain hardening checks for base image and dependency provenance.

### Longer Term
1. Separate monitor and executor trust domains (out-of-process enforcement).
2. Add kernel-enforced policy options beyond in-process interception.
3. Add formal policy verification and drift alerting integration.

## Deployment Guidance
- Treat compatibility mode as guardrails, not containment.
- For untrusted agent workloads, run via `sentinel-isolate`.
- Keep `allowed_commands`, `allowed_paths`, and `allowed_hosts` minimal.
- Prefer deny-by-default network and open only specific destinations.
- Ensure audit logs are exported/collected outside the guarded process for integrity.

## Residual Risk Statement
Sentinel Guard provides meaningful preventive controls and strong operational safety improvements, especially when paired with container isolation. However, in-process mode alone should not be considered a complete security boundary against determined adversarial code.
