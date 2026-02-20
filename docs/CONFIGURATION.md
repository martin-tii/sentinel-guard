# Configuration

Runtime configuration is defined in `sentinel.yaml`.

Authorization policy is defined in a single OPA Rego file:

- `policies/rego/sentinel/authz.rego` (source of truth)

When `opa.enabled: true`, Sentinel authorization decisions come from OPA.
`sentinel.yaml` policy-like fields are legacy compatibility fallback only (used when OPA is disabled).

## Minimal Policy Example

```yaml
allowed_paths:
  - "./workspace"
allowed_commands:
  - "echo"
  - "ls"
host_match_mode: "exact"   # exact | subdomain
allowed_hosts:
  - host: "api.openai.com"
    match: "exact"
    schemes: ["https"]
    ports: [443]

policy_integrity:
  tamper_detection: true

judge:
  enabled: true
  provider: "ollama"
  model: "llama-guard3"
  endpoint: "http://localhost:11434/api/generate"
  runtime_judge_threshold: 0.4
  risk_threshold: 0.7
  fail_open: false
  prompt_guard:
    enabled: true
    model: "meta-llama/Llama-Prompt-Guard-2-86M"
    threshold: 0.8
    fail_open: false
  injection_scan:
    enabled: true
    on_detection: "approval"   # block | approval | audit
    max_chars_per_source: 65536
    chunk_chars: 8192
    file_reads:
      enabled: true
      allowlist_paths: []
    network_responses:
      enabled: true
      allowlist_hosts: []
      text_content_types:
        - "text/*"
        - "application/json"
        - "application/*+json"
        - "application/xml"
        - "application/*+xml"
        - "application/javascript"
        - "application/x-www-form-urlencoded"

phishing:
  enabled: true
  blocked_tlds: [".xyz", ".top", ".zip"]

blocked_command_bases:
  - "python"
  - "bash"
  - "sh"

network_failsafe:
  socket_connect: true
  allow_private_network: false
  blocked_hosts: []
  blocked_ips: []
  allowed_ips: []

opa:
  enabled: true
  url: "http://127.0.0.1:8181"
  decision_path: "/v1/data/sentinel/authz/decision"
  timeout_ms: 1500
  fail_mode: "deny"   # deny | allow
```

## Common Policy Profiles

Use these as quick starting points, then expand with the full policy schema above.

### 1) Strict Local / No Network

- `allowed_commands`: minimal set only
- `allowed_hosts`: empty
- `network_failsafe.socket_connect: true`
- Run with `--network none` (or strict compose profile)

### 2) Networked Proxied (Gold standard (topology-enforced proxy routing))

- `allowed_hosts`: explicit allowlist only
- `network_failsafe.socket_connect: true`
- `network_failsafe.allow_private_network: false`
- `opa.enabled: true` with reachable `opa.url`
- Run via proxied compose topology (sidecar + internal network), not only bridge proxy env vars

### 3) Compatibility Mode with Approval Defaults

- `judge.injection_scan.enabled: true`
- `judge.injection_scan.on_detection: approval`
- `prompt_guard.enabled: true`
- `SENTINEL_APPROVAL_MODE=auto` (or explicit `tkinter`/`console`/`reject`)

## Environment Variables

### Safety Controls

```bash
# Dual-control emergency disable
export SENTINEL_DISABLE=true
export SENTINEL_ALLOW_DISABLE=true

# Approval behavior when no custom handler is registered:
# auto (default), tkinter, console, reject
export SENTINEL_APPROVAL_MODE=auto
```

### Policy Integrity

```bash
export SENTINEL_POLICY_CONTENT="$(cat sentinel.yaml)"
export SENTINEL_POLICY_SHA256="<sha256>"
export SENTINEL_POLICY_HMAC_KEY="<shared-secret>"
export SENTINEL_POLICY_HMAC_SHA256="<hmac-sha256>"
export SENTINEL_POLICY_IMMUTABLE=true
export SENTINEL_PRODUCTION=true
```

### Compatibility-Mode Runtime Tuning

```bash
export SENTINEL_TAMPER_CHECK_INTERVAL_MS=250
export SENTINEL_TAMPER_CHECK_SAMPLE_RATE=0.0
export SENTINEL_DNS_CACHE_TTL_SECONDS=2
export SENTINEL_DNS_RESOLVE_TIMEOUT_MS=1000
```

### Isolation-Mode Controls

```bash
export SENTINEL_SECCOMP_PROFILE=strict  # strict | datasci | custom
export SENTINEL_SECCOMP_MODE=enforce   # enforce | log | off
export SENTINEL_PROXY=http://proxy.internal:8080
export SENTINEL_NO_PROXY=localhost,127.0.0.1,.svc.cluster.local
export SENTINEL_ENFORCE_PROXY=true
```

### OPA Controls

```bash
export SENTINEL_OPA_ENABLED=true
export SENTINEL_OPA_URL=http://127.0.0.1:8181
export SENTINEL_OPA_DECISION_PATH=/v1/data/sentinel/authz/decision
export SENTINEL_OPA_TIMEOUT_MS=1500
export SENTINEL_OPA_FAIL_MODE=deny  # deny | allow
```

## Notes

- In production mode, signed + immutable policy settings are required.
- In production isolated runs, networked mode is blocked unless `SENTINEL_ALLOW_NETWORK_IN_PRODUCTION=true` is set.
- In compatibility mode, DNS checks can still have TOCTOU/rebinding risk; use isolation mode for hard boundaries.
- Prompt Guard is enabled by default and requires Hugging Face `transformers` plus an inference backend (for example, PyTorch).
- `judge.injection_scan` controls automatic prompt-injection scanning across built-in user input, text file reads, and text-like HTTP responses.
- With `on_detection: approval`, headless/no-handler environments fail safe to reject.

## Validation

Validation mapping is centralized in [VALIDATION_MATRIX.md](./VALIDATION_MATRIX.md).
Run `pytest -q` for full coverage.
