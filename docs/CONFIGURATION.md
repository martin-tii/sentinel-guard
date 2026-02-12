# Configuration

Policies are defined in `sentinel.yaml`.

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
    enabled: false
    model: "meta-llama/Prompt-Guard-86M"
    threshold: 0.8
    fail_open: false

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
```

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

## Notes

- In production mode, signed + immutable policy settings are required.
- In production isolated runs, networked mode is blocked unless `SENTINEL_ALLOW_NETWORK_IN_PRODUCTION=true` is set.
- In compatibility mode, DNS checks can still have TOCTOU/rebinding risk; use isolation mode for hard boundaries.
- Prompt Guard is optional and requires Hugging Face `transformers` plus an inference backend (for example, PyTorch) when enabled.
