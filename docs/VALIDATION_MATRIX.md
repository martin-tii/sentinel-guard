# Validation Matrix

Central test-to-claim map for Sentinel docs.  
Run the full suite with:

```bash
cd sentinel-guard
pytest -q
```

## Core Runtime and Isolation

- Isolation command construction, hardening flags, proxy/seccomp wiring:
  - `tests/test_isolation.py::IsolationCommandBuildTests`
- Runtime tamper checks, policy integrity, attestation scheduling:
  - `tests/test_integrity.py::RuntimeTamperDetectionTests`
  - `tests/test_integrity.py::PolicyIntegrityTests`
  - `tests/test_integrity.py::IntegritySchedulingAndAttestationTests`
- Production integrity/network controls:
  - `tests/test_production_controls.py::ProductionPolicyIntegrityTests`
  - `tests/test_production_controls.py::ProductionIsolationNetworkTests`
- Entry-point workspace/policy bootstrap:
  - `tests/test_entrypoint_script.py::EntrypointScriptTests`

## Policy and Decision Layers

- Network policy host/scheme/port matching:
  - `tests/test_network_policy.py::NetworkPolicyTests`
- AI Judge runtime adjudication:
  - `tests/test_judge.py::AIJudgeRuntimeTests`
- Prompt Guard detector behavior:
  - `tests/test_judge.py::PromptGuardDetectorTests`
- Injection scan coverage (input/file/network):
  - `tests/test_injection_scan.py::InjectionScanTests`
- Dual-control safety disable flow:
  - `tests/test_security_controls.py::SecurityControlTests`
- Approval routing defaults and fallback modes:
  - `tests/test_approval.py::ApprovalDefaultModeTests`

## Setup and Operational Flows

- Demo/setup command-path behavior:
  - `tests/test_run_demo_script.py::RunDemoScriptTests`
- OpenClaw isolation wrapper behavior:
  - `tests/test_openclaw_isolation.py::OpenClawIsolationTests`
- OpenClaw installer + hardening config application:
  - `tests/test_install_openclaw_with_sentinel.py::InstallOpenClawWithSentinelTests`
  - `tests/test_openclaw_sandbox_configure.py::OpenClawSandboxConfigureTests`
- OpenClaw popup guard behavior:
  - `tests/test_openclaw_popup_guard.py::OpenClawPopupGuardTests`
- OpenClaw pre-exec plugin behavior:
  - `openclaw-plugins/sentinel-preexec/tests/preexec.test.mjs`
- OpenClaw injection-guard plugin behavior:
  - `openclaw-plugins/sentinel-injection-guard/tests/injection-guard.test.mjs`

## Documentation-Only Claims

Architecture guidance, mode-selection recommendations, and threat-boundary narrative are non-executable rationale and reviewed as documentation quality, not runtime tests.
