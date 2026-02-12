import os
import sys
import importlib.util

# 1. Setup paths (assuming sentinel-guard is installed or in adjacent folder)
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core import activate_sentinel, set_approval_handler
from src.approval import console_approval_handler


def main():
    print("[Sentinel] Initializing...")

    # 2. Configure the Policy Path (Optional override)
    # os.environ["SENTINEL_CONFIG"] = "/path/to/custom/sentinel.yaml"

    # 3. ACTIVATE PROTECTION
    # This wrapper enforces in-process controls for Python entrypoints only.
    # Official OpenClaw CLI/Gateway runs in Node.js and must be isolated externally.
    activate_sentinel()

    # 4. Set the Approval UI (Console or Tkinter)
    # For a headless server, use console_approval_handler or a custom webhook
    set_approval_handler(console_approval_handler)

    print("[Sentinel] Active. Launching OpenClaw Python entrypoint...")
    print("------------------------------------------------")

    # 5. Launch OpenClaw Python entrypoint
    # Assumption: You usually run `python openclaw.py`.
    # We load that script dynamically here.
    OPENCLAW_PATH = os.environ.get("OPENCLAW_PATH", "openclaw.py")

    if not os.path.exists(OPENCLAW_PATH):
        # Fallback for demo purposes if user doesn't have openclaw.py yet
        print(f"[Sentinel] Target '{OPENCLAW_PATH}' not found. Running internal simulation.")
        import examples.risky_agent as mock_agent

        mock_agent.run_risky_agent()
        return

    # Dynamic Import & Execution of the Agent
    spec = importlib.util.spec_from_file_location("__main__", OPENCLAW_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load target module: {OPENCLAW_PATH}")

    module = importlib.util.module_from_spec(spec)
    sys.modules["__main__"] = module
    spec.loader.exec_module(module)


if __name__ == "__main__":
    main()
