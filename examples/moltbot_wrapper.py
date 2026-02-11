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
    # This must happen before any Moltbot imports to ensure patching works
    activate_sentinel()

    # 4. Set the Approval UI (Console or Tkinter)
    # For a headless server, use console_approval_handler or a custom webhook
    set_approval_handler(console_approval_handler)

    print("[Sentinel] Active. Launching Moltbot...")
    print("------------------------------------------------")

    # 5. Launch Moltbot
    # Assumption: You usually run `python moltbot.py`.
    # We load that script dynamically here.
    MOLTBOT_PATH = "moltbot.py"  # CHANGE THIS to your actual agent script path

    if not os.path.exists(MOLTBOT_PATH):
        # Fallback for demo purposes if user doesn't have moltbot.py yet
        print(f"[Sentinel] Target '{MOLTBOT_PATH}' not found. Running internal simulation.")
        import examples.risky_agent as mock_agent

        mock_agent.run_risky_agent()
        return

    # Dynamic Import & Execution of the Agent
    spec = importlib.util.spec_from_file_location("__main__", MOLTBOT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load target module: {MOLTBOT_PATH}")

    module = importlib.util.module_from_spec(spec)
    sys.modules["__main__"] = module
    spec.loader.exec_module(module)


if __name__ == "__main__":
    main()
