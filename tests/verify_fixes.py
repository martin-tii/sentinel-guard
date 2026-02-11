import sys
import os
import subprocess
from pathlib import Path

# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.core import activate_sentinel

activate_sentinel()

print("--- 🛡️ VERIFICATION START ---")

# TEST 1: The "Fake Workspace" Attack
# Old Vulnerability: allowed_path="./workspace" matched "./workspace_fake"
print("\n[TEST 1] Testing Path Traversal (Fake Workspace)...")
fake_path = os.path.abspath("./workspace_fake/secret.txt")
try:
    # Ensure directory exists for the test to be valid logic-wise
    os.makedirs(os.path.dirname(fake_path), exist_ok=True)
    with open(fake_path, "w") as f:
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

print("\n--- 🛡️ VERIFICATION END ---")