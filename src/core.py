import builtins
import subprocess
import requests # Assuming requests is used, we'll patch it
from .policy import PolicyEnforcer
from .utils import audit

# Initialize Policy
policy = PolicyEnforcer()

# --- Interceptors ---

# 1. File System Interceptor (The Jail)
_original_open = builtins.open

def sentinel_open(file, mode='r', buffering=-1, encoding=None, errors=None, newline=None, closefd=True, opener=None):
    # Only check if writing or reading? Policy checks all access for now.
    try:
        policy.check_file_access(file)
    except PermissionError as e:
        raise e
    return _original_open(file, mode, buffering, encoding, errors, newline, closefd, opener)

# 2. Command Execution Interceptor (The Governor)
_original_system = subprocess.run

def sentinel_run(*args, **kwargs):
    command = args[0] if args else kwargs.get('args')
    if isinstance(command, list):
        command = " ".join(command)
    
    try:
        policy.check_command(command)
    except PermissionError as e:
        raise e
    return _original_system(*args, **kwargs)

# 3. Network Interceptor (The Governor)
# Note: This is a simple patch for requests.get. A full solution would patch socket/urllib.
_original_get = requests.get

def sentinel_get(url, params=None, **kwargs):
    try:
        policy.check_network(url)
    except PermissionError as e:
        raise e
    return _original_get(url, params=params, **kwargs)


# --- Activation ---

def activate_sentinel():
    """Activates the Sentinel monitoring system."""
    audit("SYSTEM", "Sentinel Activated. Monitoring engaged.", "INFO")
    
    # Monkey Patching
    builtins.open = sentinel_open
    subprocess.run = sentinel_run
    requests.get = sentinel_get

    # Airlock is passive, used when processing input explicitly
    
def scan_input(text):
    """Public API for the Airlock."""
    return policy.check_input(text)
