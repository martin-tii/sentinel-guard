import yaml
import os
import shlex
from urllib.parse import urlparse
from pathlib import Path
from .utils import audit

class PolicyEnforcer:
    def __init__(self, policy_path="sentinel.yaml"):
        self.policy = self._load_policy(policy_path)

    def _load_policy(self, path):
        try:
            # Note: We use the raw open here to avoid recursion with the interceptor
            with open(path, "r") as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            audit("LOAD_POLICY", f"Policy file not found: {path}", "ERROR")
            return {}

    def check_file_access(self, path):
        """The Jail: Validate file access using Path parsing (Strict)."""
        # Resolve path to absolute
        target_path = Path(path).resolve()
        
        # 1. Check Blocked Paths (Explicit Deny)
        for blocked in self.policy.get("blocked_paths", []):
            blocked_path = Path(blocked).expanduser().resolve()
            # Check if target is inside blocked path
            try:
                target_path.relative_to(blocked_path)
                audit("FILE_ACCESS", path, "BLOCKED (Explicit Deny)")
                raise PermissionError(f"Access to {path} is explicitly blocked.")
            except ValueError:
                continue # Not relative to this blocked path

        # 2. Check Allowed Paths (Whitelist)
        allowed = False
        for allowed_path in self.policy.get("allowed_paths", []):
            whitelist_path = Path(allowed_path).expanduser().resolve()
            try:
                target_path.relative_to(whitelist_path)
                allowed = True
                break
            except ValueError:
                continue

        if not allowed:
             audit("FILE_ACCESS", path, "BLOCKED (Not Whitelisted)")
             raise PermissionError(f"Access to {path} is outside the allowed workspace.")
        
        audit("FILE_ACCESS", path, "ALLOWED")
        return True

    def check_command(self, command):
        """The Governor: Validate shell commands using shlex."""
        try:
            # Parse the command line safely (handles quotes, etc.)
            parts = shlex.split(command)
        except ValueError:
            # Unbalanced quotes or malformed command
            audit("EXEC_COMMAND", command, "BLOCKED (Malformed)")
            raise PermissionError("Malformed command string.")

        if not parts:
            return True

        cmd_base = parts[0]
        
        # Check for shell separators if we want to be extra safe
        risky_chars = [';', '&&', '||', '|']
        if any(char in command for char in risky_chars):
             audit("EXEC_COMMAND", command, "BLOCKED (Shell Injection Risk)")
             raise PermissionError("Complex shell chaining (;, &&, |) is not allowed.")

        if cmd_base not in self.policy.get("allowed_commands", []):
             audit("EXEC_COMMAND", command, "BLOCKED")
             raise PermissionError(f"Command '{cmd_base}' is not allowed.")
        
        audit("EXEC_COMMAND", command, "ALLOWED")
        return True

    def check_network(self, url):
        """The Governor: Validate actual hostnames."""
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
        except Exception:
             audit("NETWORK_ACCESS", url, "BLOCKED (Invalid URL)")
             raise PermissionError("Invalid URL format.")

        if not hostname:
             # Could be a relative path or weird format
             audit("NETWORK_ACCESS", url, "BLOCKED (No Hostname)")
             raise PermissionError("URL must contain a hostname.")

        # Check whitelist
        allowed = False
        for allowed_host in self.policy.get("allowed_hosts", []):
            # Strict match or subdomain match (e.g., .openai.com)
            if hostname == allowed_host or hostname.endswith("." + allowed_host):
                allowed = True
                break
        
        if not allowed:
            audit("NETWORK_ACCESS", url, "BLOCKED")
            raise PermissionError(f"Network access to {hostname} is blocked.")
            
        audit("NETWORK_ACCESS", url, "ALLOWED")
        return True

    def check_input(self, text):
        """The Airlock: Sanitize input."""
        # (Existing logic is fine for MVP)
        for keyword in self.policy.get("blocked_keywords", []):
            if keyword.lower() in text.lower():
                audit("INPUT_SANITIZATION", f"Blocked keyword found: {keyword}", "BLOCKED")
                raise ValueError("Input contains restricted content.")
        
        audit("INPUT_SANITIZATION", "Input clean", "ALLOWED")
        return text