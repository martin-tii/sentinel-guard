import yaml
import os
from .utils import audit

class PolicyEnforcer:
    def __init__(self, policy_path="sentinel.yaml"):
        self.policy = self._load_policy(policy_path)

    def _load_policy(self, path):
        try:
            with open(path, "r") as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            audit("LOAD_POLICY", f"Policy file not found: {path}", "ERROR")
            return {}

    def check_file_access(self, path):
        """The Jail: Validate file access against whitelist/blacklist."""
        abs_path = os.path.abspath(path)
        
        # Check blocked paths first
        for blocked in self.policy.get("blocked_paths", []):
             if blocked in abs_path:
                 audit("FILE_ACCESS", path, "BLOCKED")
                 raise PermissionError(f"Access to {path} is blocked by Sentinel Policy.")

        # Check allowed paths
        allowed = False
        for allowed_path in self.policy.get("allowed_paths", []):
            if os.path.abspath(allowed_path) in abs_path:
                allowed = True
                break
        
        if not allowed:
             audit("FILE_ACCESS", path, "BLOCKED")
             raise PermissionError(f"Access to {path} is not in allowed paths.")
        
        audit("FILE_ACCESS", path, "ALLOWED")
        return True

    def check_command(self, command):
        """The Governor: Validate shell commands."""
        # Simple check: command must start with an allowed command
        cmd_base = command.split()[0]
        if cmd_base not in self.policy.get("allowed_commands", []):
             audit("EXEC_COMMAND", command, "BLOCKED")
             raise PermissionError(f"Command '{cmd_base}' is not allowed.")
        
        audit("EXEC_COMMAND", command, "ALLOWED")
        return True

    def check_network(self, url):
        """The Governor: Validate network requests."""
        for allowed_host in self.policy.get("allowed_hosts", []):
            if allowed_host in url:
                audit("NETWORK_ACCESS", url, "ALLOWED")
                return True
        
        audit("NETWORK_ACCESS", url, "BLOCKED")
        raise PermissionError(f"Network access to {url} is blocked.")

    def check_input(self, text):
        """The Airlock: Sanitize input for injection prompts."""
        for keyword in self.policy.get("blocked_keywords", []):
            if keyword.lower() in text.lower():
                audit("INPUT_SANITIZATION", f"Blocked keyword found: {keyword}", "BLOCKED")
                raise ValueError("Input contains restricted content.")
        
        audit("INPUT_SANITIZATION", "Input clean", "ALLOWED")
        return text
