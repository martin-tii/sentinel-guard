import yaml
import os
import shlex
import io
from urllib.parse import urlparse
from pathlib import Path
from .utils import audit

class PolicyEnforcer:
    def __init__(self, policy_path="sentinel.yaml"):
        self.policy_path = self._resolve_policy_path(policy_path)
        self.policy = self._load_policy(self.policy_path)

    def _resolve_policy_path(self, path):
        candidate = Path(path)
        if candidate.is_absolute():
            return candidate

        cwd_candidate = Path.cwd() / candidate
        if cwd_candidate.exists():
            return cwd_candidate

        # Fallback to repository root (../sentinel.yaml from src/policy.py)
        return Path(__file__).resolve().parents[1] / candidate

    def _load_policy(self, path):
        try:
            # Use io.open so policy loading is not blocked by monkey-patched builtins.open
            with io.open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            audit("LOAD_POLICY", f"Policy file not found: {path}", "ERROR")
            return {}
        except yaml.YAMLError as e:
            audit("LOAD_POLICY", f"Invalid policy file at {path}: {e}", "ERROR")
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

    def _shell_tokens(self, command_text):
        lexer = shlex.shlex(command_text, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        return list(lexer)

    def _command_base_from_shell_tokens(self, tokens):
        operators = {";", "&&", "||", "|", "&", ">", ">>", "<", "<<", "(", ")"}
        for token in tokens:
            if token in operators:
                continue
            return token
        return None

    def check_command(self, command, shell=False):
        """The Governor: Validate command execution with shell-aware parsing."""
        if command is None:
            audit("EXEC_COMMAND", "None", "BLOCKED (Malformed)")
            raise PermissionError("Command is required.")

        allowed_commands = self.policy.get("allowed_commands", [])

        # shell=False path: prefer structured argv and avoid shell-operator checks.
        if not shell:
            if isinstance(command, (list, tuple)):
                if not command:
                    return True
                cmd_base = str(command[0])
            else:
                try:
                    parts = shlex.split(str(command))
                except ValueError:
                    audit("EXEC_COMMAND", str(command), "BLOCKED (Malformed)")
                    raise PermissionError("Malformed command string.")
                if not parts:
                    return True
                cmd_base = parts[0]

            if cmd_base not in allowed_commands:
                audit("EXEC_COMMAND", str(command), "BLOCKED")
                raise PermissionError(f"Command '{cmd_base}' is not allowed.")

            audit("EXEC_COMMAND", str(command), "ALLOWED")
            return True

        # shell=True path: strict parsing and shell operator blocking.
        if isinstance(command, (list, tuple)):
            command_text = " ".join(str(part) for part in command)
        else:
            command_text = str(command)

        try:
            tokens = self._shell_tokens(command_text)
        except ValueError:
            audit("EXEC_COMMAND", command_text, "BLOCKED (Malformed)")
            raise PermissionError("Malformed command string.")

        if not tokens:
            return True

        blocked_operators = {";", "&&", "||", "|", "&", ">", ">>", "<", "<<"}
        if any(token in blocked_operators for token in tokens):
            audit("EXEC_COMMAND", command_text, "BLOCKED (Shell Injection Risk)")
            raise PermissionError("Complex shell chaining/redirection is not allowed.")

        cmd_base = self._command_base_from_shell_tokens(tokens)
        if not cmd_base:
            audit("EXEC_COMMAND", command_text, "BLOCKED (Malformed)")
            raise PermissionError("Could not determine executable command.")

        if cmd_base not in allowed_commands:
            audit("EXEC_COMMAND", command_text, "BLOCKED")
            raise PermissionError(f"Command '{cmd_base}' is not allowed.")

        audit("EXEC_COMMAND", command_text, "ALLOWED")
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
