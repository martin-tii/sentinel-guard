import yaml
import os
import shlex
import io
import socket
import ipaddress
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

    def _blocked_command_bases(self):
        configured = self.policy.get("blocked_command_bases", [])
        defaults = [
            "python", "python3", "bash", "sh", "zsh", "fish",
            "perl", "ruby", "node", "php", "pwsh", "powershell",
        ]
        blocked = set(defaults)
        blocked.update(str(cmd).strip() for cmd in configured if str(cmd).strip())
        return blocked

    def _enforce_command_base_policy(self, cmd_base, command_text):
        blocked = self._blocked_command_bases()
        if cmd_base in blocked:
            audit("EXEC_COMMAND", command_text, "BLOCKED (Forbidden Base Command)")
            raise PermissionError(
                f"Command '{cmd_base}' is blocked by fail-safe policy."
            )

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

            self._enforce_command_base_policy(cmd_base, str(command))
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

        blocked_operators = {
            ";", "&&", "||", "|", "&", ">", ">>", "<", "<<",
            "$", "(", ")", "`",
        }
        has_blocked_operator = any(token in blocked_operators for token in tokens)
        has_substitution_pattern = ("$(" in command_text) or ("`" in command_text)
        if has_blocked_operator or has_substitution_pattern:
            audit("EXEC_COMMAND", command_text, "BLOCKED (Shell Injection Risk)")
            raise PermissionError("Complex shell chaining/redirection/substitution is not allowed.")

        cmd_base = self._command_base_from_shell_tokens(tokens)
        if not cmd_base:
            audit("EXEC_COMMAND", command_text, "BLOCKED (Malformed)")
            raise PermissionError("Could not determine executable command.")

        self._enforce_command_base_policy(cmd_base, command_text)
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

        if not self._is_allowed_hostname(hostname):
            audit("NETWORK_ACCESS", url, "BLOCKED")
            raise PermissionError(f"Network access to {hostname} is blocked.")
            
        audit("NETWORK_ACCESS", url, "ALLOWED")
        return True

    def _is_allowed_hostname(self, hostname):
        allowed_hosts = self.policy.get("allowed_hosts", [])
        for allowed_host in allowed_hosts:
            if hostname == allowed_host or hostname.endswith("." + allowed_host):
                return True
        return False

    def _host_in_rules(self, host, rules):
        for rule in rules:
            rule = str(rule).strip()
            if not rule:
                continue
            if host == rule or host.endswith("." + rule):
                return True
        return False

    def _resolve_host_ips(self, host):
        resolved = set()
        try:
            ip_obj = ipaddress.ip_address(host)
            resolved.add(ip_obj)
            return resolved
        except ValueError:
            pass

        try:
            infos = socket.getaddrinfo(host, None)
            for info in infos:
                sockaddr = info[4]
                if not sockaddr:
                    continue
                ip_str = sockaddr[0]
                try:
                    resolved.add(ipaddress.ip_address(ip_str))
                except ValueError:
                    continue
        except Exception:
            return resolved
        return resolved

    def _ip_matches_any_rule(self, ip_obj, rules):
        for rule in rules:
            rule = str(rule).strip()
            if not rule:
                continue
            try:
                if "/" in rule:
                    if ip_obj in ipaddress.ip_network(rule, strict=False):
                        return True
                else:
                    if ip_obj == ipaddress.ip_address(rule):
                        return True
            except ValueError:
                continue
        return False

    def check_socket_connect(self, host, port):
        """
        Socket-level fail-safe check.
        Used when network_failsafe.socket_connect is enabled.
        """
        host_text = str(host).strip()
        if not host_text:
            audit("SOCKET_CONNECT", f"{host}:{port}", "BLOCKED (No Host)")
            raise PermissionError("Socket connect target host is required.")

        # Unix domain socket paths are not remote network hosts.
        if host_text.startswith("/"):
            audit("SOCKET_CONNECT", f"{host_text}:{port}", "ALLOWED")
            return True

        cfg = self.policy.get("network_failsafe", {})
        blocked_hosts = cfg.get("blocked_hosts", [])
        if self._host_in_rules(host_text, blocked_hosts):
            audit("SOCKET_CONNECT", f"{host_text}:{port}", "BLOCKED (Blocked Host)")
            raise PermissionError(f"Socket access to {host_text} is blocked.")

        # Hostname policy is still enforced at socket layer.
        # If host is an IP literal, hostname allowlist does not apply.
        is_ip_literal = True
        try:
            ipaddress.ip_address(host_text)
        except ValueError:
            is_ip_literal = False

        if not is_ip_literal and not self._is_allowed_hostname(host_text):
            audit("SOCKET_CONNECT", f"{host_text}:{port}", "BLOCKED (Host Not Allowed)")
            raise PermissionError(f"Socket access to {host_text} is blocked.")

        resolved_ips = self._resolve_host_ips(host_text)
        blocked_ips = cfg.get("blocked_ips", [])
        allowed_ips = cfg.get("allowed_ips", [])
        allow_private_network = bool(cfg.get("allow_private_network", False))

        if resolved_ips:
            for ip_obj in resolved_ips:
                if self._ip_matches_any_rule(ip_obj, blocked_ips):
                    audit("SOCKET_CONNECT", f"{host_text}:{port}", "BLOCKED (Blocked IP)")
                    raise PermissionError(f"Socket access to {ip_obj} is blocked.")

                if allowed_ips and not self._ip_matches_any_rule(ip_obj, allowed_ips):
                    audit("SOCKET_CONNECT", f"{host_text}:{port}", "BLOCKED (IP Not Allowed)")
                    raise PermissionError(f"Socket access to {ip_obj} is not allowed.")

                if not allow_private_network and (
                    ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
                ):
                    audit("SOCKET_CONNECT", f"{host_text}:{port}", "BLOCKED (Private Network)")
                    raise PermissionError(f"Private network socket access to {ip_obj} is blocked.")

        audit("SOCKET_CONNECT", f"{host_text}:{port}", "ALLOWED")
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
