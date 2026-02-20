package sentinel.authz

import rego.v1

default decision := {
  "allow": false,
  "reason": "Denied by default policy",
  "tags": ["default_deny"],
}

blocked_paths := ["/etc", "/home", "~/.ssh"]
allowed_commands := {"echo", "ls", "ps"}
blocked_command_bases := {
  "python", "python3", "bash", "sh", "zsh", "fish", "perl", "ruby", "node", "php", "pwsh", "powershell",
}

allowed_hosts := [
  {"host": "api.openai.com", "match": "exact", "schemes": {"https"}, "ports": {443}},
  {"host": "pypi.org", "match": "exact", "schemes": {"https"}, "ports": {443}},
]

allowed_tool_calls := {"exec", "process", "write", "edit", "apply_patch"}

shell_blocked_patterns := [";", "&&", "||", "|", "$(", "`", ">", "<"]

decision := {
  "allow": true,
  "reason": "Allowed by OPA policy",
  "tags": ["allow", action_tag],
} if {
  valid_input
  action_tag := sprintf("action:%s", [input.action.type])
  allow_action
}

decision := {
  "allow": false,
  "reason": deny_reason,
  "tags": ["deny", action_tag],
} if {
  valid_input
  action_tag := sprintf("action:%s", [input.action.type])
  deny_reason := deny_reasons[_]
}

valid_input if {
  is_nonempty_string(input.action.type)
}

allow_action if {
  input.action.type == "file_access"
  allow_file_access
}

allow_action if {
  input.action.type == "command_exec"
  allow_command_exec
}

allow_action if {
  input.action.type == "network_http"
  allow_network_http
}

allow_action if {
  input.action.type == "socket_connect"
  allow_socket_connect
}

allow_action if {
  input.action.type == "tool_call"
  allow_tool_call
}

allow_file_access if {
  target := normalize_path(input.action.target)
  root := normalize_path(input.context.workspace_root)
  is_nonempty_string(root)
  is_subpath(target, root)
  not file_path_is_blocked(target)
}

file_path_is_blocked(target) if {
  blocked := blocked_paths[_]
  startswith(target, blocked)
}

allow_command_exec if {
  base := lower(command_base)
  allowed_commands[base]
  not blocked_command_bases[base]
  not has_shell_injection_pattern
}

command_base := out if {
  args := input.action.args
  is_array(args)
  count(args) > 0
  out := lower(sprintf("%v", [args[0]]))
} else := out if {
  raw := lower(sprintf("%v", [input.action.target]))
  parts := split(raw, " ")
  count(parts) > 0
  out := parts[0]
}

has_shell_injection_pattern if {
  text := lower(sprintf("%v", [input.action.target]))
  pattern := shell_blocked_patterns[_]
  contains(text, pattern)
}

allow_network_http if {
  host := lower(sprintf("%v", [input.action.metadata.host]))
  scheme := lower(sprintf("%v", [input.action.metadata.scheme]))
  port := to_number(input.action.metadata.port)
  host_rule_matches(host, scheme, port)
}

allow_socket_connect if {
  host := lower(sprintf("%v", [input.action.metadata.host]))
  is_nonempty_string(host)
  port := to_number(input.action.metadata.port)
  host_rule_matches(host, "https", port)
}

host_rule_matches(host, scheme, port) if {
  rule := allowed_hosts[_]
  host_matches_rule(host, rule)
  rule.schemes[scheme]
  effective_port := object.get(input.action.metadata, "port", default_port(scheme))
  numeric_port := to_number(effective_port)
  rule.ports[numeric_port]
}

host_matches_rule(host, rule) if {
  lower(rule.match) == "subdomain"
  host_matches_subdomain(host, rule.host)
} else if {
  host_matches_exact(host, rule.host)
}

allow_tool_call if {
  tool := lower(sprintf("%v", [input.action.tool]))
  allowed_tool_calls[tool]
}

deny_reasons contains "File access outside allowed workspace" if {
  input.action.type == "file_access"
  not allow_file_access
}

deny_reasons contains "Command is not allowed by policy" if {
  input.action.type == "command_exec"
  not allow_command_exec
}

deny_reasons contains "HTTP destination is not allowed by policy" if {
  input.action.type == "network_http"
  not allow_network_http
}

deny_reasons contains "Socket destination is not allowed by policy" if {
  input.action.type == "socket_connect"
  not allow_socket_connect
}

deny_reasons contains "Tool invocation is not allowed by policy" if {
  input.action.type == "tool_call"
  not allow_tool_call
}

# Defensive fallback for unknown action types.
deny_reasons contains "Unknown action type" if {
  not allow_action
  input.action.type != "file_access"
  input.action.type != "command_exec"
  input.action.type != "network_http"
  input.action.type != "socket_connect"
  input.action.type != "tool_call"
}

is_nonempty_string(value) if {
  is_string(value)
  trim_space(value) != ""
}

default_port("http") := 80
default_port("https") := 443

normalize_path(value) := out if {
  out := trim_space(sprintf("%v", [value]))
}

is_subpath(path, root) if {
  p := normalize_path(path)
  r := normalize_path(root)
  p == r
} else if {
  p := normalize_path(path)
  r := normalize_path(root)
  startswith(p, sprintf("%s/", [r]))
}

host_matches_exact(host, allowed) if {
  lower(host) == lower(allowed)
}

host_matches_subdomain(host, allowed) if {
  lower(host) == lower(allowed)
} else if {
  endswith(lower(host), sprintf(".%s", [lower(allowed)]))
}
