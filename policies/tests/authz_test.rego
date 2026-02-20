package sentinel.authz_test

import rego.v1
import data.sentinel.authz

test_file_access_allow if {
  input := {
    "action": {"type": "file_access", "target": "/workspace/project/a.txt"},
    "context": {"workspace_root": "/workspace/project"},
  }
  authz.decision with input as input == {"allow": true, "reason": "Allowed by OPA policy", "tags": ["allow", "action:file_access"]}
}

test_file_access_deny_outside_workspace if {
  input := {
    "action": {"type": "file_access", "target": "/etc/passwd"},
    "context": {"workspace_root": "/workspace/project"},
  }
  result := authz.decision with input as input
  result.allow == false
  contains(lower(result.reason), "file")
}

test_command_allow if {
  input := {
    "action": {"type": "command_exec", "target": "ls -la", "args": ["ls", "-la"]},
    "context": {"workspace_root": "/workspace/project"},
  }
  result := authz.decision with input as input
  result.allow
}

test_command_deny_shell_chain if {
  input := {
    "action": {"type": "command_exec", "target": "ls && cat /etc/passwd", "args": ["ls", "&&", "cat"]},
    "context": {"workspace_root": "/workspace/project"},
  }
  result := authz.decision with input as input
  result.allow == false
}

test_network_allow_openai_https if {
  input := {
    "action": {
      "type": "network_http",
      "target": "https://api.openai.com/v1/models",
      "metadata": {"host": "api.openai.com", "scheme": "https", "port": 443}
    },
    "context": {"workspace_root": "/workspace/project"},
  }
  result := authz.decision with input as input
  result.allow
}

test_network_deny_wrong_host if {
  input := {
    "action": {
      "type": "network_http",
      "target": "https://evil.com",
      "metadata": {"host": "evil.com", "scheme": "https", "port": 443}
    },
    "context": {"workspace_root": "/workspace/project"},
  }
  result := authz.decision with input as input
  result.allow == false
}

test_tool_call_deny_unknown_tool if {
  input := {
    "action": {
      "type": "tool_call",
      "tool": "danger_tool",
      "target": "danger_tool"
    },
    "context": {"workspace_root": "/workspace/project"},
  }
  result := authz.decision with input as input
  result.allow == false
}
