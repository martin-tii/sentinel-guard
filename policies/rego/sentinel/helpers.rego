package sentinel.helpers

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
