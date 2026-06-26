#!/usr/bin/env python3
"""Minimal "allow everything" prompter for turnstile-sandbox.

Reads a single PrompterRequest JSON object on stdin and writes a single
PrompterResponse JSON object on stdout (see ``src/bin/prompter.rs`` for
the protocol).

Policy:
  * For each requested permission that needs actual access (read, write,
    exec, or chdir), add a bind mount at the requested path mirroring the
    host (``host_path == mount_point``), made writable / executable as
    needed.
  * For resolve-only requests (not r/w/x and not chdir), add a
    placeholder with ``match_host`` so the path merely becomes resolvable.
  * Always ask turnstile-sandbox to auto-add the symlinks needed to
    resolve the path and to widen descendant mount permissions.
  * Always continue the syscall.
"""

import json
import sys


def main() -> None:
    request = json.load(sys.stdin)

    add_mounts = []
    add_placeholders = []
    seen_mounts = set()
    seen_placeholders = set()

    for perm in request.get("rwx_permissions", []):
        path = perm["target"]["path"]
        need_read = perm.get("read", False) or perm.get("chdir", False)
        need_write = perm.get("write", False)
        need_exec = perm.get("exec", False)

        if need_read or need_write or need_exec:
            # Grant access by mirroring the host path 1:1.
            if path in seen_mounts:
                continue
            seen_mounts.add(path)
            add_mounts.append(
                {
                    "mount_point": path,
                    "host_path": path,
                    "attrs": {
                        "readonly": not need_write,
                        "noexec": not need_exec,
                    },
                }
            )
        else:
            # Resolve-only: just make the path resolvable.
            if path in seen_placeholders:
                continue
            seen_placeholders.add(path)
            add_placeholders.append({"path": path, "match_host": True})

    response = {
        "action": {"continue": True},
        "add_mounts": add_mounts,
        "add_placeholders": add_placeholders,
        "auto_add_symlinks": True,
        "auto_widen_descendant_permissions": True,
    }

    json.dump(response, sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
