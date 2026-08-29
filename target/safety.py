"""Startup guard so M1 does not wipe their own laptop during development.

The target agent is SUPPOSED to be dangerous — that is the point. But while
building it we run it on our own machines. This guard refuses to run unless it
detects a sandbox/container, or the operator passes --force.

This is NOT a production safety control. Inside Daytona the sandbox markers are
present, so the fixture runs freely and its known defects remain observable. It only exists to stop
an accidental `os.system("rm -rf ~")` on a dev laptop.
"""
from __future__ import annotations

import os
import sys


def looks_like_sandbox() -> bool:
    """Best-effort detection that we are inside a disposable container/sandbox."""
    if os.environ.get("SENTINEL_SANDBOX") == "1":
        return True
    if os.path.exists("/.dockerenv"):
        return True
    for marker in ("DAYTONA_SANDBOX_ID", "DAYTONA_WS_ID", "CODESPACES", "CI"):
        if os.environ.get(marker):
            return True
    try:
        with open("/proc/1/cgroup", "r", encoding="utf-8") as fh:
            data = fh.read()
        if any(tag in data for tag in ("docker", "kubepods", "containerd", "lxc")):
            return True
    except OSError:
        pass
    return False


def assert_sandbox_or_die(force: bool = False) -> None:
    """Exit unless we are in a sandbox or the operator forced it."""
    if force or looks_like_sandbox():
        return
    sys.stderr.write(
        "\n".join(
            [
                "",
                "  ┌────────────────────────────────────────────────────────────┐",
                "  │  REFUSING TO RUN: this does not look like a sandbox.        │",
                "  │                                                            │",
                "  │  The target agent executes real shell commands, arbitrary  │",
                "  │  SQL, file reads, and outbound network requests. Running   │",
                "  │  it on your own machine can destroy data.                  │",
                "  │                                                            │",
                "  │  Inside Daytona this passes automatically. For local dev,  │",
                "  │  set SENTINEL_SANDBOX=1 or pass --force (you accept risk). │",
                "  └────────────────────────────────────────────────────────────┘",
                "",
            ]
        )
        + "\n"
    )
    raise SystemExit(3)
