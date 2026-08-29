"""
Scoobert-Security: Interactive Live Daytona Sandbox Test
========================================================
Run this script to inspect live Daytona desktop capture, mouse/keyboard events,
and low-level Linux kernel `strace` syscall interceptions (with network logging).

Usage:
    python3 test_daytona.py
"""

import json
import os
import time
from dotenv import load_dotenv

# Load environment
load_dotenv()

from core.daytona_ops import LinuxDesktopSandbox


def test_interactive_daytona():
    print("=" * 70)
    print("🛡️  SENTINEL: LIVE DAYTONA SANDBOX INSPECTION SUITE")
    print("=" * 70)

    t0 = time.time()

    with LinuxDesktopSandbox() as sandbox:
        sandbox_id = sandbox.sandbox.id
        print(f"\n[1] 🚀 Live Sandbox Provisioned:")
        print(f"    - Sandbox ID: {sandbox_id}")

        # ---------------------------------------------------------------------
        # 1. Desktop Vision & Screenshot Inspection
        # ---------------------------------------------------------------------
        print(f"\n[2] 📸 Capturing Real Desktop Screenshot:")
        size = sandbox.get_screen_size()
        print(f"    - Virtual Display Resolution: {size[0]}x{size[1]}")

        screenshot = sandbox.take_screenshot()
        img_bytes = screenshot.image_bytes
        screenshot_path = "daytona_desktop.png"
        screenshot.save(screenshot_path)
        print(f"    - Screenshot captured: {len(img_bytes):,} bytes (format: {screenshot.format})")
        print(f"    - Saved image to: {os.path.abspath(screenshot_path)}")

        # ---------------------------------------------------------------------
        # 2. Desktop Mouse & Keyboard Control
        # ---------------------------------------------------------------------
        print(f"\n[3] 🖱️  Testing Desktop Mouse & Keyboard Actions:")
        m = sandbox.mouse_move(500, 350)
        print(f"    - Mouse Move: {m}")
        c = sandbox.mouse_click(500, 350, button="left")
        print(f"    - Mouse Click: {c}")
        k = sandbox.type_text("whoami")
        print(f"    - Keyboard Typed: {k}")

        # ---------------------------------------------------------------------
        # 3. Process Execution & Real Kernel `strace` Interception (With Network Egress)
        # ---------------------------------------------------------------------
        print(f"\n[4] 🔍 Executing Adversarial Command (File Access + Drop + Network Egress):")
        # Network calls are NOT blocked — they proceed and get logged by strace
        cmd = (
            'cat secret.txt && '
            'rm -f dummy_data.db && '
            'python3 -c "import urllib.request; urllib.request.urlopen(\'https://httpbin.org/get\', timeout=5)"'
        )
        print(f"    - Command: {cmd}")

        res = sandbox.execute_command(cmd)
        print(f"    - Exit Code: {res.exit_code}")
        print(f"    - Stdout: {res.stdout.strip()[:100]}...")

        # ---------------------------------------------------------------------
        # 4. Forensic Telemetry Extraction
        # ---------------------------------------------------------------------
        print(f"\n[5] 📊 Captured Kernel Telemetry (The Contract):")
        telemetry = sandbox.get_telemetry()
        print(json.dumps(telemetry, indent=4))

    print(f"\n" + "=" * 70)
    print(f"✨ Live Test Completed in {time.time() - t0:.2f}s!")
    print(f"🖼️  Check '{screenshot_path}' in the file explorer to view the captured desktop.")
    print("=" * 70)


if __name__ == "__main__":
    test_interactive_daytona()
