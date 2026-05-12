#!/usr/bin/env python3
"""
build_exe.py  —  Ulinzi HIDS v4 Executable Builder
====================================================
Run this ONCE on your Kali VM to compile Ulinzi into a single executable.

Usage:
    python3 build_exe.py

Output:
    dist/ulinzi          ← The standalone executable
    dist/ulinzi.conf     ← Default config (copy alongside the executable)

The executable bundles Python, Flask, psutil, and all dependencies.
No Python installation needed to run it — just: sudo ./ulinzi

HOW IT WORKS
    PyInstaller walks the import tree and packages everything into a single
    ELF binary. The Flask templates are embedded as data. The executable
    unpacks to a temp dir at runtime (fast, < 2 seconds).

RUNNING THE EXECUTABLE
    sudo ./dist/ulinzi              # full monitoring (all 8 rules)
    sudo ./dist/ulinzi --port 8080  # custom port
    ./dist/ulinzi                   # host-only (no network capture, no sudo needed)

REQUIREMENTS
    pip install pyinstaller flask psutil requests --break-system-packages
"""

import subprocess, sys, os, shutil

ENTRY  = "app.py"
NAME   = "ulinzi"
DIST   = "dist"

def run(cmd):
    print(f"\n$ {' '.join(cmd)}")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print(f"\n[ERROR] Command failed with exit code {result.returncode}")
        sys.exit(result.returncode)

def main():
    print("=" * 60)
    print("  Ulinzi HIDS v4 — PyInstaller build")
    print("=" * 60)

    # Check dependencies
    missing = []
    for pkg in ("flask","psutil","requests","PyInstaller"):
        try: __import__(pkg.lower().replace("pyinstaller","PyInstaller"))
        except ImportError: missing.append(pkg)
    if missing:
        print(f"\n[ERROR] Missing packages: {', '.join(missing)}")
        print(f"Install: pip install {' '.join(missing)} --break-system-packages")
        sys.exit(1)

    # Clean previous build
    for d in ("build", DIST, f"{NAME}.spec"):
        if os.path.exists(d):
            print(f"  Removing old {d}/")
            shutil.rmtree(d) if os.path.isdir(d) else os.remove(d)

    # PyInstaller command
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",                          # single binary
        "--name", NAME,
        "--distpath", DIST,
        "--clean",
        "--strip",                            # smaller binary
        # Hidden imports Flask needs at runtime
        "--hidden-import", "flask",
        "--hidden-import", "flask.templating",
        "--hidden-import", "jinja2",
        "--hidden-import", "jinja2.ext",
        "--hidden-import", "werkzeug",
        "--hidden-import", "werkzeug.serving",
        "--hidden-import", "werkzeug.routing",
        "--hidden-import", "click",
        "--hidden-import", "psutil",
        "--hidden-import", "requests",
        "--hidden-import", "sqlite3",
        # Engine module
        "--hidden-import", "hids_engine",
        # No console window (we manage our own logging)
        # "--noconsole",  # leave commented — we want stdout on Kali terminal
        ENTRY,
    ]

    run(cmd)

    # Copy default config alongside executable
    import json
    default_cfg = {
        "interface":            None,
        "baseline_seconds":     60,
        "window_seconds":       1,
        "threshold_multiplier": 3,
        "confirm_windows":      2,
        "cooldown_secs":        30,
        "file_check_interval":  5,
        "syn_floor":            100,
        "udp_floor":            500,
        "icmp_floor":           50,
        "total_floor":          800,
        "syn_ratio_min":        0.60,
        "port_scan_threshold":  20,
        "dns_query_floor":      50,
        "auth_fail_floor":      3,
        "sudo_event_floor":     5,
        "process_spawn_floor":  20,
        "ntfy_enabled":         False,
        "ntfy_topic":           "ulinzi-hids-CHANGE-THIS",
        "ntfy_server":          "https://ntfy.sh",
        "ntfy_min_level":       "MEDIUM",
        "ntfy_token":           "",
        "alert_log":            "alerts.log",
        "json_log":             "alerts.jsonl",
        "info_log":             "hids.log",
        "db_path":              "ulinzi.db",
        "monitored_files": [
            "/etc/passwd", "/etc/shadow", "/etc/sudoers",
            "/etc/hosts", "/etc/ssh/sshd_config", "/etc/crontab"
        ]
    }
    cfg_path = os.path.join(DIST, "ulinzi.conf")
    with open(cfg_path, "w") as fh:
        json.dump(default_cfg, fh, indent=2)

    # Create run script
    run_sh = os.path.join(DIST, "run.sh")
    with open(run_sh, "w") as fh:
        fh.write("""#!/bin/bash
# Ulinzi HIDS v4 — Quick launcher
# Run from the directory containing the ulinzi executable
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ "$EUID" -ne 0 ]; then
    echo "[ulinzi] WARNING: Not running as root. Network rules (N1-N6) disabled."
    echo "[ulinzi] For full monitoring, run: sudo ./run.sh"
    echo ""
fi

./ulinzi "$@"
""")
    os.chmod(run_sh, 0o755)
    os.chmod(os.path.join(DIST, NAME), 0o755)

    exe_size = os.path.getsize(os.path.join(DIST, NAME)) / 1024 / 1024

    print(f"""
{'='*60}
  BUILD SUCCESSFUL
{'='*60}

  Executable : {DIST}/{NAME}  ({exe_size:.1f} MB)
  Config     : {DIST}/ulinzi.conf
  Launcher   : {DIST}/run.sh

  To run:
    cd {DIST}
    sudo ./ulinzi                     # full monitoring, port 5000
    sudo ./ulinzi --port 8080         # custom port

  To configure push notifications:
    nano {DIST}/ulinzi.conf
    # Set ntfy_enabled: true and ntfy_topic to your topic name

  To deploy to /usr/local/bin:
    sudo cp {DIST}/ulinzi /usr/local/bin/
    sudo cp {DIST}/ulinzi.conf /etc/ulinzi.conf

{'='*60}
""")

if __name__ == "__main__":
    main()
