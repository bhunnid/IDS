"""
IDS Web Control Panel
Flask app to monitor and control a background anomaly-based IDS.
"""

import os
import threading
import subprocess
import time
import json
from datetime import datetime
from flask import Flask, render_template_string, jsonify, request, redirect, url_for

# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────
IDS_SCRIPT   = os.environ.get("IDS_SCRIPT",   "ids_main.py")   # path to your IDS entry point
ALERT_LOG    = os.environ.get("ALERT_LOG",    "alerts.log")    # alert log file the IDS writes to
MAX_ALERTS   = int(os.environ.get("MAX_ALERTS", 100))           # lines to keep in memory
HOST         = os.environ.get("HOST",         "0.0.0.0")
PORT         = int(os.environ.get("PORT",     5000))

app = Flask(__name__)

# ──────────────────────────────────────────────
# IDS process state (shared, protected by lock)
# ──────────────────────────────────────────────
_lock        = threading.Lock()
_ids_process = None          # subprocess.Popen handle  (or None)
_ids_thread  = None          # watcher thread
_start_time  = None          # datetime the IDS last started
_stop_reason = "Never started"


def _ids_is_running() -> bool:
    with _lock:
        return _ids_process is not None and _ids_process.poll() is None


def _watcher(proc: subprocess.Popen):
    """Background thread: waits for the IDS process to exit, then cleans up."""
    global _ids_process, _stop_reason
    proc.wait()
    with _lock:
        if _ids_process is proc:          # make sure we're still talking about this process
            _stop_reason = f"Exited with code {proc.returncode}"
            _ids_process = None


# ──────────────────────────────────────────────
# Alert helpers
# ──────────────────────────────────────────────

def _read_alerts(n: int = 50) -> list[str]:
    """Return the last *n* lines from the alert log, newest first."""
    if not os.path.exists(ALERT_LOG):
        return ["No alert log found at: " + ALERT_LOG]
    try:
        with open(ALERT_LOG, "r", errors="replace") as fh:
            lines = fh.readlines()
        trimmed = [l.rstrip() for l in lines if l.strip()]
        return trimmed[-n:][::-1]          # reverse so newest is first
    except OSError as exc:
        return [f"Error reading log: {exc}"]


# ──────────────────────────────────────────────
# HTML Template  (single-file, inline)
# ──────────────────────────────────────────────
TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IDS Control Panel</title>
<style>
  /* ── Reset & base ─────────────────────────── */
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg:        #0d1117;
    --surface:   #161b22;
    --border:    #30363d;
    --text:      #c9d1d9;
    --muted:     #6e7681;
    --green:     #3fb950;
    --red:       #f85149;
    --amber:     #d29922;
    --blue:      #58a6ff;
    --font-mono: 'Courier New', Courier, monospace;
    --font-ui:   Georgia, 'Times New Roman', serif;
  }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--font-ui);
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 2rem 1rem;
  }

  /* ── Header ───────────────────────────────── */
  header {
    width: 100%;
    max-width: 780px;
    border-bottom: 1px solid var(--border);
    padding-bottom: 1rem;
    margin-bottom: 1.8rem;
    display: flex;
    align-items: baseline;
    gap: 1rem;
  }
  header h1 {
    font-size: 1.4rem;
    letter-spacing: .06em;
    text-transform: uppercase;
    color: var(--blue);
  }
  header small {
    color: var(--muted);
    font-size: .78rem;
    font-family: var(--font-mono);
  }

  /* ── Main card container ──────────────────── */
  .panel {
    width: 100%;
    max-width: 780px;
    display: flex;
    flex-direction: column;
    gap: 1.2rem;
  }

  /* ── Section card ─────────────────────────── */
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 1.1rem 1.4rem;
  }
  .card-title {
    font-size: .7rem;
    letter-spacing: .12em;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: .8rem;
  }

  /* ── Status row ───────────────────────────── */
  .status-row {
    display: flex;
    align-items: center;
    gap: 1rem;
    flex-wrap: wrap;
  }
  .badge {
    display: inline-flex;
    align-items: center;
    gap: .4rem;
    padding: .3rem .75rem;
    border-radius: 2rem;
    font-family: var(--font-mono);
    font-size: .82rem;
    font-weight: bold;
  }
  .badge-running  { background: rgba(63,185,80,.15); color: var(--green);  border: 1px solid rgba(63,185,80,.4); }
  .badge-stopped  { background: rgba(248,81,73,.12); color: var(--red);    border: 1px solid rgba(248,81,73,.35); }
  .dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    display: inline-block;
  }
  .dot-running { background: var(--green); box-shadow: 0 0 6px var(--green); }
  .dot-stopped { background: var(--red); }

  .uptime {
    color: var(--muted);
    font-family: var(--font-mono);
    font-size: .78rem;
  }

  /* ── Buttons ──────────────────────────────── */
  .controls {
    display: flex;
    gap: .75rem;
    flex-wrap: wrap;
    margin-top: .4rem;
  }
  button {
    padding: .5rem 1.4rem;
    border: none;
    border-radius: 4px;
    font-size: .88rem;
    cursor: pointer;
    font-family: var(--font-ui);
    transition: opacity .15s;
  }
  button:disabled { opacity: .4; cursor: not-allowed; }
  button:not(:disabled):hover { opacity: .82; }

  .btn-start { background: var(--green);  color: #0d1117; font-weight: bold; }
  .btn-stop  { background: var(--red);    color: #fff;    font-weight: bold; }
  .btn-refresh { background: var(--border); color: var(--text); }

  /* ── Alert log ────────────────────────────── */
  .alert-log {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: .8rem 1rem;
    max-height: 340px;
    overflow-y: auto;
    font-family: var(--font-mono);
    font-size: .78rem;
    line-height: 1.7;
  }
  .alert-log p { color: var(--muted); }
  .alert-line { color: var(--text); border-bottom: 1px solid rgba(48,54,61,.5); padding: .1rem 0; }
  .alert-line.warn  { color: var(--amber); }
  .alert-line.crit  { color: var(--red); }

  /* ── Footer ───────────────────────────────── */
  footer {
    margin-top: 2rem;
    font-size: .72rem;
    color: var(--muted);
    font-family: var(--font-mono);
  }

  /* ── Meta info grid ───────────────────────── */
  .meta-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: .6rem;
    margin-top: .2rem;
  }
  .meta-item { font-size: .78rem; color: var(--muted); font-family: var(--font-mono); }
  .meta-item span { color: var(--text); }
</style>
</head>
<body>

<header>
  <h1>&#9632; IDS Control Panel</h1>
  <small id="clock"></small>
</header>

<div class="panel">

  <!-- Status card -->
  <div class="card">
    <div class="card-title">System Status</div>
    <div class="status-row">
      <span id="status-badge" class="badge {{ 'badge-running' if running else 'badge-stopped' }}">
        <span class="dot {{ 'dot-running' if running else 'dot-stopped' }}"></span>
        {{ 'RUNNING' if running else 'STOPPED' }}
      </span>
      <span class="uptime" id="uptime-label">{{ uptime }}</span>
    </div>

    <div class="meta-grid" style="margin-top:.9rem;">
      <div class="meta-item">Log file: <span>{{ alert_log }}</span></div>
      <div class="meta-item">IDS script: <span>{{ ids_script }}</span></div>
      <div class="meta-item">Alerts shown: <span>{{ alert_count }}</span></div>
    </div>
  </div>

  <!-- Controls card -->
  <div class="card">
    <div class="card-title">Controls</div>
    <div class="controls">
      <form method="POST" action="/start" style="display:inline">
        <button class="btn-start" {{ 'disabled' if running else '' }}>&#9654; Start IDS</button>
      </form>
      <form method="POST" action="/stop" style="display:inline">
        <button class="btn-stop"  {{ 'disabled' if not running else '' }}>&#9632; Stop IDS</button>
      </form>
      <button class="btn-refresh" onclick="location.reload()">&#8635; Refresh</button>
    </div>
    {% if flash_msg %}
    <p style="margin-top:.7rem; font-size:.82rem; color:{{ 'var(--green)' if flash_ok else 'var(--red)' }}">
      {{ flash_msg }}
    </p>
    {% endif %}
  </div>

  <!-- Alerts card -->
  <div class="card">
    <div class="card-title">Latest Alerts  <span style="font-size:.65rem;">(newest first)</span></div>
    <div class="alert-log" id="alert-log">
      {% if alerts %}
        {% for line in alerts %}
          <div class="alert-line {{ 'crit' if 'CRITICAL' in line or 'ALERT' in line else 'warn' if 'WARN' in line else '' }}">{{ line }}</div>
        {% endfor %}
      {% else %}
        <p>No alerts yet.</p>
      {% endif %}
    </div>
    <p style="font-size:.72rem; color:var(--muted); margin-top:.5rem; font-family:var(--font-mono);">
      Last updated: <span id="last-updated">{{ last_updated }}</span>
    </p>
  </div>

</div>

<footer>IDS Panel &mdash; lightweight monitoring interface</footer>

<script>
  // Live clock
  function tick() {
    document.getElementById('clock').textContent = new Date().toLocaleString();
  }
  tick();
  setInterval(tick, 1000);

  // Auto-refresh alerts + status every 10 s
  async function refreshAlerts() {
    try {
      const [statusRes, alertsRes] = await Promise.all([
        fetch('/status'),
        fetch('/alerts?n=50')
      ]);
      const status = await statusRes.json();
      const alerts = await alertsRes.json();

      // Update badge
      const badge = document.getElementById('status-badge');
      badge.className = 'badge ' + (status.running ? 'badge-running' : 'badge-stopped');
      badge.innerHTML = `<span class="dot ${status.running ? 'dot-running' : 'dot-stopped'}"></span>${status.running ? 'RUNNING' : 'STOPPED'}`;

      // Update uptime
      document.getElementById('uptime-label').textContent = status.uptime || '';

      // Update alert log
      const log = document.getElementById('alert-log');
      if (alerts.alerts && alerts.alerts.length) {
        log.innerHTML = alerts.alerts.map(line => {
          const cls = /CRITICAL|ALERT/.test(line) ? 'crit' : /WARN/.test(line) ? 'warn' : '';
          return `<div class="alert-line ${cls}">${escHtml(line)}</div>`;
        }).join('');
      } else {
        log.innerHTML = '<p>No alerts yet.</p>';
      }

      document.getElementById('last-updated').textContent = new Date().toLocaleTimeString();
    } catch(e) { /* network hiccup — silent */ }
  }

  function escHtml(s) {
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  setInterval(refreshAlerts, 10000);
</script>
</body>
</html>"""


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def _uptime_str() -> str:
    if _start_time and _ids_is_running():
        delta = int((datetime.now() - _start_time).total_seconds())
        h, r = divmod(delta, 3600)
        m, s = divmod(r, 60)
        return f"up {h:02d}:{m:02d}:{s:02d}"
    return _stop_reason


def _render(flash_msg="", flash_ok=True):
    alerts = _read_alerts(50)
    return render_template_string(
        TEMPLATE,
        running      = _ids_is_running(),
        uptime       = _uptime_str(),
        alerts       = alerts,
        alert_count  = len(alerts),
        alert_log    = ALERT_LOG,
        ids_script   = IDS_SCRIPT,
        last_updated = datetime.now().strftime("%H:%M:%S"),
        flash_msg    = flash_msg,
        flash_ok     = flash_ok,
    )


# ──────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────

@app.get("/")
def index():
    return _render()


@app.post("/start")
def start_ids():
    global _ids_process, _ids_thread, _start_time, _stop_reason

    if _ids_is_running():
        return _render("IDS is already running.", flash_ok=False)

    if not os.path.exists(IDS_SCRIPT):
        # ── Demo / stub mode: create a fake log writer so the panel is
        #    fully functional even without the real IDS script.
        return _render(
            f"Script '{IDS_SCRIPT}' not found. Set IDS_SCRIPT env var.",
            flash_ok=False,
        )

    try:
        proc = subprocess.Popen(
            ["python", IDS_SCRIPT],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
            close_fds=True,
        )
        with _lock:
            _ids_process = proc
            _start_time  = datetime.now()
            _stop_reason = "Not started"

        t = threading.Thread(target=_watcher, args=(proc,), daemon=True)
        t.start()
        with _lock:
            _ids_thread = t

        return _render("IDS started successfully.", flash_ok=True)
    except Exception as exc:
        return _render(f"Failed to start IDS: {exc}", flash_ok=False)


@app.post("/stop")
def stop_ids():
    global _ids_process, _stop_reason

    if not _ids_is_running():
        return _render("IDS is not running.", flash_ok=False)

    with _lock:
        proc = _ids_process

    try:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

        with _lock:
            _ids_process = None
            _stop_reason = f"Stopped manually at {datetime.now().strftime('%H:%M:%S')}"

        return _render("IDS stopped.", flash_ok=True)
    except Exception as exc:
        return _render(f"Error stopping IDS: {exc}", flash_ok=False)


@app.get("/status")
def status():
    running = _ids_is_running()
    return jsonify({
        "running": running,
        "uptime":  _uptime_str(),
        "started": _start_time.isoformat() if _start_time and running else None,
    })


@app.get("/alerts")
def alerts():
    n = min(int(request.args.get("n", 50)), MAX_ALERTS)
    return jsonify({
        "alerts":    _read_alerts(n),
        "log_file":  ALERT_LOG,
        "timestamp": datetime.now().isoformat(),
    })


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=False, use_reloader=False)
