"""
IDS Web Control Panel — app.py
================================
Flask web interface to start, stop, and monitor the anomaly-based IDS.

Improvements over v1
---------------------
- /status  now returns IDS phase (training / detecting), alert counts by kind,
  total windows processed, and last-alert timestamp — all parsed live from
  alerts.log so the panel stays accurate even after restarts.
- /alerts  returns structured JSON (timestamp, kind, detail, severity) instead
  of raw lines, enabling the front-end to render rich, colour-coded cards.
- /metrics returns time-series spark data (alert counts per 5-min bucket) for
  the mini chart in the header.
- /clear   POST endpoint to archive and wipe alerts.log from the UI.
- Front-end: full dark terminal aesthetic with a live spark chart, per-kind
  threat badges, severity colouring, and 5-second auto-polling (was 10 s).
- Alert parsing understands every message the updated IDS emits:
    IDS started, IDS entered DETECTION MODE, named attack kinds, IDS stopped.
- Process management: watcher thread updates a _phase variable so the panel
  can show TRAINING / DETECTING / STOPPED correctly without polling the log.
"""

import os
import re
import sys
import threading
import subprocess
import time
import json
import collections
from datetime import datetime, timezone
from flask import Flask, render_template_string, jsonify, request

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────
IDS_SCRIPT  = os.environ.get("IDS_SCRIPT",  "ids_main.py")
ALERT_LOG   = os.environ.get("ALERT_LOG",   "alerts.log")
MAX_ALERTS  = int(os.environ.get("MAX_ALERTS", 200))
HOST        = os.environ.get("HOST", "0.0.0.0")
PORT        = int(os.environ.get("PORT", 5000))

# IDS config constants mirrored here for the UI progress bar
IDS_TRAIN_SECONDS = int(os.environ.get("IDS_TRAIN_SECONDS", 300))

app = Flask(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Process state  (protected by _lock)
# ─────────────────────────────────────────────────────────────────────────────
_lock        = threading.Lock()
_ids_process = None          # subprocess.Popen or None
_start_time  = None          # datetime when IDS last started
_stop_reason = "Never started"
_ids_phase   = "stopped"     # "stopped" | "training" | "detecting"


def _ids_is_running() -> bool:
    with _lock:
        return _ids_process is not None and _ids_process.poll() is None


def _watcher(proc: subprocess.Popen):
    """Daemon thread: cleans up state when IDS process exits for any reason."""
    global _ids_process, _stop_reason, _ids_phase
    proc.wait()
    with _lock:
        if _ids_process is proc:
            _stop_reason = f"Exited (code {proc.returncode})"
            _ids_process = None
            _ids_phase   = "stopped"


# ─────────────────────────────────────────────────────────────────────────────
# Alert log parsing
# ─────────────────────────────────────────────────────────────────────────────

# Matches: [2024-11-01 14:32:05] ALERT: <message>
_ALERT_RE = re.compile(
    r'^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s+ALERT:\s+(.+)$'
)

# Attack kind → severity + display label
# New IDS format:  [YYYY-MM-DD HH:MM:SS] ALERT: <kind> | <detail>
_KIND_META = {
    # Attack alerts (match on kind field before the " | ")
    "SYN flood / port scan": ("critical", "SYN Flood"),
    "UDP flood":             ("critical", "UDP Flood"),
    "ICMP flood":            ("critical", "ICMP Flood"),
    "Volumetric DoS":        ("critical", "Vol. DoS"),
    "Port scan":             ("high",     "Port Scan"),
    # Lifecycle events
    "IDS started":           ("info",     "Started"),
    "IDS entered DETECTION mode": ("info", "Armed"),
    "IDS stopped":           ("info",     "Stopped"),
}


def _classify(kind_str: str) -> tuple[str, str, str]:
    """Map the kind field from the alert line to (kind, severity, label)."""
    for key, (sev, label) in _KIND_META.items():
        if key.lower() in kind_str.lower():
            return key, sev, label
    return kind_str, "medium", "Alert"


def _parse_alert_line(raw: str) -> dict | None:
    """
    Parse one raw log line into a structured alert dict, or None.
    Format: [YYYY-MM-DD HH:MM:SS] ALERT: <kind> | <detail>
    """
    m = _ALERT_RE.match(raw.strip())
    if not m:
        return None
    ts_str, full_body = m.group(1), m.group(2)

    # Split on first " | " to separate kind from detail
    if " | " in full_body:
        kind_str, detail = full_body.split(" | ", 1)
    else:
        kind_str, detail = full_body, ""

    kind, severity, label = _classify(kind_str)

    # Extract numeric rate from detail if present
    rate_m = re.search(r'(?:total_rate|udp_rate|syn_rate|icmp_rate|rate)=([\d.]+)', detail)
    rate   = float(rate_m.group(1)) if rate_m else None

    return {
        "ts":       ts_str,
        "body":     full_body,
        "kind":     kind,
        "severity": severity,
        "label":    label,
        "rate":     rate,
    }


def _read_alerts(n: int = 100) -> list[dict]:
    """Return the last *n* structured alerts, newest first."""
    if not os.path.exists(ALERT_LOG):
        return []
    try:
        with open(ALERT_LOG, "r", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return []
    parsed = []
    for line in reversed(lines):
        a = _parse_alert_line(line)
        if a:
            parsed.append(a)
            if len(parsed) >= n:
                break
    return parsed


def _alert_counts() -> dict:
    """Count alerts by severity across the whole log (for stats bar)."""
    counts = {"critical": 0, "high": 0, "medium": 0, "info": 0}
    if not os.path.exists(ALERT_LOG):
        return counts
    try:
        with open(ALERT_LOG, "r", errors="replace") as fh:
            for line in fh:
                a = _parse_alert_line(line)
                if a and a["severity"] in counts:
                    counts[a["severity"]] += 1
    except OSError:
        pass
    return counts


def _spark_data(buckets: int = 24, bucket_minutes: int = 5) -> list[int]:
    """
    Return alert counts per time bucket (excluding info) for the spark chart.
    buckets=24, bucket_minutes=5 → last 2 hours at 5-min resolution.
    """
    result = [0] * buckets
    if not os.path.exists(ALERT_LOG):
        return result
    now = datetime.now()
    try:
        with open(ALERT_LOG, "r", errors="replace") as fh:
            for line in fh:
                a = _parse_alert_line(line)
                if not a or a["severity"] == "info":
                    continue
                try:
                    ts = datetime.strptime(a["ts"], "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    continue
                diff_minutes = (now - ts).total_seconds() / 60
                idx = int(diff_minutes / bucket_minutes)
                if 0 <= idx < buckets:
                    result[idx] += 1
    except OSError:
        pass
    # Reverse so index 0 = oldest, last = newest
    return list(reversed(result))


def _uptime_str() -> str:
    if _start_time and _ids_is_running():
        secs = int((datetime.now() - _start_time).total_seconds())
        h, r = divmod(secs, 3600)
        m, s = divmod(r, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"
    return ""


def _training_progress() -> float:
    """0.0–1.0 fraction through training phase, or 1.0 if not training."""
    with _lock:
        phase = _ids_phase
        st    = _start_time
    if phase != "training" or st is None:
        return 1.0
    elapsed = (datetime.now() - st).total_seconds()
    return min(elapsed / IDS_TRAIN_SECONDS, 0.99)


# ─────────────────────────────────────────────────────────────────────────────
# HTML Template
# ─────────────────────────────────────────────────────────────────────────────
TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IDS Control Panel</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Barlow+Condensed:wght@300;400;600;700&display=swap');

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --bg:       #070b0f;
  --bg2:      #0d1520;
  --surface:  #111a27;
  --border:   #1e2d40;
  --border2:  #243447;
  --text:     #c8d8e8;
  --muted:    #4a6a85;
  --dim:      #2a4060;

  --green:    #00e5a0;
  --green-d:  rgba(0,229,160,.12);
  --red:      #ff4560;
  --red-d:    rgba(255,69,96,.12);
  --amber:    #ffb300;
  --amber-d:  rgba(255,179,0,.1);
  --blue:     #38b6ff;
  --blue-d:   rgba(56,182,255,.1);
  --violet:   #b060ff;
  --violet-d: rgba(176,96,255,.1);

  --mono: 'Share Tech Mono', monospace;
  --ui:   'Barlow Condensed', sans-serif;
}

html { scroll-behavior: smooth; }

body {
  background: var(--bg);
  color: var(--text);
  font-family: var(--ui);
  font-weight: 400;
  min-height: 100vh;
  padding: 0;
  /* scanline texture */
  background-image: repeating-linear-gradient(
    0deg,
    transparent,
    transparent 2px,
    rgba(0,0,0,.08) 2px,
    rgba(0,0,0,.08) 4px
  );
}

/* ── Layout ──────────────────────────────────── */
.layout {
  max-width: 1100px;
  margin: 0 auto;
  padding: 1.5rem 1.2rem 3rem;
  display: grid;
  grid-template-rows: auto auto 1fr;
  gap: 1.2rem;
}

/* ── Header ──────────────────────────────────── */
.hdr {
  display: grid;
  grid-template-columns: 1fr auto;
  align-items: center;
  gap: 1rem;
  border-bottom: 1px solid var(--border);
  padding-bottom: 1.1rem;
}
.hdr-left { display: flex; align-items: baseline; gap: .9rem; }
.hdr-logo {
  font-family: var(--mono);
  font-size: 1.05rem;
  color: var(--blue);
  letter-spacing: .15em;
  text-transform: uppercase;
  display: flex;
  align-items: center;
  gap: .5rem;
}
.hdr-logo::before {
  content: '';
  display: inline-block;
  width: 10px; height: 10px;
  border: 2px solid var(--blue);
  border-radius: 50%;
  box-shadow: 0 0 8px var(--blue);
  animation: pulse-ring 2s ease-in-out infinite;
}
@keyframes pulse-ring {
  0%,100% { box-shadow: 0 0 4px var(--blue); }
  50%      { box-shadow: 0 0 14px var(--blue), 0 0 30px rgba(56,182,255,.3); }
}
.hdr-sub {
  font-family: var(--mono);
  font-size: .7rem;
  color: var(--muted);
}
.hdr-right {
  font-family: var(--mono);
  font-size: .75rem;
  color: var(--muted);
  text-align: right;
  line-height: 1.6;
}
#clock { color: var(--text); }

/* ── Spark row ───────────────────────────────── */
.spark-row {
  display: grid;
  grid-template-columns: 1fr 1fr 1fr 1fr auto;
  gap: .8rem;
  align-items: center;
}
.stat-pill {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: .55rem .9rem;
  display: flex;
  flex-direction: column;
  gap: .15rem;
}
.stat-pill .sp-label {
  font-size: .62rem;
  letter-spacing: .12em;
  text-transform: uppercase;
  color: var(--muted);
  font-family: var(--mono);
}
.stat-pill .sp-val {
  font-size: 1.5rem;
  font-weight: 700;
  line-height: 1;
  font-family: var(--ui);
}
.sp-crit  { color: var(--red); }
.sp-high  { color: var(--amber); }
.sp-med   { color: var(--violet); }
.sp-info  { color: var(--muted); }

#spark-wrap {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: .55rem .9rem;
  min-width: 200px;
}
#spark-wrap .sp-label {
  font-size: .62rem;
  letter-spacing: .12em;
  text-transform: uppercase;
  color: var(--muted);
  font-family: var(--mono);
  margin-bottom: .35rem;
}
#spark-canvas { display: block; width: 100%; height: 40px; }

/* ── Main grid ───────────────────────────────── */
.main-grid {
  display: grid;
  grid-template-columns: 280px 1fr;
  gap: 1.2rem;
  align-items: start;
}

/* ── Card ────────────────────────────────────── */
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 6px;
  overflow: hidden;
}
.card-head {
  padding: .65rem 1rem;
  border-bottom: 1px solid var(--border);
  font-size: .65rem;
  letter-spacing: .15em;
  text-transform: uppercase;
  color: var(--muted);
  font-family: var(--mono);
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.card-body { padding: 1rem; }

/* ── Status panel (left column) ─────────────── */
.status-block { margin-bottom: 1rem; }

.phase-badge {
  display: inline-flex;
  align-items: center;
  gap: .5rem;
  padding: .4rem .9rem;
  border-radius: 3px;
  font-family: var(--mono);
  font-size: .8rem;
  letter-spacing: .08em;
  font-weight: 600;
  text-transform: uppercase;
  border: 1px solid;
  width: 100%;
  justify-content: center;
  margin-bottom: .8rem;
}
.phase-stopped  { background: rgba(255,69,96,.08);   color: var(--red);   border-color: rgba(255,69,96,.3);  }
.phase-training { background: rgba(255,179,0,.08);   color: var(--amber); border-color: rgba(255,179,0,.3);  }
.phase-detecting{ background: rgba(0,229,160,.08);   color: var(--green); border-color: rgba(0,229,160,.3);  }

.dot {
  width: 7px; height: 7px;
  border-radius: 50%;
  flex-shrink: 0;
}
.dot-stopped  { background: var(--red); }
.dot-training { background: var(--amber);
  animation: blink .9s step-end infinite; }
.dot-detecting{ background: var(--green);
  box-shadow: 0 0 6px var(--green); }
@keyframes blink { 50% { opacity: 0; } }

/* Training progress bar */
.progress-wrap {
  margin-bottom: .9rem;
  display: none;
}
.progress-wrap.visible { display: block; }
.progress-label {
  display: flex;
  justify-content: space-between;
  font-size: .68rem;
  color: var(--muted);
  font-family: var(--mono);
  margin-bottom: .3rem;
}
.progress-track {
  height: 4px;
  background: var(--border);
  border-radius: 2px;
  overflow: hidden;
}
.progress-bar {
  height: 100%;
  background: linear-gradient(90deg, var(--amber), var(--blue));
  border-radius: 2px;
  transition: width .8s ease;
}

/* Meta rows */
.meta-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: .3rem 0;
  border-bottom: 1px solid var(--border);
  font-size: .78rem;
}
.meta-row:last-child { border-bottom: none; }
.meta-key { color: var(--muted); font-family: var(--mono); font-size: .7rem; }
.meta-val { color: var(--text);  font-family: var(--mono); font-size: .75rem; text-align: right; }
.meta-val.good  { color: var(--green); }
.meta-val.bad   { color: var(--red);   }
.meta-val.warn  { color: var(--amber); }

/* Controls */
.btn-row {
  display: flex;
  flex-direction: column;
  gap: .6rem;
  margin-top: .8rem;
}
.btn {
  width: 100%;
  padding: .6rem 1rem;
  border: 1px solid;
  border-radius: 3px;
  font-family: var(--ui);
  font-size: .9rem;
  font-weight: 600;
  letter-spacing: .06em;
  text-transform: uppercase;
  cursor: pointer;
  transition: opacity .12s, box-shadow .12s;
}
.btn:disabled { opacity: .3; cursor: not-allowed; }
.btn:not(:disabled):hover { opacity: .8; }

.btn-start {
  background: var(--green-d);
  color: var(--green);
  border-color: rgba(0,229,160,.4);
}
.btn-start:not(:disabled):hover {
  box-shadow: 0 0 14px rgba(0,229,160,.25);
}
.btn-stop {
  background: var(--red-d);
  color: var(--red);
  border-color: rgba(255,69,96,.4);
}
.btn-stop:not(:disabled):hover {
  box-shadow: 0 0 14px rgba(255,69,96,.2);
}
.btn-clear {
  background: transparent;
  color: var(--muted);
  border-color: var(--border);
  font-size: .78rem;
}
.btn-clear:not(:disabled):hover { color: var(--text); border-color: var(--border2); }

.flash {
  margin-top: .6rem;
  font-size: .75rem;
  font-family: var(--mono);
  padding: .4rem .6rem;
  border-radius: 3px;
  border: 1px solid;
}
.flash-ok  { color: var(--green); background: var(--green-d); border-color: rgba(0,229,160,.3); }
.flash-err { color: var(--red);   background: var(--red-d);   border-color: rgba(255,69,96,.3); }

/* ── Alert feed (right column) ──────────────── */
.alert-feed {
  max-height: calc(100vh - 260px);
  min-height: 300px;
  overflow-y: auto;
  padding: .5rem;
  scrollbar-width: thin;
  scrollbar-color: var(--border) transparent;
}
.alert-feed::-webkit-scrollbar { width: 4px; }
.alert-feed::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

.alert-card {
  display: grid;
  grid-template-columns: auto 1fr auto;
  gap: .5rem .8rem;
  align-items: start;
  padding: .65rem .75rem;
  border-radius: 4px;
  border: 1px solid var(--border);
  margin-bottom: .45rem;
  font-family: var(--mono);
  font-size: .73rem;
  background: var(--bg2);
  transition: border-color .15s;
  animation: slide-in .2s ease;
}
@keyframes slide-in {
  from { opacity:0; transform: translateY(-4px); }
  to   { opacity:1; transform: translateY(0); }
}
.alert-card:hover { border-color: var(--border2); }

.alert-card.sev-critical { border-left: 3px solid var(--red);    background: rgba(255,69,96,.04);  }
.alert-card.sev-high     { border-left: 3px solid var(--amber);  background: rgba(255,179,0,.03);  }
.alert-card.sev-medium   { border-left: 3px solid var(--violet); background: rgba(176,96,255,.03); }
.alert-card.sev-info     { border-left: 3px solid var(--dim);    background: transparent; }

.ac-icon { font-size: 1rem; line-height: 1; padding-top: .05rem; }
.ac-body { min-width: 0; }
.ac-kind { font-size: .7rem; font-weight: 700; letter-spacing: .06em; text-transform: uppercase; margin-bottom: .2rem; }
.ac-kind.sev-critical { color: var(--red);    }
.ac-kind.sev-high     { color: var(--amber);  }
.ac-kind.sev-medium   { color: var(--violet); }
.ac-kind.sev-info     { color: var(--muted);  }
.ac-detail { color: var(--muted); line-height: 1.4; font-size: .68rem; word-break: break-all; }
.ac-ts { color: var(--dim); font-size: .65rem; white-space: nowrap; text-align: right; }

.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 200px;
  color: var(--dim);
  font-family: var(--mono);
  font-size: .78rem;
  gap: .4rem;
}
.empty-icon { font-size: 2rem; opacity: .3; }

/* Feed controls */
.feed-controls {
  display: flex;
  align-items: center;
  gap: .6rem;
}
.fc-dot {
  width: 6px; height: 6px;
  border-radius: 50%;
  background: var(--green);
  box-shadow: 0 0 5px var(--green);
  animation: blink .9s step-end infinite;
}
.fc-dot.paused { background: var(--dim); box-shadow: none; animation: none; }
.fc-count { font-size: .68rem; color: var(--muted); font-family: var(--mono); }
.fc-btn {
  background: none;
  border: 1px solid var(--border);
  border-radius: 3px;
  color: var(--muted);
  font-size: .68rem;
  font-family: var(--mono);
  padding: .15rem .5rem;
  cursor: pointer;
}
.fc-btn:hover { color: var(--text); border-color: var(--border2); }

/* Filter tabs */
.filter-tabs {
  display: flex;
  gap: .3rem;
}
.ftab {
  background: none;
  border: 1px solid var(--border);
  border-radius: 2px;
  color: var(--muted);
  font-size: .65rem;
  font-family: var(--mono);
  padding: .15rem .45rem;
  cursor: pointer;
  letter-spacing: .05em;
  text-transform: uppercase;
  transition: all .12s;
}
.ftab.active { background: var(--border2); color: var(--text); border-color: var(--border2); }

/* ── Responsive ──────────────────────────────── */
@media (max-width: 720px) {
  .main-grid { grid-template-columns: 1fr; }
  .spark-row { grid-template-columns: 1fr 1fr; }
  #spark-wrap { grid-column: 1 / -1; }
}
</style>
</head>
<body>
<div class="layout">

  <!-- ── Header ──────────────────────────────── -->
  <header class="hdr">
    <div class="hdr-left">
      <div class="hdr-logo">IDS Console</div>
      <span class="hdr-sub">anomaly detection system</span>
    </div>
    <div class="hdr-right">
      <div id="clock"></div>
      <div>{{ alert_log }}</div>
    </div>
  </header>

  <!-- ── Spark / stat row ─────────────────────── -->
  <div class="spark-row">
    <div class="stat-pill">
      <span class="sp-label">Critical</span>
      <span class="sp-val sp-crit" id="cnt-critical">{{ counts.critical }}</span>
    </div>
    <div class="stat-pill">
      <span class="sp-label">High</span>
      <span class="sp-val sp-high" id="cnt-high">{{ counts.high }}</span>
    </div>
    <div class="stat-pill">
      <span class="sp-label">Medium</span>
      <span class="sp-val sp-med" id="cnt-medium">{{ counts.medium }}</span>
    </div>
    <div class="stat-pill">
      <span class="sp-label">Info</span>
      <span class="sp-val sp-info" id="cnt-info">{{ counts.info }}</span>
    </div>
    <div id="spark-wrap">
      <div class="sp-label">Alerts / 5 min — last 2 h</div>
      <canvas id="spark-canvas" width="200" height="40"></canvas>
    </div>
  </div>

  <!-- ── Main grid ────────────────────────────── -->
  <div class="main-grid">

    <!-- Left: status + controls -->
    <div>
      <div class="card">
        <div class="card-head">System</div>
        <div class="card-body">
          <div class="status-block">
            <div id="phase-badge" class="phase-badge phase-{{ phase }}">
              <span class="dot dot-{{ phase }}"></span>
              <span id="phase-text">{{ phase_label }}</span>
            </div>

            <!-- Training progress bar (visible only during training) -->
            <div id="progress-wrap" class="progress-wrap {{ 'visible' if phase == 'training' else '' }}">
              <div class="progress-label">
                <span>Baseline training</span>
                <span id="progress-pct">{{ "%.0f"|format(train_progress * 100) }}%</span>
              </div>
              <div class="progress-track">
                <div id="progress-bar" class="progress-bar"
                     style="width: {{ "%.1f"|format(train_progress * 100) }}%"></div>
              </div>
            </div>

            <div class="meta-row">
              <span class="meta-key">uptime</span>
              <span class="meta-val" id="uptime">{{ uptime or '—' }}</span>
            </div>
            <div class="meta-row">
              <span class="meta-key">script</span>
              <span class="meta-val">{{ ids_script }}</span>
            </div>
            <div class="meta-row">
              <span class="meta-key">log</span>
              <span class="meta-val">{{ alert_log }}</span>
            </div>
            <div class="meta-row">
              <span class="meta-key">pid</span>
              <span class="meta-val" id="pid-val">{{ pid or '—' }}</span>
            </div>
            <div class="meta-row">
              <span class="meta-key">last alert</span>
              <span class="meta-val warn" id="last-alert-ts">{{ last_alert_ts or '—' }}</span>
            </div>
          </div>

          <div class="btn-row">
            <form method="POST" action="/start" style="margin:0">
              <button class="btn btn-start" {{ 'disabled' if running else '' }}>
                ▶ Start IDS
              </button>
            </form>
            <form method="POST" action="/stop" style="margin:0">
              <button class="btn btn-stop" {{ 'disabled' if not running else '' }}>
                ■ Stop IDS
              </button>
            </form>
            <form method="POST" action="/clear" style="margin:0">
              <button class="btn btn-clear">⊘ Clear alert log</button>
            </form>
          </div>

          {% if flash_msg %}
          <div class="flash {{ 'flash-ok' if flash_ok else 'flash-err' }}">
            {{ flash_msg }}
          </div>
          {% endif %}
        </div>
      </div>
    </div>

    <!-- Right: alert feed -->
    <div class="card" style="display:flex; flex-direction:column;">
      <div class="card-head">
        <div class="feed-controls">
          <div class="fc-dot" id="live-dot"></div>
          <span class="fc-count" id="feed-count">{{ alerts|length }} alerts</span>
          <button class="fc-btn" id="pause-btn" onclick="togglePause()">Pause</button>
        </div>
        <div class="filter-tabs">
          <button class="ftab active" onclick="setFilter('all',this)">All</button>
          <button class="ftab" onclick="setFilter('critical',this)">Critical</button>
          <button class="ftab" onclick="setFilter('high',this)">High</button>
          <button class="ftab" onclick="setFilter('medium',this)">Medium</button>
        </div>
      </div>

      <div class="alert-feed" id="alert-feed">
        {% if alerts %}
          {% for a in alerts %}
          <div class="alert-card sev-{{ a.severity }}" data-sev="{{ a.severity }}">
            <div class="ac-icon">{{ {'critical':'⚠', 'high':'▲', 'medium':'◆', 'info':'·'}[a.severity] }}</div>
            <div class="ac-body">
              <div class="ac-kind sev-{{ a.severity }}">{{ a.label }}</div>
              <div class="ac-detail">{{ a.body }}</div>
            </div>
            <div class="ac-ts">{{ a.ts[11:] }}</div>
          </div>
          {% endfor %}
        {% else %}
          <div class="empty-state">
            <div class="empty-icon">◎</div>
            <div>No alerts yet</div>
          </div>
        {% endif %}
      </div>
    </div>

  </div><!-- /main-grid -->
</div><!-- /layout -->

<script>
// ── Clock ───────────────────────────────────────────────────────────────────
function tick() {
  const d = new Date();
  document.getElementById('clock').textContent =
    d.toLocaleDateString() + ' ' + d.toLocaleTimeString();
}
tick(); setInterval(tick, 1000);

// ── Spark chart ─────────────────────────────────────────────────────────────
let sparkData = {{ spark | tojson }};

function drawSpark(data) {
  const canvas = document.getElementById('spark-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.offsetWidth || 200;
  const H = 40;
  canvas.width = W; canvas.height = H;
  ctx.clearRect(0, 0, W, H);
  const max = Math.max(...data, 1);
  const bw  = W / data.length;
  data.forEach((v, i) => {
    const h = (v / max) * (H - 4);
    const x = i * bw;
    const intense = v > 0 ? Math.min(v / max, 1) : 0;
    ctx.fillStyle = intense > 0.6
      ? `rgba(255,69,96,${0.4 + intense * 0.5})`
      : intense > 0.2
        ? `rgba(255,179,0,${0.3 + intense * 0.5})`
        : `rgba(56,182,255,${0.15 + intense * 0.4})`;
    ctx.fillRect(x + 1, H - h, bw - 2, h);
  });
}
drawSpark(sparkData);
window.addEventListener('resize', () => drawSpark(sparkData));

// ── Filter ──────────────────────────────────────────────────────────────────
let activeFilter = 'all';
function setFilter(f, el) {
  activeFilter = f;
  document.querySelectorAll('.ftab').forEach(b => b.classList.remove('active'));
  el.classList.add('active');
  applyFilter();
}
function applyFilter() {
  document.querySelectorAll('#alert-feed .alert-card').forEach(card => {
    card.style.display =
      (activeFilter === 'all' || card.dataset.sev === activeFilter) ? '' : 'none';
  });
}

// ── Pause ───────────────────────────────────────────────────────────────────
let paused = false;
function togglePause() {
  paused = !paused;
  const btn = document.getElementById('pause-btn');
  const dot = document.getElementById('live-dot');
  btn.textContent = paused ? 'Resume' : 'Pause';
  dot.classList.toggle('paused', paused);
}

// ── Severity icon map ────────────────────────────────────────────────────────
const SEV_ICON = { critical: '⚠', high: '▲', medium: '◆', info: '·' };

// ── Build alert card HTML ────────────────────────────────────────────────────
function buildCard(a) {
  const icon = SEV_ICON[a.severity] || '·';
  const ts   = a.ts ? a.ts.slice(11) : '';
  return `<div class="alert-card sev-${esc(a.severity)}" data-sev="${esc(a.severity)}">
    <div class="ac-icon">${icon}</div>
    <div class="ac-body">
      <div class="ac-kind sev-${esc(a.severity)}">${esc(a.label)}</div>
      <div class="ac-detail">${esc(a.body)}</div>
    </div>
    <div class="ac-ts">${esc(ts)}</div>
  </div>`;
}

function esc(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}

// ── Polling ──────────────────────────────────────────────────────────────────
let lastTs = '';    // ts of most recent alert seen

async function poll() {
  try {
    const [sRes, aRes, mRes] = await Promise.all([
      fetch('/status'),
      fetch('/alerts?n=100'),
      fetch('/metrics'),
    ]);
    const status  = await sRes.json();
    const aData   = await aRes.json();
    const metrics = await mRes.json();

    // ── Phase badge ───────────────────────────────────────────────────────
    const badge = document.getElementById('phase-badge');
    const ptext = document.getElementById('phase-text');
    const upEl  = document.getElementById('uptime');
    const pidEl = document.getElementById('pid-val');

    badge.className = 'phase-badge phase-' + status.phase;
    badge.querySelector('.dot').className = 'dot dot-' + status.phase;
    const LABELS = { stopped:'Stopped', training:'Training…', detecting:'Detecting' };
    ptext.textContent = LABELS[status.phase] || status.phase;
    upEl.textContent = status.uptime || '—';
    pidEl.textContent = status.pid || '—';

    // ── Training progress bar ─────────────────────────────────────────────
    const pw  = document.getElementById('progress-wrap');
    const pb  = document.getElementById('progress-bar');
    const pct = document.getElementById('progress-pct');
    if (status.phase === 'training') {
      pw.classList.add('visible');
      const p = Math.min((status.train_progress || 0) * 100, 99);
      pb.style.width = p.toFixed(1) + '%';
      pct.textContent = p.toFixed(0) + '%';
    } else {
      pw.classList.remove('visible');
    }

    // ── Stat pills ────────────────────────────────────────────────────────
    const c = metrics.counts || {};
    ['critical','high','medium','info'].forEach(k => {
      const el = document.getElementById('cnt-' + k);
      if (el) el.textContent = c[k] ?? 0;
    });

    // ── Spark ─────────────────────────────────────────────────────────────
    if (metrics.spark) { sparkData = metrics.spark; drawSpark(sparkData); }

    // ── Last alert ts ──────────────────────────────────────────────────────
    const lts = document.getElementById('last-alert-ts');
    if (aData.alerts && aData.alerts.length) {
      const first = aData.alerts[0];
      lts.textContent = first.ts ? first.ts.slice(11) : '—';
    }

    // ── Alert feed ────────────────────────────────────────────────────────
    if (!paused && aData.alerts) {
      const feed    = document.getElementById('alert-feed');
      const cnt     = document.getElementById('feed-count');
      const newAlerts = aData.alerts.filter(a => a.severity !== 'info' || true);

      // Only re-render if newest alert changed
      const newestTs = newAlerts.length ? newAlerts[0].ts : '';
      if (newestTs !== lastTs) {
        lastTs = newestTs;
        if (newAlerts.length === 0) {
          feed.innerHTML = `<div class="empty-state"><div class="empty-icon">◎</div><div>No alerts yet</div></div>`;
        } else {
          feed.innerHTML = newAlerts.map(buildCard).join('');
          applyFilter();
        }
        cnt.textContent = newAlerts.length + ' alert' + (newAlerts.length !== 1 ? 's' : '');
      }
    }

  } catch(e) { /* network blip — stay silent */ }
}

poll();
setInterval(poll, 5000);
</script>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _current_phase() -> str:
    """
    Derive the IDS phase from process state + alert log.
    Priority: process state first, then fall back to log content.
    """
    with _lock:
        phase = _ids_phase
        proc  = _ids_process

    if not _ids_is_running():
        return "stopped"

    # If the IDS wrote a DETECTION MODE line, it has graduated from training
    if os.path.exists(ALERT_LOG):
        try:
            with open(ALERT_LOG, "r", errors="replace") as fh:
                content = fh.read()
            if "DETECTION MODE" in content or "entered DETECTION" in content:
                return "detecting"
        except OSError:
            pass

    return phase  # "training" by default while running


def _last_alert_ts() -> str | None:
    """Return the timestamp string of the most recent non-info alert."""
    alerts = _read_alerts(10)
    for a in alerts:
        if a["severity"] != "info":
            return a["ts"][11:]   # HH:MM:SS portion
    return None


def _render(flash_msg="", flash_ok=True):
    running  = _ids_is_running()
    phase    = _current_phase()
    alerts   = _read_alerts(100)
    counts   = _alert_counts()
    spark    = _spark_data()

    phase_labels = {
        "stopped":   "Stopped",
        "training":  "Training…",
        "detecting": "Detecting",
    }

    with _lock:
        proc = _ids_process
        pid  = proc.pid if proc else None

    return render_template_string(
        TEMPLATE,
        running        = running,
        phase          = phase,
        phase_label    = phase_labels.get(phase, phase.title()),
        uptime         = _uptime_str(),
        pid            = pid,
        alerts         = alerts,
        counts         = counts,
        spark          = spark,
        alert_log      = ALERT_LOG,
        ids_script     = IDS_SCRIPT,
        last_alert_ts  = _last_alert_ts(),
        train_progress = _training_progress(),
        flash_msg      = flash_msg,
        flash_ok       = flash_ok,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/")
def index():
    return _render()


@app.post("/start")
def start_ids():
    global _ids_process, _ids_thread, _start_time, _stop_reason, _ids_phase

    if _ids_is_running():
        return _render("IDS is already running.", flash_ok=False)

    if not os.path.exists(IDS_SCRIPT):
        return _render(
            f"Script not found: {IDS_SCRIPT!r} — set IDS_SCRIPT env var.",
            flash_ok=False,
        )

    try:
        proc = subprocess.Popen(
            [sys.executable, IDS_SCRIPT],
            stdout = subprocess.DEVNULL,
            stderr = subprocess.DEVNULL,
            close_fds = True,
        )
        with _lock:
            _ids_process = proc
            _start_time  = datetime.now()
            _stop_reason = ""
            _ids_phase   = "training"

        t = threading.Thread(target=_watcher, args=(proc,), daemon=True)
        t.start()
        with _lock:
            _ids_thread = t

        return _render("IDS started — baseline training in progress.", flash_ok=True)
    except Exception as exc:
        return _render(f"Failed to start IDS: {exc}", flash_ok=False)


@app.post("/stop")
def stop_ids():
    global _ids_process, _stop_reason, _ids_phase

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
            _ids_phase   = "stopped"
            _stop_reason = f"Stopped at {datetime.now().strftime('%H:%M:%S')}"

        return _render("IDS stopped.", flash_ok=True)
    except Exception as exc:
        return _render(f"Error stopping IDS: {exc}", flash_ok=False)


@app.post("/clear")
def clear_log():
    """Archive alerts.log → alerts.log.bak and start fresh."""
    try:
        if os.path.exists(ALERT_LOG):
            bak = ALERT_LOG + ".bak"
            os.replace(ALERT_LOG, bak)
        return _render(f"Alert log cleared (backup: {ALERT_LOG}.bak)", flash_ok=True)
    except OSError as exc:
        return _render(f"Could not clear log: {exc}", flash_ok=False)


@app.get("/status")
def status():
    running  = _ids_is_running()
    phase    = _current_phase()
    with _lock:
        proc = _ids_process
        st   = _start_time

    return jsonify({
        "running":        running,
        "phase":          phase,
        "uptime":         _uptime_str(),
        "started":        st.isoformat() if st and running else None,
        "pid":            proc.pid if proc else None,
        "train_progress": _training_progress(),
        "stop_reason":    _stop_reason,
    })


@app.get("/alerts")
def alerts_route():
    n = min(int(request.args.get("n", 100)), MAX_ALERTS)
    return jsonify({
        "alerts":    _read_alerts(n),
        "log_file":  ALERT_LOG,
        "timestamp": datetime.now().isoformat(),
    })


@app.get("/metrics")
def metrics():
    return jsonify({
        "counts": _alert_counts(),
        "spark":  _spark_data(),
    })


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=False, use_reloader=False)
