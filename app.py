"""
app.py  —  IDS Web Control Panel

Run:  python3 app.py
Open: http://localhost:5000

The IDS engine (ids_main.py) is launched with sudo so it can open a raw
packet socket.  The panel itself does not need root.
"""

import os
import re
import sys
import time
import threading
import subprocess
import collections
from datetime import datetime
from flask import Flask, render_template_string, jsonify, request

# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────
IDS_SCRIPT        = os.environ.get("IDS_SCRIPT",  "ids_main.py")
ALERT_LOG         = os.environ.get("ALERT_LOG",   "alerts.log")
IDS_BASELINE_SECS = int(os.environ.get("IDS_BASELINE_SECS", 60))
HOST              = os.environ.get("HOST", "0.0.0.0")
PORT              = int(os.environ.get("PORT", 5000))

app = Flask(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Process state  (all reads/writes under _lock)
# ─────────────────────────────────────────────────────────────────────────────
_lock        = threading.Lock()
_proc        = None        # subprocess.Popen or None
_start_time  = None        # datetime when IDS last started
_stop_reason = "Not started yet"


def _running() -> bool:
    with _lock:
        return _proc is not None and _proc.poll() is None


def _watcher(proc: subprocess.Popen) -> None:
    """Daemon thread: waits for process exit and cleans up state."""
    global _proc, _stop_reason
    proc.wait()
    with _lock:
        if _proc is proc:
            _stop_reason = "Exited (code %d)" % proc.returncode
            _proc = None


def _uptime() -> str:
    with _lock:
        st = _start_time
    if st and _running():
        s = int((datetime.now() - st).total_seconds())
        h, r = divmod(s, 3600)
        m, sec = divmod(r, 60)
        return "%02d:%02d:%02d" % (h, m, sec)
    return ""


# ─────────────────────────────────────────────────────────────────────────────
# Phase detection
# The ONLY source of truth for the current phase is alerts.log.
# This avoids the race condition where in-memory state diverges from reality.
# Progress-bar percentage is computed from the start timestamp.
# ─────────────────────────────────────────────────────────────────────────────

def _phase_from_log() -> str:
    """
    Derive the IDS phase by reading alerts.log.
    Returns 'stopped' | 'baseline' | 'detecting'.
    """
    if not _running():
        return "stopped"

    if not os.path.exists(ALERT_LOG):
        return "baseline"   # running but no log yet -> still starting up

    try:
        with open(ALERT_LOG, errors="replace") as fh:
            content = fh.read()
    except OSError:
        return "baseline"

    # If the log contains a "DETECTION mode" line the IDS has graduated
    if "DETECTION mode" in content:
        return "detecting"

    return "baseline"


def _baseline_pct() -> float:
    """
    Returns 0.0–0.99 fraction through the baseline phase.
    Returns 1.0 once detection has started.
    """
    if _phase_from_log() != "baseline":
        return 1.0
    with _lock:
        st = _start_time
    if st is None:
        return 0.0
    elapsed = (datetime.now() - st).total_seconds()
    return min(elapsed / IDS_BASELINE_SECS, 0.99)


# ─────────────────────────────────────────────────────────────────────────────
# Alert parsing
# ─────────────────────────────────────────────────────────────────────────────

_RE = re.compile(r'^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s+ALERT:\s+(.+)$')

_KINDS = {
    "SYN flood":        ("critical", "SYN Flood",  "#ff4560"),
    "UDP flood":        ("critical", "UDP Flood",  "#ff4560"),
    "ICMP flood":       ("critical", "ICMP Flood", "#ff4560"),
    "Volumetric DoS":   ("critical", "Vol. DoS",   "#ff4560"),
    "Port scan":        ("high",     "Port Scan",  "#ffb300"),
    "IDS started":      ("info",     "Started",    "#4a6a85"),
    "DETECTION mode":   ("info",     "Armed",      "#4a6a85"),
    "IDS stopped":      ("info",     "Stopped",    "#4a6a85"),
}


def _parse(raw: str):
    m = _RE.match(raw.strip())
    if not m:
        return None
    ts, body = m.group(1), m.group(2)
    kind_str = body.split(" | ")[0] if " | " in body else body
    detail   = body.split(" | ", 1)[1] if " | " in body else ""

    sev, label, color = "medium", "Alert", "#b060ff"
    for key, (s, l, c) in _KINDS.items():
        if key.lower() in kind_str.lower():
            sev, label, color = s, l, c
            break

    return {
        "ts": ts, "body": body, "kind": kind_str,
        "severity": sev, "label": label, "color": color, "detail": detail,
    }


def _read_alerts(n: int = 100):
    if not os.path.exists(ALERT_LOG):
        return []
    try:
        with open(ALERT_LOG, errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return []
    out = []
    for line in reversed(lines):
        a = _parse(line)
        if a:
            out.append(a)
            if len(out) >= n:
                break
    return out


def _counts():
    c = {"critical": 0, "high": 0, "medium": 0, "info": 0}
    if not os.path.exists(ALERT_LOG):
        return c
    try:
        with open(ALERT_LOG, errors="replace") as fh:
            for line in fh:
                a = _parse(line)
                if a and a["severity"] in c:
                    c[a["severity"]] += 1
    except OSError:
        pass
    return c


def _spark(buckets: int = 24, mins: int = 5):
    result = [0] * buckets
    if not os.path.exists(ALERT_LOG):
        return result
    now = datetime.now()
    try:
        with open(ALERT_LOG, errors="replace") as fh:
            for line in fh:
                a = _parse(line)
                if not a or a["severity"] == "info":
                    continue
                try:
                    ts  = datetime.strptime(a["ts"], "%Y-%m-%d %H:%M:%S")
                    idx = int((now - ts).total_seconds() / 60 / mins)
                    if 0 <= idx < buckets:
                        result[idx] += 1
                except ValueError:
                    pass
    except OSError:
        pass
    return list(reversed(result))


# ─────────────────────────────────────────────────────────────────────────────
# HTML Template
# ─────────────────────────────────────────────────────────────────────────────

TMPL = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IDS Panel</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#06090d;--bg2:#0b1017;--surf:#0f1923;--brd:#1a2535;--brd2:#243040;
  --txt:#b8cfe0;--mut:#3a5570;--dim:#1e3045;
  --grn:#00d48a;--red:#ff3d57;--amb:#f59e0b;--blu:#38b2ff;--vio:#a855f7;
  --font:'IBM Plex Mono',monospace;--ui:'IBM Plex Sans',sans-serif;
}
html,body{height:100%;background:var(--bg);color:var(--txt);font-family:var(--ui)}
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 3px,rgba(0,0,0,.06) 3px,rgba(0,0,0,.06) 4px);pointer-events:none;z-index:9999}

.wrap{max-width:1120px;margin:0 auto;padding:1.5rem 1rem 4rem;display:grid;gap:1.1rem}

/* Header */
.hdr{display:flex;justify-content:space-between;align-items:center;padding-bottom:1rem;border-bottom:1px solid var(--brd)}
.logo{font-family:var(--font);font-size:1rem;color:var(--blu);letter-spacing:.15em;display:flex;align-items:center;gap:.6rem}
.logo-ring{width:10px;height:10px;border-radius:50%;border:2px solid var(--blu);box-shadow:0 0 10px var(--blu);animation:glow 2s ease-in-out infinite}
@keyframes glow{0%,100%{box-shadow:0 0 4px var(--blu)}50%{box-shadow:0 0 18px var(--blu),0 0 35px rgba(56,178,255,.3)}}
.hdr-right{font-family:var(--font);font-size:.72rem;color:var(--mut);text-align:right;line-height:1.7}
#clock{color:var(--txt)}

/* Stat pills */
.pills{display:grid;grid-template-columns:repeat(4,1fr) 240px;gap:.8rem;align-items:stretch}
.pill{background:var(--surf);border:1px solid var(--brd);border-radius:6px;padding:.6rem .9rem}
.pill-label{font-family:var(--font);font-size:.6rem;letter-spacing:.12em;text-transform:uppercase;color:var(--mut);margin-bottom:.2rem}
.pill-val{font-size:1.6rem;font-weight:600;line-height:1}
.crit{color:var(--red)}.high{color:var(--amb)}.med{color:var(--vio)}.info-c{color:var(--mut)}
.spark-wrap{background:var(--surf);border:1px solid var(--brd);border-radius:6px;padding:.6rem .9rem}
#spark{display:block;width:100%;height:42px;margin-top:.3rem}

/* Main grid */
.main{display:grid;grid-template-columns:280px 1fr;gap:1.1rem;align-items:start}

/* Card */
.card{background:var(--surf);border:1px solid var(--brd);border-radius:6px;overflow:hidden}
.card-hdr{padding:.6rem 1rem;border-bottom:1px solid var(--brd);font-family:var(--font);font-size:.6rem;letter-spacing:.14em;text-transform:uppercase;color:var(--mut);display:flex;justify-content:space-between;align-items:center}
.card-body{padding:1rem}

/* Phase badge */
.badge{display:flex;align-items:center;gap:.5rem;padding:.4rem .8rem;border-radius:4px;font-family:var(--font);font-size:.75rem;letter-spacing:.06em;text-transform:uppercase;border:1px solid;margin-bottom:.9rem;justify-content:center}
.badge-stopped  {background:rgba(255,61,87,.07);color:var(--red);border-color:rgba(255,61,87,.3)}
.badge-baseline {background:rgba(245,158,11,.07);color:var(--amb);border-color:rgba(245,158,11,.3)}
.badge-detecting{background:rgba(0,212,138,.07);color:var(--grn);border-color:rgba(0,212,138,.3)}
.dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.dot-stopped  {background:var(--red)}
.dot-baseline {background:var(--amb);animation:blink .8s step-end infinite}
.dot-detecting{background:var(--grn);box-shadow:0 0 7px var(--grn)}
@keyframes blink{50%{opacity:0}}

/* Baseline progress bar */
.prog-wrap{margin-bottom:.9rem}
.prog-hidden{display:none}
.prog-labels{display:flex;justify-content:space-between;font-family:var(--font);font-size:.65rem;color:var(--mut);margin-bottom:.25rem}
.prog-track{height:4px;background:var(--dim);border-radius:2px;overflow:hidden}
.prog-bar{height:100%;background:linear-gradient(90deg,var(--amb),var(--blu));border-radius:2px;transition:width .8s}

/* Meta table */
.meta{width:100%;border-collapse:collapse;font-family:var(--font);font-size:.7rem;margin-bottom:.9rem}
.meta td{padding:.3rem 0;border-bottom:1px solid var(--brd)}
.meta td:first-child{color:var(--mut);width:45%}
.meta td:last-child{color:var(--txt);text-align:right}

/* Buttons */
.btns{display:flex;flex-direction:column;gap:.6rem}
.btn{width:100%;padding:.55rem;border:1px solid;border-radius:4px;font-family:var(--ui);font-size:.85rem;font-weight:600;letter-spacing:.05em;text-transform:uppercase;cursor:pointer;transition:opacity .12s,box-shadow .12s}
.btn:disabled{opacity:.25;cursor:not-allowed}
.btn:not(:disabled):hover{opacity:.8}
.btn-start{background:rgba(0,212,138,.08);color:var(--grn);border-color:rgba(0,212,138,.4)}
.btn-start:not(:disabled):hover{box-shadow:0 0 14px rgba(0,212,138,.2)}
.btn-stop {background:rgba(255,61,87,.08);color:var(--red);border-color:rgba(255,61,87,.4)}
.btn-stop:not(:disabled):hover{box-shadow:0 0 14px rgba(255,61,87,.2)}
.btn-clear{background:transparent;color:var(--mut);border-color:var(--brd);font-size:.75rem}
.flash{margin-top:.7rem;padding:.4rem .6rem;border-radius:4px;font-family:var(--font);font-size:.7rem;border:1px solid}
.flash-ok {color:var(--grn);background:rgba(0,212,138,.07);border-color:rgba(0,212,138,.3)}
.flash-err{color:var(--red);background:rgba(255,61,87,.07);border-color:rgba(255,61,87,.3)}

/* Alert feed */
.feed-hdr-inner{display:flex;justify-content:space-between;align-items:center}
.feed-controls{display:flex;align-items:center;gap:.6rem}
.live-dot{width:6px;height:6px;border-radius:50%;background:var(--grn);box-shadow:0 0 5px var(--grn);animation:blink .9s step-end infinite}
.live-dot.paused{background:var(--mut);box-shadow:none;animation:none}
.feed-count{font-family:var(--font);font-size:.65rem;color:var(--mut)}
.fbtn{background:none;border:1px solid var(--brd);border-radius:3px;color:var(--mut);font-family:var(--font);font-size:.65rem;padding:.15rem .5rem;cursor:pointer}
.fbtn:hover{color:var(--txt);border-color:var(--brd2)}
.filters{display:flex;gap:.3rem}
.ftab{background:none;border:1px solid var(--brd);border-radius:3px;color:var(--mut);font-family:var(--font);font-size:.62rem;padding:.15rem .45rem;cursor:pointer;text-transform:uppercase;letter-spacing:.05em}
.ftab.on{background:var(--brd2);color:var(--txt);border-color:var(--brd2)}

/* Alert cards */
.feed-list{max-height:calc(100vh - 280px);min-height:280px;overflow-y:auto;padding:.4rem;scrollbar-width:thin;scrollbar-color:var(--brd) transparent}
.feed-list::-webkit-scrollbar{width:4px}
.feed-list::-webkit-scrollbar-thumb{background:var(--brd);border-radius:2px}
.acard{display:grid;grid-template-columns:28px 1fr auto;gap:.5rem;align-items:start;padding:.6rem .7rem;border-radius:4px;border:1px solid var(--brd);border-left:3px solid;margin-bottom:.4rem;background:var(--bg2);animation:fadein .2s ease;font-family:var(--font);font-size:.7rem}
@keyframes fadein{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:none}}
.acard:hover{border-color:var(--brd2)}
.ac-icon{font-size:1rem;line-height:1;padding-top:.05rem}
.ac-kind{font-size:.68rem;font-weight:600;letter-spacing:.06em;text-transform:uppercase;margin-bottom:.18rem}
.ac-detail{color:var(--mut);font-size:.65rem;line-height:1.5;word-break:break-all}
.ac-ts{color:var(--dim);font-size:.62rem;white-space:nowrap;text-align:right}
.empty{display:flex;flex-direction:column;align-items:center;justify-content:center;height:200px;color:var(--dim);font-family:var(--font);font-size:.75rem;gap:.4rem}
.empty-icon{font-size:2rem;opacity:.3}

@media(max-width:760px){.main{grid-template-columns:1fr}.pills{grid-template-columns:1fr 1fr}}
</style>
</head>
<body>
<div class="wrap">

<header class="hdr">
  <div class="logo"><div class="logo-ring"></div>IDS CONSOLE</div>
  <div class="hdr-right"><div id="clock"></div><div>{{ alert_log }}</div></div>
</header>

<div class="pills">
  <div class="pill"><div class="pill-label">Critical</div><div class="pill-val crit"  id="cnt-critical">{{ counts.critical }}</div></div>
  <div class="pill"><div class="pill-label">High</div>    <div class="pill-val high"  id="cnt-high">{{ counts.high }}</div></div>
  <div class="pill"><div class="pill-label">Medium</div>  <div class="pill-val med"   id="cnt-medium">{{ counts.medium }}</div></div>
  <div class="pill"><div class="pill-label">Info</div>    <div class="pill-val info-c" id="cnt-info">{{ counts.info }}</div></div>
  <div class="spark-wrap">
    <div class="pill-label">Alerts / 5 min — last 2 h</div>
    <canvas id="spark" width="200" height="42"></canvas>
  </div>
</div>

<div class="main">

  <!-- Left: status + controls -->
  <div class="card">
    <div class="card-hdr">System</div>
    <div class="card-body">

      <div id="badge" class="badge badge-{{ phase }}">
        <span class="dot dot-{{ phase }}"></span>
        <span id="badge-txt">{{ phase_label }}</span>
      </div>

      <!-- Progress bar: always in DOM, hidden via class when not in baseline -->
      <div id="prog-wrap" class="prog-wrap {{ '' if phase == 'baseline' else 'prog-hidden' }}">
        <div class="prog-labels">
          <span>Baseline learning</span>
          <span id="prog-pct">{{ "%.0f"|format(bpct * 100) }}%</span>
        </div>
        <div class="prog-track">
          <div id="prog-bar" class="prog-bar"
               style="width:{{ "%.1f"|format(bpct * 100) }}%"></div>
        </div>
      </div>

      <table class="meta">
        <tr><td>Status</td>   <td id="uptime">{{ uptime or "—" }}</td></tr>
        <tr><td>PID</td>      <td id="pid">{{ pid or "—" }}</td></tr>
        <tr><td>Script</td>   <td>{{ ids_script }}</td></tr>
        <tr><td>Log file</td> <td>{{ alert_log }}</td></tr>
        <tr><td>Last alert</td><td id="last-ts">{{ last_ts or "—" }}</td></tr>
      </table>

      <div class="btns">
        <form method="POST" action="/start" style="margin:0">
          <button class="btn btn-start" {{ "disabled" if running else "" }}>
            ▶ Start IDS
          </button>
        </form>
        <form method="POST" action="/stop" style="margin:0">
          <button class="btn btn-stop" {{ "disabled" if not running else "" }}>
            ■ Stop IDS
          </button>
        </form>
        <form method="POST" action="/clear" style="margin:0">
          <button class="btn btn-clear">⊘ Clear log</button>
        </form>
      </div>

      {% if flash %}
      <div class="flash {{ 'flash-ok' if ok else 'flash-err' }}">{{ flash }}</div>
      {% endif %}

    </div>
  </div>

  <!-- Right: alert feed -->
  <div class="card" style="display:flex;flex-direction:column">
    <div class="card-hdr feed-hdr-inner">
      <div class="feed-controls">
        <div class="live-dot" id="live-dot"></div>
        <span class="feed-count" id="feed-count">{{ alerts|length }} alert{{ 's' if alerts|length != 1 else '' }}</span>
        <button class="fbtn" id="pause-btn" onclick="togglePause()">Pause</button>
      </div>
      <div class="filters">
        <button class="ftab on" onclick="setF('all',this)">All</button>
        <button class="ftab" onclick="setF('critical',this)">Critical</button>
        <button class="ftab" onclick="setF('high',this)">High</button>
        <button class="ftab" onclick="setF('medium',this)">Medium</button>
      </div>
    </div>
    <div class="feed-list" id="feed">
      {% if alerts %}
        {% for a in alerts %}
        <div class="acard" data-sev="{{ a.severity }}" style="border-left-color:{{ a.color }}">
          <div class="ac-icon" style="color:{{ a.color }}">
            {{ {"critical":"⚠","high":"▲","medium":"◆","info":"·"}[a.severity] }}
          </div>
          <div>
            <div class="ac-kind" style="color:{{ a.color }}">{{ a.label }}</div>
            <div class="ac-detail">{{ a.detail or a.body }}</div>
          </div>
          <div class="ac-ts">{{ a.ts[11:] }}</div>
        </div>
        {% endfor %}
      {% else %}
        <div class="empty"><div class="empty-icon">◎</div><div>No alerts yet</div></div>
      {% endif %}
    </div>
  </div>

</div><!-- /main -->
</div><!-- /wrap -->

<script>
// ── Clock ──────────────────────────────────────────────────────────────────
const clockEl = document.getElementById('clock');
function tick(){ clockEl.textContent = new Date().toLocaleString(); }
tick(); setInterval(tick, 1000);

// ── Spark chart ────────────────────────────────────────────────────────────
let sparkData = {{ spark|tojson }};
function drawSpark(d){
  const c = document.getElementById('spark');
  if(!c) return;
  const W = c.offsetWidth || 200, H = 42, max = Math.max(...d, 1);
  c.width = W; c.height = H;
  const ctx = c.getContext('2d');
  ctx.clearRect(0, 0, W, H);
  const bw = W / d.length;
  d.forEach((v, i) => {
    const h = (v / max) * (H - 4), x = i * bw, t = v / max;
    ctx.fillStyle = t > .6 ? `rgba(255,61,87,${.4+t*.5})`
                  : t > .2 ? `rgba(245,158,11,${.3+t*.5})`
                  :           `rgba(56,178,255,${.15+t*.4})`;
    ctx.fillRect(x + 1, H - h, bw - 2, h);
  });
}
drawSpark(sparkData);
window.addEventListener('resize', () => drawSpark(sparkData));

// ── Filter ─────────────────────────────────────────────────────────────────
let activeF = 'all';
function setF(f, el){
  activeF = f;
  document.querySelectorAll('.ftab').forEach(b => b.classList.remove('on'));
  el.classList.add('on');
  applyF();
}
function applyF(){
  document.querySelectorAll('#feed .acard').forEach(c => {
    c.style.display = (activeF === 'all' || c.dataset.sev === activeF) ? '' : 'none';
  });
}

// ── Pause ──────────────────────────────────────────────────────────────────
let paused = false;
function togglePause(){
  paused = !paused;
  document.getElementById('pause-btn').textContent = paused ? 'Resume' : 'Pause';
  document.getElementById('live-dot').classList.toggle('paused', paused);
}

// ── Helpers ────────────────────────────────────────────────────────────────
const ICONS = { critical:'⚠', high:'▲', medium:'◆', info:'·' };
const PHASE_LABELS = { stopped:'Stopped', baseline:'Baseline…', detecting:'Detecting' };
function esc(s){
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
function buildCard(a){
  return `<div class="acard" data-sev="${esc(a.severity)}" style="border-left-color:${esc(a.color)}">
    <div class="ac-icon" style="color:${esc(a.color)}">${ICONS[a.severity]||'·'}</div>
    <div>
      <div class="ac-kind" style="color:${esc(a.color)}">${esc(a.label)}</div>
      <div class="ac-detail">${esc(a.detail||a.body)}</div>
    </div>
    <div class="ac-ts">${esc(a.ts ? a.ts.slice(11) : '')}</div>
  </div>`;
}

// ── Polling loop ───────────────────────────────────────────────────────────
let lastTs = '';

async function poll(){
  try {
    const [sr, ar, mr] = await Promise.all([
      fetch('/status'), fetch('/alerts?n=100'), fetch('/metrics'),
    ]);
    const st = await sr.json();
    const al = await ar.json();
    const mt = await mr.json();

    // Phase badge
    const bdg = document.getElementById('badge');
    bdg.className = 'badge badge-' + st.phase;
    bdg.querySelector('.dot').className = 'dot dot-' + st.phase;
    document.getElementById('badge-txt').textContent =
      PHASE_LABELS[st.phase] || st.phase;

    // Uptime / PID
    document.getElementById('uptime').textContent = st.uptime || '—';
    document.getElementById('pid').textContent    = st.pid    || '—';

    // Progress bar — show only during baseline phase
    const pw  = document.getElementById('prog-wrap');
    const pb  = document.getElementById('prog-bar');
    const ppt = document.getElementById('prog-pct');
    if(st.phase === 'baseline'){
      pw.classList.remove('prog-hidden');
      const p = Math.min((st.baseline_pct || 0) * 100, 99);
      pb.style.width = p.toFixed(1) + '%';
      ppt.textContent = p.toFixed(0) + '%';
    } else {
      pw.classList.add('prog-hidden');
    }

    // Alert counts
    const c = mt.counts || {};
    ['critical','high','medium','info'].forEach(k => {
      const el = document.getElementById('cnt-' + k);
      if(el) el.textContent = c[k] ?? 0;
    });

    // Spark
    if(mt.spark){ sparkData = mt.spark; drawSpark(sparkData); }

    // Last alert timestamp
    if(al.alerts && al.alerts.length){
      const first = al.alerts.find(a => a.severity !== 'info');
      document.getElementById('last-ts').textContent =
        first ? first.ts.slice(11) : '—';
    }

    // Alert feed (only re-render when newest timestamp changes)
    if(!paused && al.alerts){
      const feed     = document.getElementById('feed');
      const cnt      = document.getElementById('feed-count');
      const newestTs = al.alerts.length ? al.alerts[0].ts : '';
      if(newestTs !== lastTs){
        lastTs = newestTs;
        if(!al.alerts.length){
          feed.innerHTML =
            '<div class="empty"><div class="empty-icon">◎</div><div>No alerts yet</div></div>';
          cnt.textContent = '0 alerts';
        } else {
          feed.innerHTML = al.alerts.map(buildCard).join('');
          cnt.textContent = al.alerts.length + ' alert' +
                            (al.alerts.length !== 1 ? 's' : '');
          applyF();
        }
      }
    }

  } catch(e){ /* network blip — stay silent */ }
}

poll();
setInterval(poll, 5000);
</script>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
# Render helper
# ─────────────────────────────────────────────────────────────────────────────

def _render(flash: str = "", ok: bool = True) -> str:
    running = _running()
    phase   = _phase_from_log()
    alerts  = _read_alerts(100)
    labels  = {"stopped": "Stopped", "baseline": "Baseline…", "detecting": "Detecting"}
    lts     = next((a["ts"][11:] for a in alerts if a["severity"] != "info"), None)

    with _lock:
        p   = _proc
        pid = p.pid if p else None

    return render_template_string(
        TMPL,
        running     = running,
        phase       = phase,
        phase_label = labels.get(phase, phase.title()),
        uptime      = _uptime(),
        pid         = pid,
        bpct        = _baseline_pct(),
        alerts      = alerts,
        counts      = _counts(),
        spark       = _spark(),
        alert_log   = ALERT_LOG,
        ids_script  = IDS_SCRIPT,
        last_ts     = lts,
        flash       = flash,
        ok          = ok,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/")
def index():
    return _render()


@app.post("/start")
def start():
    global _proc, _start_time, _stop_reason

    if _running():
        return _render("IDS is already running.", ok=False)
    if not os.path.exists(IDS_SCRIPT):
        return _render("Script not found: %s" % IDS_SCRIPT, ok=False)

    try:
        # Launch with sudo so the IDS can open a raw packet socket.
        # app.py itself does not need root.
        p = subprocess.Popen(
            ["sudo", sys.executable, IDS_SCRIPT],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
        with _lock:
            _proc        = p
            _start_time  = datetime.now()
            _stop_reason = ""

        threading.Thread(target=_watcher, args=(p,), daemon=True).start()
        return _render("IDS started — baseline phase running.", ok=True)

    except Exception as exc:
        return _render("Failed to start: %s" % exc, ok=False)


@app.post("/stop")
def stop():
    global _proc, _stop_reason

    if not _running():
        return _render("IDS is not running.", ok=False)

    with _lock:
        p = _proc

    try:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()

        with _lock:
            _proc        = None
            _stop_reason = "Stopped at %s" % datetime.now().strftime("%H:%M:%S")

        return _render("IDS stopped.", ok=True)

    except Exception as exc:
        return _render("Error stopping IDS: %s" % exc, ok=False)


@app.post("/clear")
def clear():
    try:
        if os.path.exists(ALERT_LOG):
            os.replace(ALERT_LOG, ALERT_LOG + ".bak")
        return _render("Log cleared (backup saved as %s.bak)." % ALERT_LOG, ok=True)
    except OSError as exc:
        return _render("Could not clear log: %s" % exc, ok=False)


@app.get("/status")
def status():
    phase = _phase_from_log()
    with _lock:
        p  = _proc
        st = _start_time
    return jsonify({
        "running":      _running(),
        "phase":        phase,
        "uptime":       _uptime(),
        "pid":          p.pid if p else None,
        "baseline_pct": _baseline_pct(),
        "stop_reason":  _stop_reason,
    })


@app.get("/alerts")
def alerts_route():
    n = min(int(request.args.get("n", 100)), 200)
    return jsonify({"alerts": _read_alerts(n), "log_file": ALERT_LOG})


@app.get("/metrics")
def metrics():
    return jsonify({"counts": _counts(), "spark": _spark()})


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=False, use_reloader=False)
