"""
app.py  —  Ulinzi HIDS  ·  Web Dashboard + Engine Launcher
============================================================
Run:  sudo python3 app.py
Open: http://localhost:5000

sudo is required so the engine can open an AF_PACKET raw socket and read
/var/log/auth.log.  The Flask dashboard itself is lightweight.

The HIDS engine starts automatically in the background the moment this
script launches.  No second terminal is needed.
"""

import os, re, sys, threading, signal
from datetime import datetime
from flask import Flask, render_template_string, jsonify, request

# ── import engine ─────────────────────────────────────────────────────────────
import hids_main as engine_mod

ALERT_LOG = engine_mod.ALERT_LOG
PORT      = int(os.environ.get("PORT", 5000))
HOST_BIND = os.environ.get("HOST", "0.0.0.0")

app = Flask(__name__)

# =============================================================================
# AUTO-START ENGINE
# =============================================================================

def _launch_engine():
    engine_mod.start_engine()

_launch_thread = threading.Thread(target=_launch_engine, daemon=True)
_launch_thread.start()

# Graceful shutdown
def _on_exit(*_):
    engine_mod.stop_engine()
    os._exit(0)

signal.signal(signal.SIGTERM, _on_exit)
signal.signal(signal.SIGINT,  _on_exit)

# =============================================================================
# ALERT PARSING
# =============================================================================

# Format: [YYYY-MM-DD HH:MM:SS] LEVEL:<level> RULE:<rule> | <detail>
_RE = re.compile(
    r'^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s+LEVEL:(\w+)\s+RULE:(\S+)\s+\|\s+(.*)$'
)

_RULE_META = {
    # rule_tag           : (label,              icon, css-color-class)
    "brute_force":         ("Brute-force",       "🔑", "c-red"),
    "priv_escalation":     ("Priv. Escalation",  "⬆",  "c-red"),
    "proc_anomaly":        ("Process Anomaly",   "⚙",  "c-orange"),
    "file_integrity":      ("File Tampered",     "📄", "c-red"),
    "syn_flood":           ("SYN Flood",         "🌊", "c-red"),
    "udp_flood":           ("UDP Flood",         "🌊", "c-orange"),
    "icmp_flood":          ("ICMP Flood",        "🌊", "c-orange"),
    "udp_flood":           ("UDP Flood",         "🌊", "c-orange"),
    "vol_flood":           ("Vol. DoS",          "💥", "c-red"),
    "engine":              ("System",            "ℹ",  "c-blue"),
}

_LEVEL_COLOR = {
    "CRITICAL": "#ff3d57",
    "HIGH":     "#ff6b35",
    "MEDIUM":   "#f59e0b",
    "LOW":      "#38b2ff",
    "INFO":     "#4a6a85",
}

_LEVEL_BG = {
    "CRITICAL": "rgba(255,61,87,.08)",
    "HIGH":     "rgba(255,107,53,.08)",
    "MEDIUM":   "rgba(245,158,11,.08)",
    "LOW":      "rgba(56,178,255,.08)",
    "INFO":     "rgba(74,106,133,.06)",
}


def _parse(raw: str):
    m = _RE.match(raw.strip())
    if not m:
        return None
    ts, level, rule, detail = m.group(1), m.group(2), m.group(3), m.group(4)

    # strip scan_ prefix for display
    display_rule = rule[5:] if rule.startswith("scan_") else rule
    meta = _RULE_META.get(display_rule, ("Alert", "⚠", "c-red"))
    # port scan label includes the IP
    if rule.startswith("scan_"):
        label = f"Port Scan ({rule[5:]})"
        icon  = "🔍"
    else:
        label, icon, _ = meta

    return {
        "ts":     ts,
        "level":  level,
        "rule":   rule,
        "label":  label,
        "icon":   icon,
        "detail": detail,
        "color":  _LEVEL_COLOR.get(level, "#888"),
        "bg":     _LEVEL_BG.get(level, "rgba(100,100,100,.06)"),
    }


def _read_alerts(n: int = 120):
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
    c = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    if not os.path.exists(ALERT_LOG):
        return c
    try:
        with open(ALERT_LOG, errors="replace") as fh:
            for line in fh:
                a = _parse(line)
                if a and a["level"] in c:
                    c[a["level"]] += 1
    except OSError:
        pass
    return c


def _category_counts():
    host_rules    = {"brute_force","priv_escalation","proc_anomaly","file_integrity"}
    network_rules = {"syn_flood","udp_flood","icmp_flood","vol_flood"}
    h = n = 0
    if not os.path.exists(ALERT_LOG):
        return {"host": 0, "network": 0}
    try:
        with open(ALERT_LOG, errors="replace") as fh:
            for line in fh:
                a = _parse(line)
                if not a or a["level"] == "INFO":
                    continue
                r = a["rule"]
                if r in host_rules:           h += 1
                elif r in network_rules:      n += 1
                elif r.startswith("scan_"):   n += 1
    except OSError:
        pass
    return {"host": h, "network": n}


def _spark(buckets: int = 30, secs_per_bucket: int = 60):
    result = [0] * buckets
    if not os.path.exists(ALERT_LOG):
        return result
    now = datetime.now()
    try:
        with open(ALERT_LOG, errors="replace") as fh:
            for line in fh:
                a = _parse(line)
                if not a or a["level"] == "INFO":
                    continue
                try:
                    ts  = datetime.strptime(a["ts"], "%Y-%m-%d %H:%M:%S")
                    idx = int((now - ts).total_seconds() / secs_per_bucket)
                    if 0 <= idx < buckets:
                        result[idx] += 1
                except ValueError:
                    pass
    except OSError:
        pass
    return list(reversed(result))


def _uptime() -> str:
    st = engine_mod.hids_state.get("uptime_start")
    if st and engine_mod.is_running():
        s = int((datetime.now() - st).total_seconds())
        h, r = divmod(s, 3600)
        m, sec = divmod(r, 60)
        return f"{h:02d}:{m:02d}:{sec:02d}"
    return ""

# =============================================================================
# HTML TEMPLATE
# =============================================================================

TMPL = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ulinzi HIDS</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#060a0f;--bg2:#0b1219;--surf:#0f1b26;--brd:#1b2d40;--brd2:#253d55;
  --txt:#c0d4e8;--mut:#3d5c75;--dim:#1c3045;
  --grn:#00d48a;--red:#ff3d57;--org:#ff6b35;--amb:#f59e0b;
  --blu:#38b2ff;--vio:#a855f7;--cyn:#22d3ee;
  --font:'IBM Plex Mono',monospace;--ui:'IBM Plex Sans',sans-serif;
}
html,body{height:100%;background:var(--bg);color:var(--txt);font-family:var(--ui);font-size:14px}
body::before{content:'';position:fixed;inset:0;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.04) 2px,rgba(0,0,0,.04) 3px);
  pointer-events:none;z-index:9998}

/* ── layout ── */
.wrap{max-width:1280px;margin:0 auto;padding:1.2rem 1rem 3rem;display:grid;gap:1rem}
.hdr{display:flex;justify-content:space-between;align-items:flex-start;
     padding-bottom:.9rem;border-bottom:1px solid var(--brd)}
.brand{display:flex;align-items:center;gap:.7rem}
.ring{width:11px;height:11px;border-radius:50%;border:2px solid var(--blu);
      box-shadow:0 0 10px var(--blu);animation:pulse 2s ease-in-out infinite}
@keyframes pulse{0%,100%{box-shadow:0 0 4px var(--blu)}50%{box-shadow:0 0 20px var(--blu),0 0 40px rgba(56,178,255,.25)}}
.brand-title{font-family:var(--font);font-size:.95rem;color:var(--blu);letter-spacing:.15em}
.brand-sub{font-size:.6rem;color:var(--mut);letter-spacing:.08em;margin-top:.15rem}
.hdr-r{font-family:var(--font);font-size:.7rem;color:var(--mut);text-align:right;line-height:1.8}
#clock{color:var(--txt)}

/* ── top stat strip ── */
.strip{display:grid;grid-template-columns:repeat(5,1fr) 1fr 1fr 1fr 220px;gap:.7rem}
.pill{background:var(--surf);border:1px solid var(--brd);border-radius:7px;padding:.55rem .8rem;position:relative;overflow:hidden}
.pill::before{content:'';position:absolute;top:0;left:0;right:0;height:2px}
.pill-crit::before{background:var(--red)}
.pill-high::before{background:var(--org)}
.pill-med::before{background:var(--amb)}
.pill-low::before{background:var(--blu)}
.pill-info::before{background:var(--mut)}
.pill-host::before{background:var(--org)}
.pill-net::before{background:var(--cyn)}
.pill-win::before{background:var(--vio)}
.pill-lbl{font-family:var(--font);font-size:.56rem;letter-spacing:.12em;text-transform:uppercase;color:var(--mut);margin-bottom:.18rem}
.pill-val{font-size:1.65rem;font-weight:600;line-height:1}
.v-crit{color:var(--red)}.v-high{color:var(--org)}.v-med{color:var(--amb)}
.v-low{color:var(--blu)}.v-info{color:var(--mut)}.v-host{color:var(--org)}
.v-net{color:var(--cyn)}.v-win{color:var(--vio)}
.spark-pill{background:var(--surf);border:1px solid var(--brd);border-radius:7px;padding:.55rem .8rem}
#spark{display:block;width:100%;height:44px;margin-top:.25rem}

/* ── main 2-col grid ── */
.main{display:grid;grid-template-columns:280px 1fr;gap:1rem;align-items:start}
.card{background:var(--surf);border:1px solid var(--brd);border-radius:7px;overflow:hidden}
.card-hdr{padding:.55rem .9rem;border-bottom:1px solid var(--brd);
          font-family:var(--font);font-size:.58rem;letter-spacing:.14em;
          text-transform:uppercase;color:var(--mut);
          display:flex;justify-content:space-between;align-items:center}
.card-body{padding:.9rem}

/* ── phase badge ── */
.badge{display:flex;align-items:center;gap:.45rem;padding:.38rem .7rem;border-radius:4px;
       font-family:var(--font);font-size:.72rem;letter-spacing:.06em;text-transform:uppercase;
       border:1px solid;margin-bottom:.8rem;justify-content:center}
.badge-stopped  {background:rgba(255,61,87,.07);color:var(--red);border-color:rgba(255,61,87,.3)}
.badge-baseline {background:rgba(245,158,11,.07);color:var(--amb);border-color:rgba(245,158,11,.3)}
.badge-detecting{background:rgba(0,212,138,.07);color:var(--grn);border-color:rgba(0,212,138,.3)}
.dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.dot-stopped  {background:var(--red)}
.dot-baseline {background:var(--amb);animation:blink .7s step-end infinite}
.dot-detecting{background:var(--grn);box-shadow:0 0 8px var(--grn)}
@keyframes blink{50%{opacity:0}}

/* ── baseline progress ── */
.prog-wrap{margin-bottom:.8rem}
.prog-hidden{display:none!important}
.prog-labels{display:flex;justify-content:space-between;
             font-family:var(--font);font-size:.62rem;color:var(--mut);margin-bottom:.22rem}
.prog-track{height:5px;background:var(--dim);border-radius:3px;overflow:hidden}
.prog-bar{height:100%;background:linear-gradient(90deg,var(--amb),var(--blu));
          border-radius:3px;transition:width .6s ease}

/* ── monitor grid ── */
.mon-grid{display:grid;grid-template-columns:1fr 1fr;gap:.35rem;margin-bottom:.8rem}
.mon-pill{background:var(--bg2);border:1px solid var(--brd);border-radius:4px;padding:.28rem .5rem;
          font-family:var(--font);font-size:.6rem}
.mon-lbl{color:var(--mut);margin-bottom:.08rem;font-size:.56rem;letter-spacing:.06em;text-transform:uppercase}
.mon-val{display:flex;align-items:center;gap:.28rem}
.mdot{width:5px;height:5px;border-radius:50%;flex-shrink:0}
.mon-on{background:var(--grn)}.mon-off{background:var(--red)}

/* ── meta table ── */
.meta{width:100%;border-collapse:collapse;font-family:var(--font);font-size:.68rem;margin-bottom:.8rem}
.meta td{padding:.28rem 0;border-bottom:1px solid var(--brd)}
.meta td:first-child{color:var(--mut);width:44%}
.meta td:last-child{color:var(--txt);text-align:right}

/* ── live traffic bar ── */
.traffic-bar-wrap{margin-bottom:.8rem}
.traffic-lbl{font-family:var(--font);font-size:.58rem;letter-spacing:.1em;text-transform:uppercase;color:var(--mut);margin-bottom:.3rem}
.traffic-bars{display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:.25rem}
.tbar{background:var(--dim);border-radius:3px;overflow:hidden;height:4px;position:relative}
.tbar-fill{height:100%;border-radius:3px;transition:width .4s ease}
.tbar-label{display:flex;justify-content:space-between;font-family:var(--font);font-size:.55rem;color:var(--mut);margin-top:.1rem}

/* ── buttons ── */
.btns{display:grid;grid-template-columns:1fr 1fr;gap:.5rem;margin-bottom:.5rem}
.btn-clear-wrap{margin-top:.1rem}
.btn{width:100%;padding:.5rem;border:1px solid;border-radius:4px;
     font-family:var(--ui);font-size:.8rem;font-weight:600;
     letter-spacing:.04em;text-transform:uppercase;cursor:pointer;
     transition:opacity .12s,box-shadow .12s;background:none}
.btn:disabled{opacity:.22;cursor:not-allowed}
.btn-start{color:var(--grn);border-color:rgba(0,212,138,.4);background:rgba(0,212,138,.06)}
.btn-start:not(:disabled):hover{box-shadow:0 0 16px rgba(0,212,138,.2)}
.btn-stop {color:var(--red);border-color:rgba(255,61,87,.4);background:rgba(255,61,87,.06)}
.btn-stop:not(:disabled):hover{box-shadow:0 0 16px rgba(255,61,87,.2)}
.btn-clear{width:100%;color:var(--mut);border-color:var(--brd);font-size:.72rem;padding:.4rem}
.flash{margin-top:.6rem;padding:.35rem .55rem;border-radius:4px;
       font-family:var(--font);font-size:.68rem;border:1px solid}
.flash-ok {color:var(--grn);background:rgba(0,212,138,.07);border-color:rgba(0,212,138,.3)}
.flash-err{color:var(--red);background:rgba(255,61,87,.07);border-color:rgba(255,61,87,.3)}

/* ── alert feed ── */
.feed-hdr{display:flex;justify-content:space-between;align-items:center}
.feed-left{display:flex;align-items:center;gap:.55rem}
.live-dot{width:6px;height:6px;border-radius:50%;background:var(--grn);
          box-shadow:0 0 6px var(--grn);animation:blink .9s step-end infinite}
.live-dot.paused{background:var(--mut);box-shadow:none;animation:none}
.feed-count{font-family:var(--font);font-size:.63rem;color:var(--mut)}
.fbtn{background:none;border:1px solid var(--brd);border-radius:3px;
      color:var(--mut);font-family:var(--font);font-size:.63rem;
      padding:.12rem .44rem;cursor:pointer}
.fbtn:hover{color:var(--txt);border-color:var(--brd2)}
.filters{display:flex;gap:.28rem;flex-wrap:wrap}
.ftab{background:none;border:1px solid var(--brd);border-radius:3px;
      color:var(--mut);font-family:var(--font);font-size:.6rem;
      padding:.12rem .4rem;cursor:pointer;text-transform:uppercase;letter-spacing:.05em}
.ftab.on{color:var(--txt);border-color:var(--brd2);background:var(--brd)}

/* ── alert cards ── */
.feed{max-height:calc(100vh - 260px);min-height:320px;overflow-y:auto;
      padding:.35rem;scrollbar-width:thin;scrollbar-color:var(--brd) transparent}
.feed::-webkit-scrollbar{width:3px}
.feed::-webkit-scrollbar-thumb{background:var(--brd);border-radius:2px}

.acard{display:grid;grid-template-columns:32px 1fr auto;gap:.45rem;align-items:start;
       padding:.55rem .65rem;border-radius:5px;border:1px solid var(--brd);
       border-left:3px solid;margin-bottom:.35rem;animation:fadein .18s ease;
       font-family:var(--font);font-size:.68rem;transition:border-color .15s}
@keyframes fadein{from{opacity:0;transform:translateY(-3px)}to{opacity:1;transform:none}}
.acard:hover{border-color:var(--brd2)}
.ac-icon{font-size:1rem;line-height:1.2;text-align:center}
.ac-top{display:flex;align-items:center;gap:.4rem;margin-bottom:.12rem;flex-wrap:wrap}
.ac-level{font-size:.58rem;font-weight:700;letter-spacing:.1em;padding:.05rem .3rem;
          border-radius:2px;text-transform:uppercase}
.ac-label{font-size:.68rem;font-weight:600;letter-spacing:.05em;text-transform:uppercase}
.ac-detail{color:var(--mut);font-size:.63rem;line-height:1.55;word-break:break-all}
.ac-ts{color:var(--dim);font-size:.6rem;white-space:nowrap;text-align:right;padding-top:.1rem}

.level-CRITICAL{background:rgba(255,61,87,.15);color:#ff3d57}
.level-HIGH    {background:rgba(255,107,53,.15);color:#ff6b35}
.level-MEDIUM  {background:rgba(245,158,11,.15);color:#f59e0b}
.level-LOW     {background:rgba(56,178,255,.15);color:#38b2ff}
.level-INFO    {background:rgba(74,106,133,.15);color:#4a6a85}

.empty{display:flex;flex-direction:column;align-items:center;justify-content:center;
       height:220px;color:var(--dim);font-family:var(--font);font-size:.72rem;gap:.4rem}
.empty-icon{font-size:2.2rem;opacity:.25}

@media(max-width:1000px){.main{grid-template-columns:1fr}.strip{grid-template-columns:repeat(4,1fr)}}
@media(max-width:600px) {.strip{grid-template-columns:repeat(2,1fr)}}
</style>
</head>
<body>
<div class="wrap">

<!-- ── HEADER ── -->
<header class="hdr">
  <div class="brand">
    <div class="ring"></div>
    <div>
      <div class="brand-title">ULINZI HIDS</div>
      <div class="brand-sub">HOST INTRUSION DETECTION SYSTEM · KALI LINUX</div>
    </div>
  </div>
  <div class="hdr-r">
    <div id="clock"></div>
    <div>{{ alert_log }}</div>
    <div id="hdr-phase" style="color:var(--amb)">{{ phase_label }}</div>
  </div>
</header>

<!-- ── STAT STRIP ── -->
<div class="strip">
  <div class="pill pill-crit"><div class="pill-lbl">Critical</div><div class="pill-val v-crit" id="c-CRITICAL">{{ counts.CRITICAL }}</div></div>
  <div class="pill pill-high"><div class="pill-lbl">High</div>    <div class="pill-val v-high" id="c-HIGH">{{ counts.HIGH }}</div></div>
  <div class="pill pill-med" ><div class="pill-lbl">Medium</div>  <div class="pill-val v-med"  id="c-MEDIUM">{{ counts.MEDIUM }}</div></div>
  <div class="pill pill-low" ><div class="pill-lbl">Low</div>     <div class="pill-val v-low"  id="c-LOW">{{ counts.LOW }}</div></div>
  <div class="pill pill-info"><div class="pill-lbl">Info</div>    <div class="pill-val v-info" id="c-INFO">{{ counts.INFO }}</div></div>
  <div class="pill pill-host"><div class="pill-lbl">Host alerts</div><div class="pill-val v-host" id="c-host">{{ cat.host }}</div></div>
  <div class="pill pill-net" ><div class="pill-lbl">Net alerts</div> <div class="pill-val v-net"  id="c-net">{{ cat.network }}</div></div>
  <div class="pill pill-win" ><div class="pill-lbl">Windows</div>    <div class="pill-val v-win"  id="c-win">{{ windows }}</div></div>
  <div class="spark-pill">
    <div class="pill-lbl">Alerts / min — last 30 min</div>
    <canvas id="spark" width="220" height="44"></canvas>
  </div>
</div>

<!-- ── MAIN GRID ── -->
<div class="main">

  <!-- LEFT: CONTROLS -->
  <div class="card">
    <div class="card-hdr">System Control</div>
    <div class="card-body">

      <!-- Phase badge -->
      <div id="badge" class="badge badge-{{ phase }}">
        <span class="dot dot-{{ phase }}" id="badge-dot"></span>
        <span id="badge-txt">{{ phase_label }}</span>
      </div>

      <!-- Baseline progress bar -->
      <div id="prog-wrap" class="prog-wrap {{ '' if phase == 'baseline' else 'prog-hidden' }}">
        <div class="prog-labels">
          <span>Baseline learning</span>
          <span id="prog-pct">{{ "%.0f"|format(bpct*100) }}%</span>
        </div>
        <div class="prog-track">
          <div id="prog-bar" class="prog-bar" style="width:{{ "%.1f"|format(bpct*100) }}%"></div>
        </div>
      </div>

      <!-- Live traffic micro-bars -->
      <div class="traffic-bar-wrap">
        <div class="traffic-lbl">Live network traffic (pkts/s)</div>
        <div class="traffic-bars">
          <div>
            <div class="tbar"><div id="tb-syn"  class="tbar-fill" style="width:0%;background:var(--red)"></div></div>
            <div class="tbar-label"><span>SYN</span><span id="tv-syn">0</span></div>
          </div>
          <div>
            <div class="tbar"><div id="tb-udp"  class="tbar-fill" style="width:0%;background:var(--org)"></div></div>
            <div class="tbar-label"><span>UDP</span><span id="tv-udp">0</span></div>
          </div>
          <div>
            <div class="tbar"><div id="tb-icmp" class="tbar-fill" style="width:0%;background:var(--amb)"></div></div>
            <div class="tbar-label"><span>ICMP</span><span id="tv-icmp">0</span></div>
          </div>
          <div>
            <div class="tbar"><div id="tb-tot"  class="tbar-fill" style="width:0%;background:var(--blu)"></div></div>
            <div class="tbar-label"><span>TOT</span><span id="tv-tot">0</span></div>
          </div>
        </div>
      </div>

      <!-- Monitor status -->
      <div class="mon-grid">
        <div class="mon-pill">
          <div class="mon-lbl">Auth Log</div>
          <div class="mon-val" id="mon-auth">
            <div class="mdot {{ 'mon-on' if mon.auth_log else 'mon-off' }}"></div>
            {{ 'Active' if mon.auth_log else 'N/A' }}
          </div>
        </div>
        <div class="mon-pill">
          <div class="mon-lbl">Process Mon.</div>
          <div class="mon-val" id="mon-proc">
            <div class="mdot {{ 'mon-on' if mon.psutil else 'mon-off' }}"></div>
            {{ 'Active' if mon.psutil else 'No psutil' }}
          </div>
        </div>
        <div class="mon-pill">
          <div class="mon-lbl">File Integrity</div>
          <div class="mon-val">
            <div class="mdot mon-on"></div>
            {{ mon.fim_files }} files
          </div>
        </div>
        <div class="mon-pill">
          <div class="mon-lbl">Network Cap.</div>
          <div class="mon-val">
            <div class="mdot {{ 'mon-on' if running else 'mon-off' }}"></div>
            <span id="mon-iface">{{ mon.iface }}</span>
          </div>
        </div>
      </div>

      <!-- Meta -->
      <table class="meta">
        <tr><td>Status</td>     <td id="mt-uptime">{{ uptime or '—' }}</td></tr>
        <tr><td>Interface</td>  <td>{{ mon.iface }}</td></tr>
        <tr><td>Window</td>     <td>{{ window_secs }}s</td></tr>
        <tr><td>Baseline</td>   <td>{{ baseline_secs }}s</td></tr>
        <tr><td>Log file</td>   <td>{{ alert_log }}</td></tr>
        <tr><td>Last alert</td> <td id="mt-last">{{ last_ts or '—' }}</td></tr>
      </table>

      <!-- Buttons -->
      <div class="btns">
        <form method="POST" action="/start" style="margin:0">
          <button class="btn btn-start" {{ 'disabled' if running else '' }}>▶ Start</button>
        </form>
        <form method="POST" action="/stop" style="margin:0">
          <button class="btn btn-stop" {{ 'disabled' if not running else '' }}>■ Stop</button>
        </form>
      </div>
      <div class="btn-clear-wrap">
        <form method="POST" action="/clear" style="margin:0">
          <button class="btn btn-clear">⊘ Clear alert log</button>
        </form>
      </div>

      {% if flash %}
      <div class="flash {{ 'flash-ok' if ok else 'flash-err' }}">{{ flash }}</div>
      {% endif %}

    </div>
  </div>

  <!-- RIGHT: ALERT FEED -->
  <div class="card" style="display:flex;flex-direction:column">
    <div class="card-hdr feed-hdr">
      <div class="feed-left">
        <div class="live-dot" id="live-dot"></div>
        <span class="feed-count" id="feed-count">{{ alerts|length }} alert{{ 's' if alerts|length != 1 else '' }}</span>
        <button class="fbtn" id="pbtn" onclick="togglePause()">Pause</button>
      </div>
      <div class="filters">
        <button class="ftab on"  onclick="setF('ALL',this)">All</button>
        <button class="ftab" onclick="setF('CRITICAL',this)">Critical</button>
        <button class="ftab" onclick="setF('HIGH',this)">High</button>
        <button class="ftab" onclick="setF('MEDIUM',this)">Medium</button>
        <button class="ftab" onclick="setF('LOW',this)">Low</button>
        <button class="ftab" onclick="setF('INFO',this)">Info</button>
      </div>
    </div>
    <div class="feed" id="feed">
      {% if alerts %}
        {% for a in alerts %}
        <div class="acard" data-lv="{{ a.level }}" style="border-left-color:{{ a.color }};background:{{ a.bg }}">
          <div class="ac-icon">{{ a.icon }}</div>
          <div>
            <div class="ac-top">
              <span class="ac-level level-{{ a.level }}">{{ a.level }}</span>
              <span class="ac-label" style="color:{{ a.color }}">{{ a.label }}</span>
            </div>
            <div class="ac-detail">{{ a.detail }}</div>
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
// ── clock ─────────────────────────────────────────────────────────────────────
const clockEl=document.getElementById('clock');
function tick(){clockEl.textContent=new Date().toLocaleString();}
tick();setInterval(tick,1000);

// ── spark ─────────────────────────────────────────────────────────────────────
let sparkData={{ spark|tojson }};
function drawSpark(d){
  const c=document.getElementById('spark');if(!c)return;
  const W=c.offsetWidth||220,H=44,max=Math.max(...d,1);
  c.width=W;c.height=H;
  const ctx=c.getContext('2d');ctx.clearRect(0,0,W,H);
  const bw=W/d.length;
  d.forEach((v,i)=>{
    if(!v)return;
    const h=(v/max)*(H-4),x=i*bw,t=v/max;
    ctx.fillStyle=t>.7?`rgba(255,61,87,${.45+t*.45})`
                 :t>.35?`rgba(245,158,11,${.3+t*.5})`
                 :`rgba(56,178,255,${.18+t*.5})`;
    ctx.fillRect(x+1,H-h,Math.max(bw-2,1),h);
  });
}
drawSpark(sparkData);
window.addEventListener('resize',()=>drawSpark(sparkData));

// ── filter ────────────────────────────────────────────────────────────────────
let activeF='ALL';
function setF(f,el){
  activeF=f;
  document.querySelectorAll('.ftab').forEach(b=>b.classList.remove('on'));
  el.classList.add('on');applyF();
}
function applyF(){
  document.querySelectorAll('#feed .acard').forEach(c=>{
    c.style.display=(activeF==='ALL'||c.dataset.lv===activeF)?'':'none';
  });
}

// ── pause ─────────────────────────────────────────────────────────────────────
let paused=false;
function togglePause(){
  paused=!paused;
  document.getElementById('pbtn').textContent=paused?'Resume':'Pause';
  document.getElementById('live-dot').classList.toggle('paused',paused);
}

// ── traffic bars ──────────────────────────────────────────────────────────────
function setBar(id,val,max){
  const bar=document.getElementById('tb-'+id);
  const lbl=document.getElementById('tv-'+id);
  if(bar) bar.style.width=Math.min((val/Math.max(max,1))*100,100)+'%';
  if(lbl) lbl.textContent=val>999?(val/1000).toFixed(1)+'k':Math.round(val);
}

// ── helpers ───────────────────────────────────────────────────────────────────
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
const PHASES={stopped:'Stopped',baseline:'Baseline…',detecting:'Detecting'};
const LVLBG={CRITICAL:'rgba(255,61,87,.08)',HIGH:'rgba(255,107,53,.08)',
             MEDIUM:'rgba(245,158,11,.08)',LOW:'rgba(56,178,255,.08)',INFO:'rgba(74,106,133,.06)'};
const LVLCOL={CRITICAL:'#ff3d57',HIGH:'#ff6b35',MEDIUM:'#f59e0b',LOW:'#38b2ff',INFO:'#4a6a85'};

function buildCard(a){
  const bg=LVLBG[a.level]||'rgba(100,100,100,.06)';
  const col=LVLCOL[a.level]||'#888';
  return `<div class="acard" data-lv="${esc(a.level)}"
               style="border-left-color:${col};background:${bg}">
    <div class="ac-icon">${esc(a.icon||'⚠')}</div>
    <div>
      <div class="ac-top">
        <span class="ac-level level-${esc(a.level)}">${esc(a.level)}</span>
        <span class="ac-label" style="color:${col}">${esc(a.label)}</span>
      </div>
      <div class="ac-detail">${esc(a.detail)}</div>
    </div>
    <div class="ac-ts">${esc(a.ts?a.ts.slice(11):'')}</div>
  </div>`;
}

// ── polling ───────────────────────────────────────────────────────────────────
let lastTs='';

async function poll(){
  try{
    const [sr,ar,mr]=await Promise.all([
      fetch('/status'),fetch('/alerts?n=120'),fetch('/metrics')]);
    const st=await sr.json(),al=await ar.json(),mt=await mr.json();

    // phase badge
    const bdg=document.getElementById('badge');
    bdg.className='badge badge-'+st.phase;
    document.getElementById('badge-dot').className='dot dot-'+st.phase;
    document.getElementById('badge-txt').textContent=PHASES[st.phase]||st.phase;
    const hp=document.getElementById('hdr-phase');
    if(hp) hp.textContent=PHASES[st.phase]||st.phase;

    // uptime
    const uEl=document.getElementById('mt-uptime');
    if(uEl) uEl.textContent=st.uptime||'—';

    // progress bar
    const pw=document.getElementById('prog-wrap');
    const pb=document.getElementById('prog-bar');
    const pp=document.getElementById('prog-pct');
    if(st.phase==='baseline'){
      pw.classList.remove('prog-hidden');
      const p=Math.min((st.baseline_pct||0)*100,99);
      if(pb) pb.style.width=p.toFixed(1)+'%';
      if(pp) pp.textContent=p.toFixed(0)+'%';
    } else { pw.classList.add('prog-hidden'); }

    // windows
    const wEl=document.getElementById('c-win');
    if(wEl) wEl.textContent=st.windows||0;

    // counts
    const c=mt.counts||{};
    ['CRITICAL','HIGH','MEDIUM','LOW','INFO'].forEach(k=>{
      const el=document.getElementById('c-'+k);if(el) el.textContent=c[k]??0;
    });
    const cat=mt.cat||{};
    const hEl=document.getElementById('c-host'),nEl=document.getElementById('c-net');
    if(hEl) hEl.textContent=cat.host??0;
    if(nEl) nEl.textContent=cat.network??0;

    // spark
    if(mt.spark){sparkData=mt.spark;drawSpark(sparkData);}

    // traffic bars
    const ns=st.last_ns||{};
    const synMax=Math.max(ns.syn_rate||0,500);
    setBar('syn', ns.syn_rate||0, synMax);
    setBar('udp', ns.udp_rate||0, Math.max(ns.udp_rate||0,2000));
    setBar('icmp',ns.icmp_rate||0,Math.max(ns.icmp_rate||0,200));
    setBar('tot', ns.total_rate||0,Math.max(ns.total_rate||0,3000));

    // last alert
    if(al.alerts&&al.alerts.length){
      const first=al.alerts.find(a=>a.level!=='INFO');
      const lEl=document.getElementById('mt-last');
      if(lEl) lEl.textContent=first?first.ts.slice(11):'—';
    }

    // feed
    if(!paused&&al.alerts){
      const feed=document.getElementById('feed');
      const cntEl=document.getElementById('feed-count');
      const newestTs=al.alerts.length?al.alerts[0].ts:'';
      if(newestTs!==lastTs){
        lastTs=newestTs;
        if(!al.alerts.length){
          feed.innerHTML='<div class="empty"><div class="empty-icon">◎</div><div>No alerts yet</div></div>';
          if(cntEl) cntEl.textContent='0 alerts';
        } else {
          feed.innerHTML=al.alerts.map(buildCard).join('');
          if(cntEl) cntEl.textContent=al.alerts.length+' alert'+(al.alerts.length!==1?'s':'');
          applyF();
        }
      }
    }
  }catch(e){}
}
poll();setInterval(poll,2000);
</script>
</body>
</html>"""


# =============================================================================
# RENDER HELPER
# =============================================================================

def _render(flash: str = "", ok: bool = True):
    st      = engine_mod.get_state()
    running = engine_mod.is_running()
    phase   = st.get("phase", "stopped")
    mon     = st.get("monitors", {})
    labels  = {"stopped": "Stopped", "baseline": "Baseline…", "detecting": "Detecting"}
    alerts  = _read_alerts(120)
    lts     = next((a["ts"][11:] for a in alerts if a["level"] != "INFO"), None)

    return render_template_string(
        TMPL,
        running      = running,
        phase        = phase,
        phase_label  = labels.get(phase, phase.title()),
        uptime       = _uptime(),
        bpct         = st.get("baseline_pct", 0.0),
        windows      = st.get("windows", 0),
        alerts       = alerts,
        counts       = _counts(),
        cat          = _category_counts(),
        spark        = _spark(),
        alert_log    = ALERT_LOG,
        last_ts      = lts,
        flash        = flash,
        ok           = ok,
        mon          = {
            "auth_log":  mon.get("auth_log",  False),
            "psutil":    mon.get("psutil",    False),
            "fim_files": mon.get("fim_files", 0),
            "iface":     mon.get("iface",     "—"),
        },
        window_secs   = engine_mod.WINDOW_SECONDS,
        baseline_secs = engine_mod.BASELINE_SECONDS,
    )


# =============================================================================
# ROUTES
# =============================================================================

@app.get("/")
def index():
    return _render()


@app.post("/start")
def start():
    if engine_mod.is_running():
        return _render("Engine is already running.", ok=False)
    engine_mod.start_engine()
    return _render("Engine started.", ok=True)


@app.post("/stop")
def stop():
    if not engine_mod.is_running():
        return _render("Engine is not running.", ok=False)
    engine_mod.stop_engine()
    return _render("Engine stopped.", ok=True)


@app.post("/clear")
def clear():
    try:
        if os.path.exists(ALERT_LOG):
            os.replace(ALERT_LOG, ALERT_LOG + ".bak")
        return _render("Log cleared (backup → %s.bak)." % ALERT_LOG, ok=True)
    except OSError as e:
        return _render(f"Could not clear log: {e}", ok=False)


@app.get("/status")
def status():
    st = engine_mod.get_state()
    ns = st.get("last_ns")
    ns_dict = {}
    if ns:
        ns_dict = {
            "syn_rate":   round(ns.syn_rate,   1),
            "udp_rate":   round(ns.udp_rate,   1),
            "icmp_rate":  round(ns.icmp_rate,  1),
            "total_rate": round(ns.total_rate, 1),
        }
    return jsonify({
        "running":      engine_mod.is_running(),
        "phase":        st.get("phase", "stopped"),
        "uptime":       _uptime(),
        "windows":      st.get("windows", 0),
        "baseline_pct": st.get("baseline_pct", 0.0),
        "last_ns":      ns_dict,
    })


@app.get("/alerts")
def alerts_api():
    n = min(int(request.args.get("n", 120)), 300)
    return jsonify({"alerts": _read_alerts(n)})


@app.get("/metrics")
def metrics():
    return jsonify({
        "counts": _counts(),
        "cat":    _category_counts(),
        "spark":  _spark(),
    })


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    print(f"\n  Ulinzi HIDS — starting on http://0.0.0.0:{PORT}")
    print("  Engine starting automatically in background...")
    print("  Open http://localhost:5000 in your browser\n")
    app.run(host=HOST_BIND, port=PORT, debug=False, use_reloader=False, threaded=True)
