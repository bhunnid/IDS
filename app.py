"""
app.py  —  Ulinzi HIDS v4  ·  Web Dashboard
=============================================
Run:  sudo python3 app.py
Open: http://localhost:5000   (or http://<VM-IP>:5000 from phone)

Features:
  - Real-time dashboard with alert feed, charts, top attackers
  - Settings page: configure ntfy push notifications in-browser
  - REST API for external consumers
  - Server-Sent Events for live alert streaming
  - Mobile-responsive layout
"""

import os, re, sys, json, time, threading, signal, sqlite3
from datetime import datetime
from flask import (Flask, render_template_string, jsonify, request,
                   redirect, url_for, Response, stream_with_context)

import hids_engine as eng

ALERT_LOG = eng._DEFAULT_CONFIG["alert_log"]
PORT      = int(os.environ.get("PORT", 5000))
HOST_BIND = os.environ.get("HOST", "0.0.0.0")

app = Flask(__name__)
threading.Thread(target=eng.start_engine, daemon=True).start()

def _on_exit(*_):
    eng.stop_engine(); os._exit(0)
signal.signal(signal.SIGTERM, _on_exit)
signal.signal(signal.SIGINT,  _on_exit)

# =============================================================================
# DISPLAY HELPERS
# =============================================================================

_RULE_META = {
    "brute_force":     ("Brute-force Login",      "🔑"),
    "priv_escalation": ("Privilege Escalation",    "⬆️"),
    "proc_anomaly":    ("Process Anomaly",         "⚙️"),
    "file_integrity":  ("File Tampered",           "📄"),
    "susp_process":    ("Suspicious Process",      "👾"),
    "syn_flood":       ("SYN Flood",               "🌊"),
    "udp_flood":       ("UDP Flood",               "💧"),
    "icmp_flood":      ("ICMP Flood",              "🏓"),
    "dns_tunnel":      ("DNS Tunneling",           "🔮"),
    "arp_spoof":       ("ARP Spoofing",            "🎭"),
    "engine":          ("System",                  "ℹ️"),
}

_LEVEL_COLOR = {
    "CRITICAL": "#ff3d57", "HIGH": "#ff6b35",
    "MEDIUM":   "#f59e0b", "LOW":  "#38b2ff", "INFO": "#4a6a85",
}
_LEVEL_BG = {
    "CRITICAL": "rgba(255,61,87,.09)",  "HIGH":  "rgba(255,107,53,.09)",
    "MEDIUM":   "rgba(245,158,11,.09)", "LOW":   "rgba(56,178,255,.09)",
    "INFO":     "rgba(74,106,133,.06)",
}

def _enrich(row: dict) -> dict:
    rule  = row.get("rule","")
    level = row.get("level","INFO")
    disp  = rule[5:] if rule.startswith("scan_") else rule
    label, icon = _RULE_META.get(disp, ("Alert","⚠️"))
    if rule.startswith("scan_"):
        label=f"Port Scan ({rule[5:]})"
        icon="🔍"
    row["label"]  = label
    row["icon"]   = icon
    row["color"]  = _LEVEL_COLOR.get(level,"#888")
    row["bg"]     = _LEVEL_BG.get(level,"rgba(100,100,100,.06)")
    row["score"]  = row.get("score",0)
    return row

def _uptime() -> str:
    st = eng.hids_state.get("uptime_start")
    if st and eng.is_running():
        s=int((datetime.now()-st).total_seconds())
        h,r=divmod(s,3600); m,sec=divmod(r,60)
        return f"{h:02d}:{m:02d}:{sec:02d}"
    return ""

# =============================================================================
# MAIN DASHBOARD HTML
# =============================================================================

DASH_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ulinzi HIDS v4</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=Inter:wght@300;400;500;600&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#07090f;--bg2:#0c1220;--surf:#101828;--brd:#1a2d45;--brd2:#274060;
  --txt:#c8d8ed;--mut:#3a5472;--dim:#1a2f45;
  --grn:#00d48a;--red:#ff3d57;--org:#ff6b35;--amb:#f59e0b;
  --blu:#38b2ff;--vio:#a855f7;--cyn:#22d3ee;--pnk:#f472b6;
  --font:'IBM Plex Mono',monospace;--ui:'Inter',sans-serif;
  --radius:8px;
}
html,body{min-height:100%;background:var(--bg);color:var(--txt);font-family:var(--ui);font-size:14px}

/* scanlines */
body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:9999;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,
  rgba(0,0,0,.03) 2px,rgba(0,0,0,.03) 4px)}

/* layout */
.shell{display:grid;grid-template-rows:56px 1fr;height:100vh}
nav{background:var(--bg2);border-bottom:1px solid var(--brd);
    display:flex;align-items:center;justify-content:space-between;
    padding:0 1.25rem;position:sticky;top:0;z-index:100}
.nav-brand{display:flex;align-items:center;gap:.6rem}
.nav-ring{width:10px;height:10px;border-radius:50%;border:2px solid var(--blu);
  box-shadow:0 0 8px var(--blu);animation:pulse 2s ease-in-out infinite;flex-shrink:0}
@keyframes pulse{0%,100%{box-shadow:0 0 4px var(--blu)}
  50%{box-shadow:0 0 18px var(--blu),0 0 36px rgba(56,178,255,.2)}}
.nav-title{font-family:var(--font);font-size:.85rem;color:var(--blu);letter-spacing:.14em}
.nav-sub{font-size:.58rem;color:var(--mut);letter-spacing:.06em}
.nav-r{display:flex;align-items:center;gap:.7rem}
.nav-clock{font-family:var(--font);font-size:.72rem;color:var(--mut)}
.nav-phase{font-family:var(--font);font-size:.65rem;letter-spacing:.08em;
  text-transform:uppercase;padding:.18rem .5rem;border-radius:3px;border:1px solid}
.ph-stopped  {color:var(--red);border-color:rgba(255,61,87,.4)}
.ph-baseline {color:var(--amb);border-color:rgba(245,158,11,.4);animation:blink .8s step-end infinite}
.ph-detecting{color:var(--grn);border-color:rgba(0,212,138,.4)}
@keyframes blink{50%{opacity:.4}}
.nav-link{background:none;border:1px solid var(--brd);border-radius:4px;
  color:var(--mut);font-family:var(--font);font-size:.63rem;padding:.22rem .55rem;
  cursor:pointer;text-decoration:none;transition:.12s}
.nav-link:hover{color:var(--txt);border-color:var(--brd2)}
.nav-link.active{color:var(--blu);border-color:rgba(56,178,255,.4)}

main{overflow-y:auto;padding:1rem}

/* pages */
.page{display:none}.page.active{display:grid;gap:1rem}

/* stat strip */
.strip{display:grid;grid-template-columns:repeat(5,1fr) 1fr 1fr 220px;gap:.65rem}
@media(max-width:900px){.strip{grid-template-columns:repeat(4,1fr)}}
@media(max-width:600px){.strip{grid-template-columns:repeat(2,1fr)}}
.pill{background:var(--surf);border:1px solid var(--brd);border-radius:var(--radius);
  padding:.55rem .8rem;position:relative;overflow:hidden;cursor:default}
.pill::before{content:'';position:absolute;top:0;left:0;right:0;height:2px}
.pill-crit::before{background:var(--red)}.pill-high::before{background:var(--org)}
.pill-med::before{background:var(--amb)}.pill-low::before{background:var(--blu)}
.pill-info::before{background:var(--mut)}.pill-host::before{background:var(--pnk)}
.pill-net::before{background:var(--cyn)}.pill-total::before{background:var(--vio)}
.pill-lbl{font-family:var(--font);font-size:.52rem;letter-spacing:.1em;
  text-transform:uppercase;color:var(--mut);margin-bottom:.15rem}
.pill-val{font-size:1.7rem;font-weight:600;line-height:1}
.v-crit{color:var(--red)}.v-high{color:var(--org)}.v-med{color:var(--amb)}
.v-low{color:var(--blu)}.v-info{color:var(--mut)}.v-host{color:var(--pnk)}
.v-net{color:var(--cyn)}.v-total{color:var(--vio)}
.spark-wrap{background:var(--surf);border:1px solid var(--brd);
  border-radius:var(--radius);padding:.55rem .8rem}
.spark-lbl{font-family:var(--font);font-size:.52rem;letter-spacing:.1em;
  text-transform:uppercase;color:var(--mut);margin-bottom:.25rem}
#spark{display:block;width:100%;height:42px}

/* 3-col layout */
.cols3{display:grid;grid-template-columns:260px 1fr 240px;gap:1rem;align-items:start}
@media(max-width:1100px){.cols3{grid-template-columns:1fr 2fr}}
@media(max-width:750px) {.cols3{grid-template-columns:1fr}}

/* card */
.card{background:var(--surf);border:1px solid var(--brd);border-radius:var(--radius);overflow:hidden}
.card-hdr{padding:.5rem .9rem;border-bottom:1px solid var(--brd);
  font-family:var(--font);font-size:.55rem;letter-spacing:.13em;
  text-transform:uppercase;color:var(--mut);
  display:flex;justify-content:space-between;align-items:center}
.card-body{padding:.85rem}

/* phase badge */
.badge{display:flex;align-items:center;gap:.4rem;padding:.35rem .65rem;
  border-radius:4px;font-family:var(--font);font-size:.68rem;letter-spacing:.06em;
  text-transform:uppercase;border:1px solid;margin-bottom:.75rem;justify-content:center}
.badge-stopped  {background:rgba(255,61,87,.07);color:var(--red);border-color:rgba(255,61,87,.3)}
.badge-baseline {background:rgba(245,158,11,.07);color:var(--amb);border-color:rgba(245,158,11,.3)}
.badge-detecting{background:rgba(0,212,138,.07);color:var(--grn);border-color:rgba(0,212,138,.3)}
.bdot{width:6px;height:6px;border-radius:50%;flex-shrink:0}
.bdot-stopped{background:var(--red)}.bdot-detecting{background:var(--grn);box-shadow:0 0 6px var(--grn)}
.bdot-baseline{background:var(--amb);animation:blink .7s step-end infinite}

/* progress */
.prog-wrap{margin-bottom:.75rem}.prog-hidden{display:none!important}
.prog-row{display:flex;justify-content:space-between;font-family:var(--font);
  font-size:.6rem;color:var(--mut);margin-bottom:.2rem}
.prog-track{height:4px;background:var(--dim);border-radius:2px;overflow:hidden}
.prog-bar{height:100%;background:linear-gradient(90deg,var(--amb),var(--blu));
  border-radius:2px;transition:width .6s ease}

/* warn box */
.warn{background:rgba(245,158,11,.07);border:1px solid rgba(245,158,11,.25);
  border-radius:4px;padding:.38rem .6rem;margin-bottom:.75rem;
  font-family:var(--font);font-size:.6rem;color:var(--amb);line-height:1.5}
.warn.hidden{display:none}

/* monitor grid */
.mon-grid{display:grid;grid-template-columns:1fr 1fr;gap:.3rem;margin-bottom:.75rem}
.mon-pill{background:var(--bg2);border:1px solid var(--brd);border-radius:4px;
  padding:.25rem .45rem;font-family:var(--font);font-size:.58rem}
.mon-lbl{color:var(--mut);font-size:.52rem;letter-spacing:.05em;text-transform:uppercase;margin-bottom:.05rem}
.mon-val{display:flex;align-items:center;gap:.25rem}
.mdot{width:5px;height:5px;border-radius:50%;flex-shrink:0}
.mon-on{background:var(--grn)}.mon-off{background:var(--red)}

/* meta table */
.meta{width:100%;border-collapse:collapse;font-family:var(--font);
  font-size:.65rem;margin-bottom:.75rem}
.meta td{padding:.25rem 0;border-bottom:1px solid var(--brd)}
.meta td:first-child{color:var(--mut);width:46%}
.meta td:last-child{color:var(--txt);text-align:right;font-size:.6rem}

/* traffic bars */
.tbars{display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:.2rem;margin-bottom:.75rem}
.tbar-wrap{}.tbar-lbl{display:flex;justify-content:space-between;
  font-family:var(--font);font-size:.52rem;color:var(--mut);margin-top:.08rem}
.tbar-track{height:3px;background:var(--dim);border-radius:2px;overflow:hidden;margin-top:.2rem}
.tbar-fill{height:100%;border-radius:2px;transition:width .4s ease}
.tbars-title{font-family:var(--font);font-size:.55rem;letter-spacing:.09em;
  text-transform:uppercase;color:var(--mut);margin-bottom:.35rem}

/* buttons */
.btns{display:grid;grid-template-columns:1fr 1fr;gap:.45rem;margin-bottom:.45rem}
.btn{width:100%;padding:.45rem;border:1px solid;border-radius:4px;
  font-family:var(--ui);font-size:.78rem;font-weight:500;letter-spacing:.03em;
  text-transform:uppercase;cursor:pointer;transition:.12s;background:none}
.btn:disabled{opacity:.2;cursor:not-allowed}
.btn-start{color:var(--grn);border-color:rgba(0,212,138,.4);background:rgba(0,212,138,.05)}
.btn-start:not(:disabled):hover{box-shadow:0 0 14px rgba(0,212,138,.2)}
.btn-stop {color:var(--red);border-color:rgba(255,61,87,.4);background:rgba(255,61,87,.05)}
.btn-stop:not(:disabled):hover{box-shadow:0 0 14px rgba(255,61,87,.2)}
.btn-clear{width:100%;color:var(--mut);border-color:var(--brd);
  font-size:.68rem;padding:.35rem;background:none;cursor:pointer;
  font-family:var(--ui);text-transform:uppercase;border-radius:4px}

/* alert feed */
.feed-hdr{display:flex;justify-content:space-between;align-items:center}
.feed-left{display:flex;align-items:center;gap:.5rem}
.ldot{width:6px;height:6px;border-radius:50%;background:var(--grn);
  box-shadow:0 0 5px var(--grn);animation:blink .9s step-end infinite}
.ldot.paused{background:var(--mut);box-shadow:none;animation:none}
.fc{font-family:var(--font);font-size:.62rem;color:var(--mut)}
.fbtn,.ftab{background:none;border:1px solid var(--brd);border-radius:3px;
  color:var(--mut);font-family:var(--font);font-size:.6rem;
  padding:.1rem .38rem;cursor:pointer;text-transform:uppercase;letter-spacing:.04em}
.fbtn:hover,.ftab:hover{color:var(--txt);border-color:var(--brd2)}
.ftab.on{color:var(--txt);border-color:var(--brd2);background:var(--brd)}
.filters{display:flex;gap:.22rem;flex-wrap:wrap}
.feed{max-height:calc(100vh - 280px);min-height:300px;overflow-y:auto;
  padding:.3rem;scrollbar-width:thin;scrollbar-color:var(--brd) transparent}
.feed::-webkit-scrollbar{width:3px}
.feed::-webkit-scrollbar-thumb{background:var(--brd);border-radius:2px}

/* alert card */
.acard{display:grid;grid-template-columns:28px 1fr auto;gap:.4rem;align-items:start;
  padding:.5rem .6rem;border-radius:5px;border:1px solid var(--brd);
  border-left:3px solid;margin-bottom:.3rem;
  animation:fadein .16s ease;font-family:var(--font);font-size:.65rem}
@keyframes fadein{from{opacity:0;transform:translateY(-2px)}to{opacity:1;transform:none}}
.acard:hover{border-color:var(--brd2)}
.ac-icon{font-size:.9rem;line-height:1.3;text-align:center}
.ac-top{display:flex;align-items:center;gap:.35rem;margin-bottom:.1rem;flex-wrap:wrap}
.ac-lv{font-size:.55rem;font-weight:700;letter-spacing:.09em;
  padding:.04rem .28rem;border-radius:2px;text-transform:uppercase}
.ac-label{font-size:.65rem;font-weight:600;letter-spacing:.04em;text-transform:uppercase}
.ac-detail{color:var(--mut);font-size:.6rem;line-height:1.55;word-break:break-all}
.ac-score{color:var(--dim);font-size:.58rem}
.ac-ts{color:var(--dim);font-size:.58rem;white-space:nowrap;text-align:right;padding-top:.1rem}
.lv-CRITICAL{background:rgba(255,61,87,.15);color:#ff3d57}
.lv-HIGH    {background:rgba(255,107,53,.15);color:#ff6b35}
.lv-MEDIUM  {background:rgba(245,158,11,.15);color:#f59e0b}
.lv-LOW     {background:rgba(56,178,255,.15);color:#38b2ff}
.lv-INFO    {background:rgba(74,106,133,.15);color:#4a6a85}
.empty{display:flex;flex-direction:column;align-items:center;
  justify-content:center;height:200px;color:var(--dim);
  font-family:var(--font);font-size:.68rem;gap:.35rem}
.empty-icon{font-size:2rem;opacity:.2}

/* attackers table */
.atk-table{width:100%;border-collapse:collapse;font-family:var(--font);font-size:.62rem}
.atk-table th{color:var(--mut);font-size:.52rem;letter-spacing:.08em;
  text-transform:uppercase;padding:.3rem .4rem;border-bottom:1px solid var(--brd);
  text-align:left;font-weight:400}
.atk-table td{padding:.3rem .4rem;border-bottom:1px solid var(--dim);vertical-align:top}
.atk-table tr:hover td{background:rgba(255,255,255,.02)}
.atk-ip{color:var(--red);font-size:.65rem}
.atk-cnt{color:var(--amb)}
.atk-lv{font-size:.55rem;font-weight:700;padding:.02rem .25rem;border-radius:2px}
.tag{background:var(--dim);border-radius:3px;padding:.03rem .25rem;
  font-size:.52rem;color:var(--mut);display:inline-block;margin:.05rem}

/* chart canvas */
.chart-wrap{padding:.75rem .9rem}
#hourly-chart{width:100%;height:120px;display:block}

/* settings page */
.settings-grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
@media(max-width:700px){.settings-grid{grid-template-columns:1fr}}
.form-group{margin-bottom:.9rem}
.form-label{font-family:var(--font);font-size:.6rem;letter-spacing:.08em;
  text-transform:uppercase;color:var(--mut);display:block;margin-bottom:.3rem}
.form-input{width:100%;background:var(--bg2);border:1px solid var(--brd);
  border-radius:4px;color:var(--txt);font-family:var(--font);font-size:.72rem;
  padding:.4rem .55rem;outline:none;transition:.12s}
.form-input:focus{border-color:var(--blu);box-shadow:0 0 0 2px rgba(56,178,255,.12)}
.toggle-wrap{display:flex;align-items:center;gap:.5rem;margin-bottom:.4rem}
.toggle{position:relative;width:32px;height:18px;flex-shrink:0}
.toggle input{opacity:0;width:0;height:0}
.toggle-slider{position:absolute;cursor:pointer;inset:0;background:var(--dim);
  border-radius:18px;transition:.2s}
.toggle-slider::before{content:'';position:absolute;height:12px;width:12px;
  left:3px;bottom:3px;background:var(--mut);border-radius:50%;transition:.2s}
.toggle input:checked+.toggle-slider{background:rgba(0,212,138,.3)}
.toggle input:checked+.toggle-slider::before{transform:translateX(14px);background:var(--grn)}
.toggle-lbl{font-family:var(--font);font-size:.68rem;color:var(--txt)}
.btn-save{background:rgba(56,178,255,.08);border:1px solid rgba(56,178,255,.4);
  color:var(--blu);font-family:var(--ui);font-size:.78rem;font-weight:500;
  padding:.45rem 1.2rem;border-radius:4px;cursor:pointer;transition:.12s}
.btn-save:hover{box-shadow:0 0 12px rgba(56,178,255,.2)}
.flash-ok {margin-top:.6rem;padding:.3rem .5rem;border-radius:4px;
  font-family:var(--font);font-size:.65rem;
  color:var(--grn);background:rgba(0,212,138,.07);border:1px solid rgba(0,212,138,.3)}
.flash-err{margin-top:.6rem;padding:.3rem .5rem;border-radius:4px;
  font-family:var(--font);font-size:.65rem;
  color:var(--red);background:rgba(255,61,87,.07);border:1px solid rgba(255,61,87,.3)}
.ntfy-guide{background:var(--bg2);border:1px solid var(--brd);border-radius:6px;
  padding:.75rem .9rem;font-family:var(--font);font-size:.62rem;line-height:1.7;color:var(--mut)}
.ntfy-guide h4{color:var(--txt);font-size:.68rem;margin-bottom:.4rem;letter-spacing:.05em}
.ntfy-guide code{color:var(--blu);background:var(--dim);padding:.02rem .2rem;
  border-radius:3px;font-size:.65rem}
.ntfy-guide a{color:var(--cyn);text-decoration:none}
.ntfy-guide a:hover{text-decoration:underline}
.ntfy-step{margin-bottom:.4rem}
</style>
</head>
<body>
<div class="shell">

<!-- NAV -->
<nav>
  <div class="nav-brand">
    <div class="nav-ring"></div>
    <div>
      <div class="nav-title">ULINZI HIDS <span style="font-size:.62rem;color:var(--mut)">v4</span></div>
      <div class="nav-sub">HOST INTRUSION DETECTION · STRATHMORE UNIVERSITY</div>
    </div>
  </div>
  <div class="nav-r">
    <div class="nav-clock" id="clock"></div>
    <div id="nav-phase" class="nav-phase ph-stopped">stopped</div>
    <a class="nav-link active" id="tab-dash" onclick="showPage('dash',this)">Dashboard</a>
    <a class="nav-link" id="tab-atk"  onclick="showPage('atk',this)">Attackers</a>
    <a class="nav-link" id="tab-set"  onclick="showPage('set',this)">⚙ Settings</a>
  </div>
</nav>

<main>

<!-- ══ DASHBOARD PAGE ══ -->
<div class="page active" id="page-dash">

  <!-- Stat strip -->
  <div class="strip">
    <div class="pill pill-crit"><div class="pill-lbl">Critical</div><div class="pill-val v-crit" id="c-CRITICAL">0</div></div>
    <div class="pill pill-high"><div class="pill-lbl">High</div>    <div class="pill-val v-high" id="c-HIGH">0</div></div>
    <div class="pill pill-med" ><div class="pill-lbl">Medium</div>  <div class="pill-val v-med"  id="c-MEDIUM">0</div></div>
    <div class="pill pill-low" ><div class="pill-lbl">Low</div>     <div class="pill-val v-low"  id="c-LOW">0</div></div>
    <div class="pill pill-info"><div class="pill-lbl">Info</div>    <div class="pill-val v-info" id="c-INFO">0</div></div>
    <div class="pill pill-host"><div class="pill-lbl">Host</div>    <div class="pill-val v-host" id="c-host">0</div></div>
    <div class="pill pill-net" ><div class="pill-lbl">Network</div> <div class="pill-val v-net"  id="c-net">0</div></div>
    <div class="spark-wrap">
      <div class="spark-lbl">Alerts / min · last 30 min</div>
      <canvas id="spark" width="220" height="42"></canvas>
    </div>
  </div>

  <!-- 3 columns -->
  <div class="cols3">

    <!-- LEFT: controls -->
    <div class="card">
      <div class="card-hdr"><span>System Control</span>
        <span id="win-counter" style="color:var(--vio);font-size:.6rem">0 windows</span>
      </div>
      <div class="card-body">

        <div id="badge" class="badge badge-stopped">
          <span class="bdot bdot-stopped" id="bdot"></span>
          <span id="badge-txt">Stopped</span>
        </div>

        <div id="prog-wrap" class="prog-wrap prog-hidden">
          <div class="prog-row"><span>Baseline learning</span><span id="prog-pct">0%</span></div>
          <div class="prog-track"><div id="prog-bar" class="prog-bar" style="width:0%"></div></div>
        </div>

        <div id="sudo-warn" class="warn hidden">
          ⚠ Network rules N1-N6 disabled.<br>
          Restart with <code style="color:var(--amb)">sudo python3 app.py</code> to enable SYN/UDP/ICMP flood, port scan, DNS tunnel and ARP spoof detection.
        </div>

        <div class="tbars-title">Live inbound traffic (pkts/s)</div>
        <div class="tbars">
          <div class="tbar-wrap">
            <div class="tbar-track"><div id="tb-syn"  class="tbar-fill" style="width:0%;background:var(--red)"></div></div>
            <div class="tbar-lbl"><span>SYN</span><span id="tv-syn">0</span></div>
          </div>
          <div class="tbar-wrap">
            <div class="tbar-track"><div id="tb-udp"  class="tbar-fill" style="width:0%;background:var(--org)"></div></div>
            <div class="tbar-lbl"><span>UDP</span><span id="tv-udp">0</span></div>
          </div>
          <div class="tbar-wrap">
            <div class="tbar-track"><div id="tb-icmp" class="tbar-fill" style="width:0%;background:var(--amb)"></div></div>
            <div class="tbar-lbl"><span>ICMP</span><span id="tv-icmp">0</span></div>
          </div>
          <div class="tbar-wrap">
            <div class="tbar-track"><div id="tb-tot"  class="tbar-fill" style="width:0%;background:var(--blu)"></div></div>
            <div class="tbar-lbl"><span>TOT</span><span id="tv-tot">0</span></div>
          </div>
        </div>

        <div class="mon-grid">
          <div class="mon-pill"><div class="mon-lbl">Auth Log</div>
            <div class="mon-val" id="m-auth"><div class="mdot mon-off"></div>—</div></div>
          <div class="mon-pill"><div class="mon-lbl">Process Mon</div>
            <div class="mon-val" id="m-proc"><div class="mdot mon-off"></div>—</div></div>
          <div class="mon-pill"><div class="mon-lbl">File Integrity</div>
            <div class="mon-val" id="m-fim"><div class="mdot mon-off"></div>—</div></div>
          <div class="mon-pill"><div class="mon-lbl">Network Cap</div>
            <div class="mon-val" id="m-net"><div class="mdot mon-off"></div>—</div></div>
          <div class="mon-pill" style="grid-column:span 2"><div class="mon-lbl">Push Notifications</div>
            <div class="mon-val" id="m-ntfy"><div class="mdot mon-off"></div>—</div></div>
        </div>

        <table class="meta">
          <tr><td>Uptime</td>   <td id="mt-up">—</td></tr>
          <tr><td>Interface</td><td id="mt-if">—</td></tr>
          <tr><td>Window</td>   <td>1s</td></tr>
          <tr><td>Baseline</td> <td>60s</td></tr>
          <tr><td>Alert log</td><td>alerts.log</td></tr>
          <tr><td>Database</td> <td>ulinzi.db</td></tr>
          <tr><td>Last alert</td><td id="mt-last">—</td></tr>
        </table>

        <div class="btns">
          <form method="POST" action="/start" style="margin:0">
            <button class="btn btn-start" id="btn-start">▶ Start</button>
          </form>
          <form method="POST" action="/stop" style="margin:0">
            <button class="btn btn-stop" id="btn-stop">■ Stop</button>
          </form>
        </div>
        <form method="POST" action="/clear" style="margin:0">
          <button class="btn-clear">⊘ Clear alert log</button>
        </form>

      </div>
    </div>

    <!-- CENTRE: alert feed -->
    <div class="card" style="display:flex;flex-direction:column">
      <div class="card-hdr feed-hdr">
        <div class="feed-left">
          <div class="ldot" id="ldot"></div>
          <span class="fc" id="feed-count">0 alerts</span>
          <button class="fbtn" id="pbtn" onclick="togglePause()">Pause</button>
        </div>
        <div class="filters">
          <button class="ftab on" onclick="setF('ALL',this)">All</button>
          <button class="ftab" onclick="setF('CRITICAL',this)">Crit</button>
          <button class="ftab" onclick="setF('HIGH',this)">High</button>
          <button class="ftab" onclick="setF('MEDIUM',this)">Med</button>
          <button class="ftab" onclick="setF('LOW',this)">Low</button>
          <button class="ftab" onclick="setF('INFO',this)">Info</button>
        </div>
      </div>
      <div class="feed" id="feed">
        <div class="empty"><div class="empty-icon">◎</div><div>Starting…</div></div>
      </div>
    </div>

    <!-- RIGHT: hourly chart -->
    <div class="card">
      <div class="card-hdr">Alerts · last 24 h</div>
      <div class="chart-wrap">
        <canvas id="hourly-chart"></canvas>
      </div>
    </div>

  </div>
</div>

<!-- ══ ATTACKERS PAGE ══ -->
<div class="page" id="page-atk">
  <div class="card">
    <div class="card-hdr">Top Attackers (by event count)</div>
    <div class="card-body" style="padding:.5rem">
      <table class="atk-table" id="atk-table">
        <thead><tr>
          <th>Source IP</th><th>Events</th><th>Max Level</th>
          <th>Attack Types</th><th>First Seen</th><th>Last Seen</th>
        </tr></thead>
        <tbody id="atk-body">
          <tr><td colspan="6" style="text-align:center;color:var(--mut);padding:1.5rem;
            font-family:var(--font);font-size:.65rem">No attackers recorded yet</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</div>

<!-- ══ SETTINGS PAGE ══ -->
<div class="page" id="page-set">
  <div class="settings-grid">
    <div>
      <div class="card">
        <div class="card-hdr">Push Notifications (ntfy.sh)</div>
        <div class="card-body">
          <form id="ntfy-form">
            <div class="toggle-wrap">
              <label class="toggle">
                <input type="checkbox" id="ntfy-enabled">
                <span class="toggle-slider"></span>
              </label>
              <span class="toggle-lbl">Enable push notifications</span>
            </div>
            <div class="form-group">
              <label class="form-label">ntfy Topic (your private channel name)</label>
              <input class="form-input" id="ntfy-topic" type="text"
                     placeholder="e.g. ulinzi-kali-alerts-mybrandonthing">
            </div>
            <div class="form-group">
              <label class="form-label">ntfy Server</label>
              <input class="form-input" id="ntfy-server" type="text"
                     value="https://ntfy.sh" placeholder="https://ntfy.sh">
            </div>
            <div class="form-group">
              <label class="form-label">Minimum alert level to push</label>
              <select class="form-input" id="ntfy-min-level">
                <option value="LOW">Low and above</option>
                <option value="MEDIUM" selected>Medium and above</option>
                <option value="HIGH">High and above</option>
                <option value="CRITICAL">Critical only</option>
              </select>
            </div>
            <div class="form-group">
              <label class="form-label">ntfy Access Token (optional — for private topics)</label>
              <input class="form-input" id="ntfy-token" type="password"
                     placeholder="tk_xxxxxxxxx (leave blank for public topics)">
            </div>
            <button class="btn-save" type="button" onclick="saveNtfy()">Save & Apply</button>
            <div id="ntfy-flash"></div>
          </form>
        </div>
      </div>
    </div>

    <div>
      <div class="card">
        <div class="card-hdr">How to Get Phone Notifications</div>
        <div class="card-body">
          <div class="ntfy-guide">
            <h4>📱 Setup (takes 2 minutes, free, no account needed)</h4>
            <div class="ntfy-step">
              <strong style="color:var(--txt)">1. Install ntfy on your phone</strong><br>
              Android: <a href="https://play.google.com/store/apps/details?id=io.heckel.ntfy" target="_blank">Google Play Store</a>
              or <a href="https://f-droid.org/packages/io.heckel.ntfy/" target="_blank">F-Droid</a><br>
              iOS: <a href="https://apps.apple.com/app/ntfy/id1625396347" target="_blank">App Store</a>
            </div>
            <div class="ntfy-step">
              <strong style="color:var(--txt)">2. Subscribe to your topic</strong><br>
              Open ntfy app → tap <code>+</code> → enter your topic name<br>
              Example topic: <code>ulinzi-brandon-kali</code>
            </div>
            <div class="ntfy-step">
              <strong style="color:var(--txt)">3. Configure Ulinzi</strong><br>
              Enter the same topic name in the form on the left → Save
            </div>
            <div class="ntfy-step">
              <strong style="color:var(--txt)">4. Test it</strong><br>
              Click the <code>Test Notification</code> button below — your phone should buzz within 2 seconds
            </div>
            <div class="ntfy-step" style="margin-top:.6rem">
              <strong style="color:var(--amb)">⚠ Topic names are public by default.</strong><br>
              Use a long random-looking name, or create a paid ntfy account for private topics.
            </div>
            <button class="btn-save" style="margin-top:.65rem" onclick="testNtfy()">📣 Test Notification</button>
            <div id="test-flash"></div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

</main>
</div><!-- /shell -->

<script>
// ── clock ────────────────────────────────────────────────────────────────────
const clockEl=document.getElementById('clock');
function tick(){clockEl.textContent=new Date().toLocaleString();}
tick();setInterval(tick,1000);

// ── page nav ─────────────────────────────────────────────────────────────────
function showPage(id,el){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-link').forEach(a=>a.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  el.classList.add('active');
  if(id==='atk') loadAttackers();
  if(id==='set') loadSettings();
}

// ── spark ────────────────────────────────────────────────────────────────────
let sparkData=Array(30).fill(0);
function drawSpark(d){
  const c=document.getElementById('spark');if(!c)return;
  const W=c.offsetWidth||220,H=42,max=Math.max(...d,1);
  c.width=W;c.height=H;
  const ctx=c.getContext('2d');ctx.clearRect(0,0,W,H);
  const bw=W/d.length;
  d.forEach((v,i)=>{
    if(!v)return;
    const h=(v/max)*(H-4),x=i*bw,t=v/max;
    ctx.fillStyle=t>.7?`rgba(255,61,87,${.5+t*.4})`
                 :t>.35?`rgba(245,158,11,${.3+t*.5})`
                 :`rgba(56,178,255,${.2+t*.5})`;
    ctx.fillRect(x+1,H-h,Math.max(bw-2,1),h);
  });
}
drawSpark(sparkData);
window.addEventListener('resize',()=>drawSpark(sparkData));

// ── hourly chart ─────────────────────────────────────────────────────────────
let hourlyData=[];
function drawHourly(data){
  const c=document.getElementById('hourly-chart');if(!c||!data.length)return;
  const W=c.offsetWidth||220,H=120;
  c.width=W;c.height=H;
  const ctx=c.getContext('2d');ctx.clearRect(0,0,W,H);
  const maxV=Math.max(...data.map(d=>d.CRITICAL+d.HIGH+d.MEDIUM+d.LOW),1);
  const bw=W/data.length;
  const COLS={CRITICAL:'rgba(255,61,87,.8)',HIGH:'rgba(255,107,53,.7)',
              MEDIUM:'rgba(245,158,11,.7)',LOW:'rgba(56,178,255,.5)'};
  data.forEach((d,i)=>{
    let y=H;
    ['LOW','MEDIUM','HIGH','CRITICAL'].forEach(lv=>{
      if(!d[lv])return;
      const h=(d[lv]/maxV)*(H-6);
      y-=h;
      ctx.fillStyle=COLS[lv];
      ctx.fillRect(i*bw+1,y,Math.max(bw-2,1),h);
    });
  });
}

// ── filter / pause ───────────────────────────────────────────────────────────
let activeF='ALL',paused=false;
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
function togglePause(){
  paused=!paused;
  document.getElementById('pbtn').textContent=paused?'Resume':'Pause';
  document.getElementById('ldot').classList.toggle('paused',paused);
}

// ── traffic bars ─────────────────────────────────────────────────────────────
function setBar(id,val,mx){
  const b=document.getElementById('tb-'+id),l=document.getElementById('tv-'+id);
  if(b)b.style.width=Math.min((val/Math.max(mx,1))*100,100)+'%';
  if(l)l.textContent=val>999?(val/1000).toFixed(1)+'k':Math.round(val);
}

// ── helpers ──────────────────────────────────────────────────────────────────
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
const LBG={CRITICAL:'rgba(255,61,87,.09)',HIGH:'rgba(255,107,53,.09)',
           MEDIUM:'rgba(245,158,11,.09)',LOW:'rgba(56,178,255,.09)',INFO:'rgba(74,106,133,.06)'};
const LCOL={CRITICAL:'#ff3d57',HIGH:'#ff6b35',MEDIUM:'#f59e0b',LOW:'#38b2ff',INFO:'#4a6a85'};
const LLVLBG={CRITICAL:'rgba(255,61,87,.15)',HIGH:'rgba(255,107,53,.15)',
              MEDIUM:'rgba(245,158,11,.15)',LOW:'rgba(56,178,255,.15)',INFO:'rgba(74,106,133,.15)'};

function buildCard(a){
  const bg=LBG[a.level]||'rgba(100,100,100,.06)';
  const col=LCOL[a.level]||'#888';
  const lvbg=LLVLBG[a.level]||'rgba(100,100,100,.15)';
  return `<div class="acard" data-lv="${esc(a.level)}"
    style="border-left-color:${col};background:${bg}">
    <div class="ac-icon">${esc(a.icon||'⚠️')}</div>
    <div>
      <div class="ac-top">
        <span class="ac-lv lv-${esc(a.level)}">${esc(a.level)}</span>
        <span class="ac-label" style="color:${col}">${esc(a.label||a.rule)}</span>
      </div>
      <div class="ac-detail">${esc(a.detail)}</div>
      <div class="ac-score">score ${a.score||0}/100</div>
    </div>
    <div class="ac-ts">${esc(a.ts?a.ts.slice(11):'')}</div>
  </div>`;
}

// ── phase UI ─────────────────────────────────────────────────────────────────
const PHASES={stopped:'Stopped',baseline:'Baseline…',detecting:'Detecting'};
function applyPhase(phase,bpct,running){
  const bdg=document.getElementById('badge');
  const bdot=document.getElementById('bdot');
  const btxt=document.getElementById('badge-txt');
  const ph=document.getElementById('nav-phase');
  bdg.className='badge badge-'+phase;
  bdot.className='bdot bdot-'+phase;
  btxt.textContent=PHASES[phase]||phase;
  ph.className='nav-phase ph-'+phase;
  ph.textContent=PHASES[phase]||phase;
  const pw=document.getElementById('prog-wrap');
  const pb=document.getElementById('prog-bar');
  const pp=document.getElementById('prog-pct');
  if(phase==='baseline'){
    pw.classList.remove('prog-hidden');
    const p=Math.min((bpct||0)*100,99);
    if(pb)pb.style.width=p.toFixed(1)+'%';
    if(pp)pp.textContent=p.toFixed(0)+'%';
  }else{pw.classList.add('prog-hidden');}
  document.getElementById('btn-start').disabled=running;
  document.getElementById('btn-stop').disabled=!running;
}

function applyMonitors(mon,running){
  function setMon(id,on,label){
    const el=document.getElementById(id);if(!el)return;
    el.innerHTML=`<div class="mdot ${on?'mon-on':'mon-off'}"></div>${esc(label)}`;
  }
  setMon('m-auth',mon.auth_log, mon.auth_log?'Active':'N/A');
  setMon('m-proc',mon.psutil,   mon.psutil?'Active':'No psutil');
  setMon('m-fim', mon.fim_files>0, mon.fim_files+' files');
  const iface=mon.iface||'—';
  const netOk=running && !iface.includes('N/A') && iface!=='—';
  setMon('m-net', netOk, iface);
  document.getElementById('mt-if').textContent=iface;
  const sudoWarn=document.getElementById('sudo-warn');
  if(sudoWarn) sudoWarn.classList.toggle('hidden',netOk||!running);
  setMon('m-ntfy',mon.ntfy, mon.ntfy?'Active':'Disabled');
}

// ── main poll ─────────────────────────────────────────────────────────────────
let lastTs='';
async function poll(){
  try{
    const [sr,ar,mr,hr]=await Promise.all([
      fetch('/api/status'),fetch('/api/alerts?n=150'),
      fetch('/api/metrics'),fetch('/api/hourly')]);
    const st=await sr.json(),al=await ar.json(),
          mt=await mr.json(),hl=await hr.json();

    applyPhase(st.phase,st.baseline_pct,st.running);
    applyMonitors(st.monitors||{},st.running);

    const uEl=document.getElementById('mt-up');
    if(uEl)uEl.textContent=st.uptime||'—';
    const wEl=document.getElementById('win-counter');
    if(wEl)wEl.textContent=(st.windows||0)+' windows';

    // counts
    const c=mt.counts||{};
    ['CRITICAL','HIGH','MEDIUM','LOW','INFO'].forEach(k=>{
      const el=document.getElementById('c-'+k);if(el)el.textContent=c[k]??0;
    });
    document.getElementById('c-host').textContent=(mt.cat||{}).host??0;
    document.getElementById('c-net').textContent=(mt.cat||{}).network??0;

    // spark
    if(mt.spark){sparkData=mt.spark;drawSpark(sparkData);}

    // hourly
    if(hl.data){hourlyData=hl.data;drawHourly(hourlyData);}

    // traffic bars
    const ns=st.last_ns||{};
    setBar('syn', ns.syn_rate||0,  Math.max(ns.syn_rate||0,500));
    setBar('udp', ns.udp_rate||0,  Math.max(ns.udp_rate||0,2000));
    setBar('icmp',ns.icmp_rate||0, Math.max(ns.icmp_rate||0,200));
    setBar('tot', ns.total_rate||0,Math.max(ns.total_rate||0,3000));

    // last alert
    if(al.alerts&&al.alerts.length){
      const first=al.alerts.find(a=>a.level!=='INFO');
      const lEl=document.getElementById('mt-last');
      if(lEl)lEl.textContent=first?first.ts.slice(11):'—';
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
          if(cntEl)cntEl.textContent='0 alerts';
        }else{
          feed.innerHTML=al.alerts.map(buildCard).join('');
          if(cntEl)cntEl.textContent=al.alerts.length+' alert'+(al.alerts.length!==1?'s':'');
          applyF();
        }
      }
    }
  }catch(e){}
}
poll();setInterval(poll,2000);
window.addEventListener('resize',()=>{drawSpark(sparkData);drawHourly(hourlyData);});

// ── attackers ─────────────────────────────────────────────────────────────────
async function loadAttackers(){
  try{
    const r=await fetch('/api/attackers');const d=await r.json();
    const tb=document.getElementById('atk-body');if(!tb)return;
    if(!d.attackers||!d.attackers.length){
      tb.innerHTML='<tr><td colspan="6" style="text-align:center;color:var(--mut);padding:1.5rem;font-family:var(--font);font-size:.65rem">No attackers recorded yet</td></tr>';
      return;
    }
    const LV={CRITICAL:'#ff3d57',HIGH:'#ff6b35',MEDIUM:'#f59e0b',LOW:'#38b2ff'};
    const LVBG={CRITICAL:'rgba(255,61,87,.15)',HIGH:'rgba(255,107,53,.15)',MEDIUM:'rgba(245,158,11,.15)',LOW:'rgba(56,178,255,.15)'};
    tb.innerHTML=d.attackers.map(a=>{
      const types=JSON.parse(a.attack_types||'[]');
      const tags=types.map(t=>`<span class="tag">${esc(t)}</span>`).join('');
      const lvbg=LVBG[a.max_level]||'';const lvcol=LV[a.max_level]||'#888';
      return `<tr>
        <td class="atk-ip">${esc(a.ip)}</td>
        <td class="atk-cnt">${a.event_count}</td>
        <td><span class="atk-lv" style="background:${lvbg};color:${lvcol}">${esc(a.max_level)}</span></td>
        <td>${tags||'—'}</td>
        <td style="color:var(--mut);font-size:.58rem">${esc((a.first_seen||'').slice(11)||a.first_seen||'—')}</td>
        <td style="color:var(--mut);font-size:.58rem">${esc((a.last_seen||'').slice(11)||a.last_seen||'—')}</td>
      </tr>`;
    }).join('');
  }catch(e){}
}

// ── settings ──────────────────────────────────────────────────────────────────
async function loadSettings(){
  try{
    const r=await fetch('/api/config');const d=await r.json();
    document.getElementById('ntfy-enabled').checked=!!d.ntfy_enabled;
    document.getElementById('ntfy-topic').value=d.ntfy_topic||'';
    document.getElementById('ntfy-server').value=d.ntfy_server||'https://ntfy.sh';
    document.getElementById('ntfy-min-level').value=d.ntfy_min_level||'MEDIUM';
    document.getElementById('ntfy-token').value=d.ntfy_token||'';
  }catch(e){}
}

async function saveNtfy(){
  const payload={
    ntfy_enabled: document.getElementById('ntfy-enabled').checked,
    ntfy_topic:   document.getElementById('ntfy-topic').value.trim(),
    ntfy_server:  document.getElementById('ntfy-server').value.trim()||'https://ntfy.sh',
    ntfy_min_level: document.getElementById('ntfy-min-level').value,
    ntfy_token:   document.getElementById('ntfy-token').value.trim(),
  };
  try{
    const r=await fetch('/api/config',{method:'POST',
      headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    const d=await r.json();
    const fl=document.getElementById('ntfy-flash');
    fl.className=d.ok?'flash-ok':'flash-err';
    fl.textContent=d.ok?'✓ Saved and applied.':'✗ '+d.error;
    setTimeout(()=>fl.textContent='',4000);
  }catch(e){
    document.getElementById('ntfy-flash').textContent='Error: '+e;
  }
}

async function testNtfy(){
  try{
    const r=await fetch('/api/test-notification',{method:'POST'});
    const d=await r.json();
    const fl=document.getElementById('test-flash');
    fl.className=d.ok?'flash-ok':'flash-err';
    fl.textContent=d.ok?'✓ Test notification sent! Check your phone.':
                        '✗ '+(d.error||'Failed — check topic and server settings.');
    setTimeout(()=>fl.textContent='',6000);
  }catch(e){document.getElementById('test-flash').textContent='Error: '+e;}
}
</script>
</body>
</html>"""

# =============================================================================
# ROUTES — PAGES
# =============================================================================

@app.get("/")
def index():
    return DASH_HTML


@app.post("/start")
def start():
    if not eng.is_running():
        eng.start_engine()
    return redirect(url_for("index"))


@app.post("/stop")
def stop():
    if eng.is_running():
        eng.stop_engine()
    return redirect(url_for("index"))


@app.post("/clear")
def clear():
    try:
        if os.path.exists(ALERT_LOG):
            os.replace(ALERT_LOG, ALERT_LOG + ".bak")
        if os.path.exists(eng.CFG.get("json_log","alerts.jsonl")):
            os.replace(eng.CFG["json_log"], eng.CFG["json_log"] + ".bak")
    except OSError: pass
    return redirect(url_for("index"))


# =============================================================================
# ROUTES — JSON API
# =============================================================================

@app.get("/api/status")
def api_status():
    st  = eng.get_state()
    ns  = st.get("last_ns")
    ns_d = {}
    if ns:
        ns_d = {"syn_rate": round(ns.syn_rate,1), "udp_rate": round(ns.udp_rate,1),
                "icmp_rate": round(ns.icmp_rate,1), "total_rate": round(ns.total_rate,1)}
    mon = st.get("monitors",{})
    return jsonify({
        "running":      eng.is_running(),
        "phase":        st.get("phase","stopped"),
        "uptime":       _uptime(),
        "windows":      st.get("windows",0),
        "baseline_pct": st.get("baseline_pct",0.0),
        "last_ns":      ns_d,
        "monitors":     mon,
    })


@app.get("/api/alerts")
def api_alerts():
    n     = min(int(request.args.get("n", 150)), 500)
    level = request.args.get("level")
    since = request.args.get("since_epoch", type=float)
    rows  = eng.db_query_alerts(n=n, level_filter=level, since_epoch=since)
    return jsonify({"alerts": [_enrich(r) for r in rows]})


@app.get("/api/metrics")
def api_metrics():
    return jsonify({
        "counts": eng.db_counts(),
        "cat":    eng.db_category_counts(),
        "spark":  eng.db_spark(),
    })


@app.get("/api/hourly")
def api_hourly():
    return jsonify({"data": eng.db_hourly_activity(24)})


@app.get("/api/attackers")
def api_attackers():
    n = int(request.args.get("n", 20))
    return jsonify({"attackers": eng.db_top_attackers(n)})


@app.get("/api/config")
def api_config_get():
    safe = {k: v for k, v in eng.CFG.items()
            if k in ("ntfy_enabled","ntfy_topic","ntfy_server",
                     "ntfy_min_level","ntfy_token")}
    return jsonify(safe)


@app.post("/api/config")
def api_config_post():
    data = request.get_json(force=True, silent=True) or {}
    allowed = {"ntfy_enabled","ntfy_topic","ntfy_server","ntfy_min_level","ntfy_token"}
    for k, v in data.items():
        if k in allowed:
            eng.CFG[k] = v
    try:
        # Persist to ulinzi.conf
        if os.path.exists(eng.CONFIG_FILE):
            with open(eng.CONFIG_FILE) as fh: existing = json.load(fh)
        else:
            existing = dict(eng._DEFAULT_CONFIG)
        existing.update({k:v for k,v in data.items() if k in allowed})
        with open(eng.CONFIG_FILE,"w") as fh: json.dump(existing, fh, indent=2)
        eng.db_log_system("config_update", json.dumps({k:v for k,v in data.items() if k in allowed}))
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.post("/api/test-notification")
def api_test_notification():
    if not eng.REQUESTS_OK:
        return jsonify({"ok":False,"error":"requests library not installed"}),400
    topic  = eng.CFG.get("ntfy_topic","")
    server = eng.CFG.get("ntfy_server","https://ntfy.sh")
    token  = eng.CFG.get("ntfy_token","")
    if not topic:
        return jsonify({"ok":False,"error":"No topic configured — set a topic first"}),400
    ok = eng._send_ntfy("HIGH","engine",
                         f"Ulinzi HIDS test notification — "
                         f"server is live at {socket.gethostname()}",
                         datetime.now().strftime("%H:%M:%S"))
    if ok:
        return jsonify({"ok":True})
    return jsonify({"ok":False,"error":"ntfy delivery failed — check topic/server"}),500


# need socket for hostname in test notification
import socket

# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    print(f"""
  ╔══════════════════════════════════════════════════╗
  ║         ULINZI HIDS v4  ·  Strathmore Uni        ║
  ╠══════════════════════════════════════════════════╣
  ║  Dashboard : http://0.0.0.0:{PORT:<5}               ║
  ║  Phone     : http://<this-VM-IP>:{PORT:<5}          ║
  ║                                                  ║
  ║  Run with sudo for full network monitoring       ║
  ╚══════════════════════════════════════════════════╝
""")
    app.run(host=HOST_BIND, port=PORT, debug=False, use_reloader=False, threaded=True)
