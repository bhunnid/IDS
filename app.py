"""
PRODUCTION-READY IDS CONTROL PANEL
- thread-safe process management
- stable alert streaming (SSE)
- watchdog with auto-state correction
- safe alert caching
- improved health monitoring
"""

import os
import sys
import threading
import subprocess
import time
from datetime import datetime
from flask import Flask, render_template_string, jsonify, Response

app = Flask(__name__)

# =========================
# CONFIG
# =========================
IDS_SCRIPT = os.getenv("IDS_SCRIPT", "ids_main.py")
ALERT_LOG  = os.getenv("ALERT_LOG", "alerts.log")
MAX_ALERTS = 200

HOST = "0.0.0.0"
PORT = 5000

# =========================
# GLOBAL STATE (PROTECTED)
# =========================
lock = threading.Lock()

proc = None
start_time = None
running = False

alerts_cache = []


# =========================
# ALERT SYSTEM (THREAD SAFE)
# =========================
def load_alerts():
    global alerts_cache

    if not os.path.exists(ALERT_LOG):
        return alerts_cache

    try:
        with open(ALERT_LOG, "r", errors="ignore") as f:
            lines = f.readlines()

        cleaned = [l.strip() for l in lines if l.strip()]

        with lock:
            alerts_cache = cleaned[-MAX_ALERTS:]

        return alerts_cache

    except Exception:
        return alerts_cache


# =========================
# PROCESS MANAGEMENT (SAFE)
# =========================
def start_ids():
    global proc, start_time, running

    with lock:
        if proc and proc.poll() is None:
            return False, "Already running"

        try:
            proc = subprocess.Popen(
                [sys.executable, IDS_SCRIPT],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except Exception as e:
            return False, f"Failed: {e}"

        start_time = datetime.now()
        running = True

    threading.Thread(target=watchdog, daemon=True).start()
    return True, "Started"


def stop_ids():
    global proc, running

    with lock:
        if not proc:
            return False, "Not running"

        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

        proc = None
        running = False

    return True, "Stopped"


# =========================
# WATCHDOG
# =========================
def watchdog():
    global running, proc

    while True:
        with lock:
            if not proc:
                running = False
                return

            alive = proc.poll() is None

        if not alive:
            with lock:
                running = False
                proc = None
            return

        load_alerts()
        time.sleep(3)


# =========================
# HEALTH CHECK
# =========================
def get_health():
    with lock:
        if not proc:
            return "DOWN"

        if proc.poll() is not None:
            return "STOPPED"

    if len(alerts_cache) == 0:
        return "IDLE"

    return "OK"


# =========================
# UPTIME
# =========================
def uptime():
    if not start_time:
        return "0s"

    delta = int((datetime.now() - start_time).total_seconds())
    return f"{delta}s"


# =========================
# ROUTES
# =========================
@app.get("/")
def home():
    load_alerts()

    return render_template_string("""
    <h2>IDS CONTROL PANEL</h2>

    <p>Status: <b>{{health}}</b></p>
    <p>Running: {{running}}</p>
    <p>Uptime: {{uptime}}</p>

    <form method="post" action="/start">
        <button>Start IDS</button>
    </form>

    <form method="post" action="/stop">
        <button>Stop IDS</button>
    </form>

    <h3>Alerts (latest first)</h3>
    <div style="background:#111;color:#0f0;padding:10px;height:300px;overflow:auto;">
        {% for a in alerts %}
            <div>{{a}}</div>
        {% endfor %}
    </div>

    <script>
    const evt = new EventSource("/stream");
    evt.onmessage = function(e) {
        const box = document.querySelector("div");
        const div = document.createElement("div");
        div.textContent = e.data;
        box.prepend(div);
    };
    </script>
    """,
    alerts=alerts_cache[::-1],
    running=running,
    uptime=uptime(),
    health=get_health()
    )


@app.post("/start")
def start_route():
    ok, msg = start_ids()
    return jsonify({"ok": ok, "msg": msg})


@app.post("/stop")
def stop_route():
    ok, msg = stop_ids()
    return jsonify({"ok": ok, "msg": msg})


@app.get("/status")
def status():
    return jsonify({
        "running": running,
        "uptime": uptime(),
        "health": get_health(),
        "alerts": len(alerts_cache)
    })


@app.get("/alerts")
def alerts():
    load_alerts()
    return jsonify({
        "alerts": alerts_cache[-50:],
        "count": len(alerts_cache)
    })


# =========================
# REAL-TIME STREAM (FIXED)
# =========================
@app.get("/stream")
def stream():
    def event_stream():
        last_len = len(alerts_cache)

        while True:
            load_alerts()

            with lock:
                current_len = len(alerts_cache)
                if current_len > last_len:
                    new = alerts_cache[last_len:current_len]
                    last_len = current_len
                else:
                    new = []

            for n in new:
                yield f"data: {n}\n\n"

            time.sleep(1)

    return Response(event_stream(), mimetype="text/event-stream")


# =========================
# RUN
# =========================
if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=False, threaded=True)