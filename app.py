"""
UPGRADED IDS CONTROL PANEL
- process watchdog
- live streaming
- structured alert parsing
- health monitoring
"""

import os
import threading
import subprocess
import time
from datetime import datetime
from flask import Flask, render_template_string, jsonify, request, Response

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
# GLOBAL STATE
# =========================
lock = threading.Lock()

proc = None
start_time = None
last_heartbeat = None

alerts_cache = []
running = False


# =========================
# ALERT SYSTEM (FAST CACHE)
# =========================
def load_alerts():
    global alerts_cache
    if not os.path.exists(ALERT_LOG):
        return []

    try:
        with open(ALERT_LOG, "r", errors="ignore") as f:
            lines = f.readlines()

        cleaned = [l.strip() for l in lines if l.strip()]
        alerts_cache = cleaned[-MAX_ALERTS:]
        return alerts_cache
    except:
        return alerts_cache


# =========================
# PROCESS MANAGEMENT
# =========================
def start_ids():
    global proc, start_time, running

    if proc and proc.poll() is None:
        return False, "Already running"

    proc = subprocess.Popen(
        ["python", IDS_SCRIPT],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT
    )

    start_time = datetime.now()
    running = True

    threading.Thread(target=watchdog, daemon=True).start()

    return True, "Started"


def stop_ids():
    global proc, running

    if not proc:
        return False, "Not running"

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except:
        proc.kill()

    running = False
    return True, "Stopped"


# =========================
# WATCHDOG (IMPORTANT FIX)
# =========================
def watchdog():
    global running, proc

    while proc and proc.poll() is None:
        time.sleep(5)

        # reload alerts constantly
        load_alerts()

    running = False


# =========================
# HEALTH CHECK (NEW)
# =========================
def get_health():
    if not proc:
        return "DOWN"

    if proc.poll() is not None:
        return "STOPPED"

    # if IDS silent too long → degraded
    try:
        last = os.path.getmtime(ALERT_LOG)
        if time.time() - last > 20:
            return "DEGRADED"
    except:
        pass

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

    <h3>Alerts</h3>
    <div style="background:#111;color:#0f0;padding:10px;height:300px;overflow:auto;">
        {% for a in alerts %}
            <div>{{a}}</div>
        {% endfor %}
    </div>
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
# REAL-TIME STREAM (NEW)
# =========================
@app.get("/stream")
def stream():
    def event_stream():
        last_len = 0
        while True:
            load_alerts()
            if len(alerts_cache) > last_len:
                new = alerts_cache[last_len:]
                for n in new:
                    yield f"data: {n}\n\n"
                last_len = len(alerts_cache)
            time.sleep(1)

    return Response(event_stream(), mimetype="text/event-stream")


# =========================
# RUN
# =========================
if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=False)