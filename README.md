# IDS Web Control Panel

A minimal Flask-based web interface to start, stop, and monitor an
anomaly-based Intrusion Detection System (IDS) running as a background process.

---

## Project layout

```
ids_panel/
├── app.py           ← Flask control panel  (the only file you need to ship)
├── ids_main.py      ← YOUR IDS entry point (stub provided for demo)
├── alerts.log       ← Written by the IDS;  read by the panel (auto-created)
└── requirements.txt
```

---

## Quick start

### 1 — Install dependencies (Python 3.9+)

```bash
pip install -r requirements.txt
```

Flask is the **only** external dependency.

---

### 2 — Point the panel at your IDS

| Env var      | Default        | Description                                      |
|--------------|----------------|--------------------------------------------------|
| `IDS_SCRIPT` | `ids_main.py`  | Path to your IDS Python entry point              |
| `ALERT_LOG`  | `alerts.log`   | Path to the log file your IDS writes alerts into |
| `MAX_ALERTS` | `100`          | Max alert lines kept in memory per request       |
| `HOST`       | `0.0.0.0`      | Flask bind address                               |
| `PORT`       | `5000`         | Flask port                                       |

Example with your real IDS:

```bash
export IDS_SCRIPT=/opt/ids/main.py
export ALERT_LOG=/var/log/ids/alerts.log
```

---

### 3 — Start the web server

```bash
python app.py
```

Or with environment overrides inline:

```bash
IDS_SCRIPT=/opt/ids/main.py ALERT_LOG=/var/log/ids/alerts.log python app.py
```

---

### 4 — Open in browser

```
http://localhost:5000
```

---

## Available endpoints

| Method | Path       | Description                                |
|--------|------------|--------------------------------------------|
| GET    | `/`        | Main control panel page                    |
| POST   | `/start`   | Start the IDS process                      |
| POST   | `/stop`    | Stop the IDS process (SIGTERM → SIGKILL)   |
| GET    | `/status`  | JSON: `{ running, uptime, started }`       |
| GET    | `/alerts`  | JSON: last N alerts (`?n=50` adjustable)   |

---

## Integration contract with your IDS

The panel makes **two** assumptions about your IDS:

1. It is a **standalone Python script** launchable via `python <IDS_SCRIPT>`.
2. It **appends alert lines** to the file at `ALERT_LOG`.

No other changes to your IDS are required.

---

## Demo / testing without the real IDS

A stub `ids_main.py` is included. It writes randomised fake alerts to
`alerts.log` every few seconds so you can verify the panel end-to-end.

```bash
python app.py          # uses ids_main.py + alerts.log by default
# Open http://localhost:5000, click Start, watch alerts appear
```

---

## Security notes

- No authentication is provided (add a reverse-proxy like nginx + basic-auth
  if the panel is exposed beyond localhost).
- Tested with Python 3.10+ and Flask 3.x.
