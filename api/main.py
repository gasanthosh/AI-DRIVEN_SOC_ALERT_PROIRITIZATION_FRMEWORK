"""
main.py - SOC Alert Prioritization API (v2)
Framework: FastAPI
Features: Real-time inference, Synthetic Simulation, Metrics, File Upload,
          Live Network Sniffer Control, SSE Streaming, Alert Source Filtering
"""

import os
import sys
import io
import time
import asyncio
import logging
from collections import deque
from datetime import datetime, timezone

import numpy as np
import pandas as pd
import joblib
from fastapi import FastAPI, HTTPException, Request, Query, UploadFile, File
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from sse_starlette.sse import EventSourceResponse

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from data_pipeline import clean_features
from alert_engine import build_alert, batch_build_alerts
from live_sniffer import sniffer_manager

# -- Configuration & Logging -------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(message)s",
    handlers=[
        logging.FileHandler(os.path.join("logs", "api.log")),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("API")

# -- State -------------------------------------------------------------------
ALERT_STORE: deque[dict] = deque(maxlen=2000)
_last_sse_index: int = 0   # tracks where the SSE stream left off

METRICS_STORE: dict = {
    "total": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "benign": 0,
    "attack": 0,
    "source_counts": {"SIM": 0, "UPLOAD": 0, "SNIFFER": 0, "PREDICT": 0, "UNKNOWN": 0},
}

ARTIFACTS: dict = {
    "model": None,
    "scaler": None,
    "label_encoder": None,
    "feature_names": None,
}


def load_artifacts():
    try:
        ARTIFACTS["model"]         = joblib.load("models/xgb_model.pkl")
        ARTIFACTS["scaler"]        = joblib.load("models/scaler.pkl")
        ARTIFACTS["label_encoder"] = joblib.load("models/label_encoder.pkl")
        if os.path.exists("models/feature_names.pkl"):
            ARTIFACTS["feature_names"] = joblib.load("models/feature_names.pkl")
        log.info("Model artifacts loaded successfully.")
    except Exception as e:
        log.warning(f"Failed to load model artifacts: {e}. Running in demo mode.")


# -- App ---------------------------------------------------------------------
app = FastAPI(title="SOC Alert Prioritization API", version="2.0.0")

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# -- Pydantic Models ---------------------------------------------------------
class SimulateRequest(BaseModel):
    attack_type: str = "DDoS"
    count: int = 5

class TrafficFeatures(BaseModel):
    source: str = "PREDICT"
    model_config = {"extra": "allow"}

class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    alert_count: int
    sniffer_running: bool

class AlertResponse(BaseModel):
    id: int
    timestamp: str
    attack_type: str
    priority: str
    confidence: float
    risk_score: float
    action: str
    is_benign: bool
    source: str = "UNKNOWN"
    src_ip: str | None = None
    dst_ip: str | None = None
    ground_truth: str | None = None

class PredictionResponse(AlertResponse):
    pass


# -- Helpers -----------------------------------------------------------------
def _gen_synthetic_alert(attack_type: str | None = None) -> dict:
    attacks = [
        "DDoS", "PortScan", "Botnet", "Infiltration", "FTP-Patator",
        "DoS Hulk", "DoS GoldenEye", "SSH-Patator", "Heartbleed",
        "Web Attack - Brute Force", "Web Attack - XSS", "BENIGN",
    ]
    label = attack_type if attack_type else np.random.choice(attacks)
    conf  = np.random.uniform(0.60, 0.99)
    return build_alert(label, conf, source="SIM")


def _update_metrics(alert: dict):
    METRICS_STORE["total"] += 1
    p = alert["priority"].lower()
    if p in METRICS_STORE:
        METRICS_STORE[p] += 1
    if alert["is_benign"]:
        METRICS_STORE["benign"] += 1
    else:
        METRICS_STORE["attack"] += 1
    src = alert.get("source", "UNKNOWN")
    if src in METRICS_STORE["source_counts"]:
        METRICS_STORE["source_counts"][src] += 1
    else:
        METRICS_STORE["source_counts"]["UNKNOWN"] += 1


def _push_alert(alert: dict):
    """Append to store and update metrics."""
    ALERT_STORE.appendleft(alert)
    _update_metrics(alert)


# -- Startup / Shutdown ------------------------------------------------------
@app.on_event("startup")
async def startup_event():
    load_artifacts()
    # Wire the sniffer to our predict endpoint
    sniffer_manager.api_url = "http://localhost:8000/predict"


@app.on_event("shutdown")
async def shutdown_event():
    if sniffer_manager.is_running():
        sniffer_manager.stop()


# ============================================================================
# ROUTES
# ============================================================================

# -- System ------------------------------------------------------------------
@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health():
    return HealthResponse(
        status="ok",
        model_loaded=ARTIFACTS["model"] is not None,
        alert_count=len(ALERT_STORE),
        sniffer_running=sniffer_manager.is_running(),
    )


@app.delete("/alerts", tags=["System"])
async def clear_alerts():
    """Clear in-memory alert store and reset metrics."""
    global _last_sse_index
    ALERT_STORE.clear()
    _last_sse_index = 0
    for k in list(METRICS_STORE.keys()):
        if k == "source_counts":
            for sk in METRICS_STORE[k]:
                METRICS_STORE[k][sk] = 0
        else:
            METRICS_STORE[k] = 0
    log.info("Alert store cleared.")
    return {"cleared": True}


# -- SSE Streaming -----------------------------------------------------------
@app.get("/stream", tags=["Streaming"])
async def stream_alerts(request: Request):
    """
    Server-Sent Events endpoint.
    Pushes new alerts to connected clients in real time to avoid polling.
    """
    async def event_generator():
        seen_ids: set[int] = set()
        while True:
            if await request.is_disconnected():
                break
            new_alerts = [a for a in ALERT_STORE if a["id"] not in seen_ids]
            for alert in reversed(new_alerts):   # oldest first
                seen_ids.add(alert["id"])
                import json
                yield {"event": "alert", "data": json.dumps(alert)}
            await asyncio.sleep(1)

    return EventSourceResponse(event_generator())


# -- Network Interfaces + Sniffer Control ------------------------------------
@app.get("/network/interfaces", tags=["Sniffer"])
async def network_interfaces():
    """Return available network interfaces."""
    try:
        from scapy.all import get_if_list, get_if_hwaddr
        ifaces = get_if_list()
        result = []
        for iface in ifaces:
            try:
                mac = get_if_hwaddr(iface)
            except Exception:
                mac = "??:??:??:??:??:??"
            result.append({"name": iface, "mac": mac})
        return {"interfaces": result}
    except ImportError:
        return {"interfaces": [], "error": "scapy not available"}
    except Exception as e:
        return {"interfaces": [], "error": str(e)}


@app.post("/sniffer/start", tags=["Sniffer"])
async def sniffer_start(
    interface: str | None = Query(default=None, description="NIC name (None = default)"),
    interval:  int        = Query(default=5,    ge=1, le=60, description="Flow report interval (sec)"),
):
    if sniffer_manager.is_running():
        return {"status": "already_running", **sniffer_manager.get_status()}

    ok = sniffer_manager.start(interface=interface, interval=interval)
    if ok:
        log.info(f"Sniffer started via API: iface={interface!r} interval={interval}s")
        return {"status": "started", **sniffer_manager.get_status()}
    return {"status": "failed"}


@app.post("/sniffer/stop", tags=["Sniffer"])
async def sniffer_stop():
    if not sniffer_manager.is_running():
        return {"status": "not_running"}
    sniffer_manager.stop()
    log.info("Sniffer stopped via API.")
    return {"status": "stopped", **sniffer_manager.get_status()}


@app.get("/sniffer/status", tags=["Sniffer"])
async def sniffer_status():
    return sniffer_manager.get_status()


# -- Inference ---------------------------------------------------------------
@app.post("/predict", response_model=PredictionResponse, tags=["Inference"])
async def predict(request: Request, features: TrafficFeatures):
    if ARTIFACTS["model"] is None:
        raise HTTPException(status_code=503, detail="Model not loaded.")

    model, scaler, le = ARTIFACTS["model"], ARTIFACTS["scaler"], ARTIFACTS["label_encoder"]
    feature_cols = ARTIFACTS["feature_names"]
    raw = features.model_dump()
    vec = np.array([[raw.get(col, 0.0) or 0.0 for col in feature_cols]], dtype=np.float64)
    vec = np.nan_to_num(vec, nan=0.0)

    proba = model.predict_proba(scaler.transform(vec))[0]
    idx   = int(np.argmax(proba))
    alert = build_alert(le.inverse_transform([idx])[0], float(proba[idx]),
                        source=raw.get("source", "PREDICT"))
    # Attach IP info if provided by the sniffer
    alert["src_ip"] = raw.get("src_ip") or None
    alert["dst_ip"] = raw.get("dst_ip") or None
    _push_alert(alert)
    log.info(f"PREDICT -> {alert['attack_type']} ({alert['priority']})")
    return PredictionResponse(**alert)


# -- Simulate ----------------------------------------------------------------
@app.post("/simulate", tags=["Demo"])
async def simulate(request: Request, body: SimulateRequest):
    alerts = []
    for _ in range(body.count):
        a = _gen_synthetic_alert(body.attack_type)
        _push_alert(a)
        alerts.append(a)
    log.info(f"SIMULATE -> {body.count}x {body.attack_type}")
    return {"generated": len(alerts), "alerts": alerts}


@app.post("/simulate/random", tags=["Demo"])
async def simulate_random(
    request: Request,
    count: int = Query(default=10, ge=1, le=100)
):
    alerts = []
    for _ in range(count):
        a = _gen_synthetic_alert()
        _push_alert(a)
        alerts.append(a)
    log.info(f"SIMULATE/RANDOM -> {count} alerts")
    return {"generated": len(alerts), "alerts": alerts}


# -- Upload ------------------------------------------------------------------
@app.post("/upload", tags=["Inference"])
async def upload_traffic(request: Request, file: UploadFile = File(...)):
    if ARTIFACTS["model"] is None:
        raise HTTPException(status_code=503, detail="Model not loaded.")

    contents = await file.read()
    df = pd.read_csv(io.BytesIO(contents), low_memory=False)
    if df.empty:
        raise HTTPException(status_code=400, detail="Empty CSV")

    log.info(f"UPLOAD '{file.filename}' -> {len(df)} rows")

    df.columns = df.columns.str.strip()
    ground_truth = None
    if "Label" in df.columns:
        ground_truth = df["Label"].astype(str).str.strip().tolist()
        df = df.drop(columns=["Label"])

    feature_cols = ARTIFACTS["feature_names"]
    df = clean_features(df)
    for col in feature_cols:
        if col not in df.columns:
            df[col] = 0.0
    df = df[feature_cols].apply(pd.to_numeric, errors="coerce").fillna(0.0)

    probas = ARTIFACTS["model"].predict_proba(ARTIFACTS["scaler"].transform(df.values))
    preds  = probas.argmax(axis=1)
    confs  = probas.max(axis=1)
    labels = ARTIFACTS["label_encoder"].inverse_transform(preds)

    alerts, p_counts, a_counts = [], {"HIGH": 0, "MEDIUM": 0, "LOW": 0}, {}
    for i, (lbl, conf) in enumerate(zip(labels, confs)):
        alert = build_alert(str(lbl), float(conf), source="UPLOAD")
        if ground_truth:
            alert["ground_truth"] = ground_truth[i] if i < len(ground_truth) else None
        _push_alert(alert)
        alerts.append(alert)
        p_counts[alert["priority"]] += 1
        a_counts[lbl] = a_counts.get(lbl, 0) + 1

    log.info(
        f"UPLOAD DONE -> {len(alerts)} classified | "
        f"HIGH={p_counts['HIGH']} MEDIUM={p_counts['MEDIUM']} LOW={p_counts['LOW']}"
    )
    return {
        "filename":             file.filename,
        "rows_processed":       len(alerts),
        "priority_breakdown":   p_counts,
        "attack_type_breakdown": a_counts,
        "had_ground_truth":     ground_truth is not None,
        "sample_alerts":        alerts[:10],
    }


# -- Alerts + Metrics --------------------------------------------------------
@app.get("/alerts", response_model=list[AlertResponse], tags=["Alerts"])
async def get_alerts(
    limit:    int        = 500,
    priority: str | None = None,
    source:   str | None = None,
):
    data = list(ALERT_STORE)
    if priority:
        data = [a for a in data if a["priority"] == priority.upper()]
    if source:
        data = [a for a in data if a.get("source", "").upper() == source.upper()]
    return data[:limit]


@app.get("/metrics", tags=["Metrics"])
async def get_metrics():
    total = METRICS_STORE["total"]
    fpr   = (METRICS_STORE["low"] / total) if total > 0 else 0.0

    dist = {}
    if ALERT_STORE:
        counts = pd.Series([a["attack_type"] for a in ALERT_STORE]).value_counts()
        dist = {str(k): int(v) for k, v in counts.to_dict().items()}

    return {
        "total_alerts":       int(total),
        "high":               int(METRICS_STORE["high"]),
        "medium":             int(METRICS_STORE["medium"]),
        "low":                int(METRICS_STORE["low"]),
        "benign_count":       int(METRICS_STORE["benign"]),
        "attack_count":       int(METRICS_STORE["attack"]),
        "fpr_estimate":       round(float(fpr), 4),
        "precision_estimate": round(float(1.0 - fpr), 4),
        "label_distribution": dist,
        "source_counts":      METRICS_STORE["source_counts"],
        "sniffer":            sniffer_manager.get_status(),
    }



# -- Static + Index ----------------------------------------------------------
app.mount("/static", StaticFiles(directory="frontend"), name="static")


@app.get("/")
async def get_index():
    return FileResponse("frontend/index.html")


# -- Analytics / Model Comparison --------------------------------------------
import threading as _threading

_comparison_lock    = _threading.Lock()
_comparison_running = False

COMPARISON_PATH = os.path.join("models", "comparison_results.json")


@app.get("/analytics", tags=["Analytics"])
async def get_analytics():
    """Return the latest model comparison results (cached JSON)."""
    if not os.path.exists(COMPARISON_PATH):
        raise HTTPException(
            status_code=404,
            detail="Comparison results not yet generated. POST /analytics/run first."
        )
    import json as _json
    with open(COMPARISON_PATH) as f:
        return _json.load(f)


@app.post("/analytics/run", tags=["Analytics"])
async def run_analytics():
    """Trigger model comparison in a background thread (non-blocking)."""
    global _comparison_running
    with _comparison_lock:
        if _comparison_running:
            return {"status": "already_running"}
        _comparison_running = True

    def _run():
        global _comparison_running
        try:
            from model_comparison import run_comparison
            run_comparison()
            log.info("Model comparison complete.")
        except Exception as exc:
            log.error(f"Model comparison failed: {exc}")
        finally:
            with _comparison_lock:
                _comparison_running = False

    t = _threading.Thread(target=_run, daemon=True, name="model-compare")
    t.start()
    return {"status": "started", "message": "Comparison running in background. Poll GET /analytics in ~15s."}


@app.get("/analytics/status", tags=["Analytics"])
async def analytics_status():
    return {
        "running":  _comparison_running,
        "ready":    os.path.exists(COMPARISON_PATH),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
