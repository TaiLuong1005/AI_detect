import os
from fastapi import FastAPI
from pydantic import BaseModel
from joblib import load
import numpy as np
from features_poc import extract_features

MODEL_PATH = os.getenv("MODEL_PATH", "iforest_sqlbf.joblib")
scaler, clf, FEATS = load(MODEL_PATH)

class Event(BaseModel):
    ts: str
    src_ip: str
    method: str = "GET"
    status: int = 200
    url: str = "/"
    qs: str = ""
    ua: str = ""
    waf: dict | None = None

app = FastAPI(title="AI WebSec Unsupervised", version="1.0")

@app.get("/health")
def health():
    return {"ok": True, "model": os.path.basename(MODEL_PATH)}

@app.post("/score")
def score(evt: Event):
    x = extract_features(evt.model_dump())
    v = np.array([[x.get(k,0) for k in FEATS]])
    # IsolationForest: decision_function > 0 usually inliers; negative -> outliers
    raw = -clf.decision_function(scaler.transform(v))[0]
    # simple normalization heuristic for readability
    s = float(max(0.0, min(1.0, raw)))
    sev = "low"
    if s >= 0.8: sev = "high"
    elif s >= 0.6: sev = "med"
    return {"score": s, "sev": sev, "features": x}
