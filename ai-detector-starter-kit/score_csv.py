import os, sys
import numpy as np
import pandas as pd
from joblib import load
import re
from urllib.parse import urlparse
from math import log2

FEATS = [
    "waf_anomaly","status","url_len","qs_len","entropy_qs",
    "count_sql_kw","count_specials","has_sleep","has_or_1eq1"
]

SQL_KW = r"""(select|union|sleep|benchmark|order\s+by|group\s+by|information_schema|load_file|into\s+outfile|@@|xp_|or\s+1=1)"""
SPECIAL_CHARS = r"""[%'\")(;/*\-#]|--"""

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c/n) * log2(c/n) for c in freq.values())

def extract_from_sentence(sentence: str) -> dict:
    text = sentence or ""
    qs = text
    try:
        parts = urlparse(text)
        if parts.scheme and (parts.netloc or parts.path):
            qs = parts.query or text
            url_path = parts.path or "/"
        else:
            url_path = "/"
    except Exception:
        url_path = "/"
    kw = re.findall(SQL_KW, qs.lower())
    specials = re.findall(SPECIAL_CHARS, qs)
    return {
        "waf_anomaly": 0,
        "status": 200,
        "url_len": len(url_path),
        "qs_len": len(qs),
        "entropy_qs": shannon_entropy(qs),
        "count_sql_kw": len(kw),
        "count_specials": len(specials),
        "has_sleep": int("sleep(" in qs.lower()),
        "has_or_1eq1": int(" or 1=1" in qs.lower()),
    }

def ensure_feats(df: pd.DataFrame) -> pd.DataFrame:
    # normalize column names (strip whitespace and BOM)
    df = df.rename(columns=lambda c: str(c).strip().lstrip("\ufeff"))
    if all(c in df.columns for c in FEATS):
        # Cast and fill
        return df[FEATS].fillna(0).astype(float)
    # derive from Sentence/text columns
    sent_col = None
    for c in ["Sentence","sentence","text","payload","query","Sentence "]:
        if c in df.columns:
            sent_col = c
            break
    # Fallback: use first column as sentence if no known column found
    if sent_col is None:
        if df.shape[1] >= 1:
            sent_col = df.columns[0]
        else:
            raise SystemExit("Input CSV must have FEATS columns or a Sentence/text-like column.")
    rows = []
    for s in df[sent_col].astype(str).tolist():
        x = extract_from_sentence(s)
        rows.append([x.get(k,0) for k in FEATS])
    return pd.DataFrame(rows, columns=FEATS)

def main():
    if len(sys.argv) < 3:
        print("Usage: python score_csv.py <input.csv> <output.csv>", file=sys.stderr)
        sys.exit(1)
    inp, outp = sys.argv[1], sys.argv[2]
    model_path = os.getenv("MODEL_PATH", "iforest_sqlbf.joblib")
    scaler, clf, _ = load(model_path)
    # Robust CSV reading with encoding fallbacks and tolerant parser
    df_in = None
    last_err = None
    for enc in ("utf-8", "utf-8-sig", "latin1"):
        try:
            try:
                df_in = pd.read_csv(inp, encoding=enc)
            except Exception:
                df_in = pd.read_csv(inp, encoding=enc, engine="python", on_bad_lines="skip")
            break
        except Exception as e:
            last_err = e
            df_in = None
    if df_in is None:
        raise SystemExit(f"Failed to read CSV {inp}: {last_err}")
    Xdf = ensure_feats(df_in)
    X = Xdf.to_numpy(dtype=float)
    raw = -clf.decision_function(scaler.transform(X))
    score = np.clip(raw, 0.0, 1.0)
    sev = np.where(score>=0.8, "high", np.where(score>=0.6, "med", "low"))
    out = df_in.copy()
    out["score"] = score
    out["sev"] = sev
    out.to_csv(outp, index=False)

if __name__ == "__main__":
    main()


