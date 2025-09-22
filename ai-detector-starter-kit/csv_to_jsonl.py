import sys, json, re
import pandas as pd
from urllib.parse import urlparse
from math import log2

# Keep FEATS consistent with train_iforest.py
FEATS = [
    "waf_anomaly","status","url_len","qs_len","entropy_qs",
    "count_sql_kw","count_specials","has_sleep","has_or_1eq1"
]

SQL_KW = r"""(select|union|sleep|benchmark|order\s+by|group\s+by|information_schema|load_file|into\s+outfile|@@|xp_|or\s+1=1)"""
SPECIAL_CHARS = r"""[%'\")(;/*\-#]|--"""

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    # Simple entropy without Counter to keep file self-contained
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c/n) * log2(c/n) for c in freq.values())

def extract_from_sentence(sentence: str) -> dict:
    text = sentence or ""
    # Treat text as the query string; optional: parse URL if present
    qs = text
    try:
        # If text looks like a URL, try extracting path and query
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

def row_to_feats(row: dict) -> dict:
    # If CSV already contains FEATS, pass through; otherwise derive from Sentence
    if all(k in row for k in FEATS):
        out = {}
        for k in FEATS:
            v = row.get(k)
            try:
                out[k] = float(v)
            except Exception:
                out[k] = 0.0
        return out
    sent = row.get("Sentence") or row.get("sentence") or row.get("text") or ""
    return extract_from_sentence(str(sent))

def main():
    if len(sys.argv) < 3:
        print("Usage: python csv_to_jsonl.py <input.csv> <output.jsonl>", file=sys.stderr)
        sys.exit(1)
    inp, outp = sys.argv[1], sys.argv[2]
    # Robust CSV reading with encoding fallbacks
    last_err = None
    for enc in ("utf-8", "utf-8-sig", "latin1"):
        try:
            # First try fast engine, then fall back to python engine and skip bad lines
            try:
                df = pd.read_csv(inp, encoding=enc)
            except Exception:
                df = pd.read_csv(inp, encoding=enc, engine="python", on_bad_lines="skip")
            break
        except Exception as e:
            last_err = e
            df = None
    if df is None:
        raise SystemExit(f"Failed to read CSV {inp}: {last_err}")
    with open(outp, "w", encoding="utf-8") as f:
        for _, r in df.iterrows():
            feats = row_to_feats(r.to_dict())
            f.write(json.dumps({k: float(feats.get(k, 0)) for k in FEATS}, ensure_ascii=False) + "\n")

if __name__ == "__main__":
    main()


