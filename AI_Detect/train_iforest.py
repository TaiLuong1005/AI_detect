import argparse, json, numpy as np
from joblib import dump
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATS = ["waf_anomaly","status","url_len","qs_len","entropy_qs","count_sql_kw","count_specials","has_sleep","has_or_1eq1"]

def vec(x): 
    return [x.get(k,0) for k in FEATS]

def main():
    ap = argparse.ArgumentParser(description="Train Isolation Forest (unsupervised) from feature JSONL")
    ap.add_argument("--input", required=True, help="features_train.jsonl")
    ap.add_argument("--model", default="iforest_sqlbf.joblib", help="output model path")
    ap.add_argument("--contamination", type=float, default=0.01, help="expected outlier ratio, e.g., 0.01")
    args = ap.parse_args()

    X = []
    with open(args.input, "r") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            X.append(vec(json.loads(line)))

    if not X:
        raise SystemExit("No data loaded. Make sure --input has feature rows.")

    X = np.array(X, dtype=float)
    scaler = StandardScaler().fit(X)
    Xn = scaler.transform(X)

    clf = IsolationForest(n_estimators=250, contamination=args.contamination, random_state=42)
    clf.fit(Xn)

    dump((scaler, clf, FEATS), args.model)
    print(f"Saved model to: {args.model}")

if __name__ == "__main__":
    main()
