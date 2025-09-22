import os, time, json, argparse, subprocess, yaml
import requests
from collections import defaultdict, deque
from datetime import datetime
from features_poc import parse_nginx, is_login_fail

DEFAULT_CFG = {
    "nginx_access_log": "/var/log/nginx/access.log",
    "wazuh_alert_file": "/var/log/ai-security/alerts.log",
    "thresholds": {"score_med": 0.60, "score_high": 0.80, "brute_force_min_fails_5m": 10},
    "enable_fail2ban": True,
    "ban_minutes_default": 30,
    "ban_script": "actions/ban_ip.sh",
    "infer_url": "http://127.0.0.1:8000/score",
}

def load_cfg(cfg_path: str | None):
    cfg = DEFAULT_CFG.copy()
    if cfg_path and os.path.exists(cfg_path):
        with open(cfg_path) as f:
            user_cfg = yaml.safe_load(f) or {}
        # shallow merge
        for k, v in user_cfg.items():
            cfg[k] = v
    return cfg

def tail_f(path):
    with open(path, "r", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2); continue
            yield line

def write_alert(alert_path: str, data: dict):
    os.makedirs(os.path.dirname(alert_path), exist_ok=True)
    with open(alert_path, "a") as f:
        f.write(json.dumps(data, ensure_ascii=False) + "\n")

def maybe_ban(ip: str, minutes: int, script_path: str, dry: bool):
    if dry: 
        return
    if not script_path or not os.path.exists(script_path):
        return
    try:
        subprocess.run(["bash", script_path, ip, str(minutes)], check=False)
    except Exception as e:
        print("ban_ip error:", e)

def main():
    ap = argparse.ArgumentParser(description="Tail access log, call AI, emit alerts for Wazuh, optionally ban IP")
    ap.add_argument("--config", default="config.yaml", help="config file (YAML)")
    ap.add_argument("--access-log", dest="access_log", default=None, help="override access log path")
    ap.add_argument("--infer-url", dest="infer_url", default=None, help="override AI /score endpoint")
    ap.add_argument("--emit-features", default=None, help="write extracted features to JSONL (for training)" )
    ap.add_argument("--dry-run", action="store_true", help="do not create alerts or ban; only collect features")
    ap.add_argument("--ban-minutes", type=int, default=None, help="override ban minutes")
    args = ap.parse_args()

    cfg = load_cfg(args.config)
    access_log = args.access_log or cfg["nginx_access_log"]
    infer_url = args.infer_url or cfg["infer_url"]
    alert_path = cfg["wazuh_alert_file"]
    th = cfg["thresholds"]
    ban_minutes = args.ban_minutes or cfg["ban_minutes_default"]

    feat_f = open(args.emit_features, "a") if args.emit_features else None

    fails_window = defaultdict(lambda: deque())  # per IP: timestamps

    for line in tail_f(access_log):
        evt = parse_nginx(line)
        if not evt: 
            continue

        now = time.time()
        ip = evt.get("src_ip", "")

        # brute-force window (5 phút)
        if is_login_fail(evt):
            dq = fails_window[ip]
            dq.append(now)
            while dq and now - dq[0] > 300: 
                dq.popleft()

        # call AI
        try:
            r = requests.post(infer_url, json=evt, timeout=1.5)
            if r.status_code != 200:
                continue
            res = r.json()
        except Exception:
            continue

        if feat_f:
            frow = res.get("features", {})
            feat_f.write(json.dumps(frow) + "\n")

        if args.dry_run: 
            continue

        sev = res.get("sev","low"); score = float(res.get("score",0.0))
        bf_count = len(fails_window[ip])
        reasons = []
        if sev == "high": reasons.append("AI_high")
        if sev == "med": reasons.append("AI_med")
        if bf_count >= int(th.get("brute_force_min_fails_5m", 10)):
            reasons.append(f"BF_{bf_count}")

        # tạo alert nếu có lý do
        if reasons:
            rec = {
                "tag": "AISEC",
                "ts": datetime.utcnow().isoformat() + "Z",
                "src_ip": ip,
                "sev": sev,
                "score": round(score,3),
                "reasons": reasons,
                "url": evt.get("url",""),
                "status": evt.get("status"),
            }
            write_alert(alert_path, rec)
            maybe_ban(ip, ban_minutes, cfg.get("ban_script"), dry=False)

    if feat_f:
        feat_f.close()

if __name__ == "__main__":
    main()
