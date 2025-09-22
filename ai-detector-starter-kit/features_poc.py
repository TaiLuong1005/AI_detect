import re, math
from urllib.parse import urlparse

# Các regex nhận diện SQLi cơ bản
SQL_KW = r"""(select|union|sleep|benchmark|order\s+by|group\s+by|information_schema|load_file|into\s+outfile|@@|xp_|or\s+1=1)"""
SPECIAL_CHARS = r"""[%'\")(;/*\-#]|--"""

# Nginx "combined" log format parser (đơn giản hoá, vẫn match được phần lớn trường hợp)
import regex as re2
NGINX_COMBINED = re2.compile(
    r'(?P<src_ip>\S+) \S+ \S+ \[(?P<ts>.+?)\] "(?P<method>\S+) (?P<url>\S+)(?: \S+)?" (?P<status>\d{3}) (?P<bytes>\d+|-) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
)

def shannon_entropy(s: str) -> float:
    from collections import Counter
    if not s: return 0.0
    c = Counter(s); n = len(s)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def parse_nginx(line: str):
    m = NGINX_COMBINED.search(line)
    if not m: 
        return None
    d = m.groupdict()
    u = d.get("url","/")
    parts = urlparse(u)
    qs = parts.query or ""
    return {
        "ts": d["ts"],
        "src_ip": d["src_ip"],
        "method": d["method"],
        "status": int(d["status"]),
        "bytes": 0 if d["bytes"] == "-" else int(d["bytes"]),
        "url": parts.path or "/",
        "qs": qs,
        "ua": d.get("ua", ""),
        # Chưa parse WAF, nhưng để sẵn object
        "waf": {"anomaly": 0, "rule_ids": []}
    }

def extract_features(evt: dict):
    qs = (evt.get("qs") or "")
    kw = re.findall(SQL_KW, qs.lower())
    specials = re.findall(SPECIAL_CHARS, qs)
    return {
        "waf_anomaly": int(evt.get("waf",{}).get("anomaly", 0)),
        "status": int(evt.get("status", 0)),
        "url_len": len(evt.get("url","")),
        "qs_len": len(qs),
        "entropy_qs": shannon_entropy(qs),
        "count_sql_kw": len(kw),
        "count_specials": len(specials),
        "has_sleep": int("sleep(" in qs.lower()),
        "has_or_1eq1": int(" or 1=1" in qs.lower())
    }

def is_login_fail(evt: dict) -> bool:
    """Heuristic đơn giản: POST tới path có 'login' và status thuộc {200,401,403}."""
    try:
        return (evt.get("method") == "POST" and "login" in (evt.get("url") or "").lower()
                and int(evt.get("status",0)) in (200,401,403))
    except Exception:
        return False
