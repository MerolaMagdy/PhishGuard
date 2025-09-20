# analysis.py (improved — supports file paths, directories and wildcards)
import os
import re
import json
import time
import glob
import sqlite3
import tldextract
import requests
from urllib.parse import urlparse
from email import policy
from email.parser import BytesParser
from html import unescape

# ---------- CONFIG ----------
VT_API_KEY = None  # ضع مفتاحك لو عندك
VT_API_URL = "https://www.virustotal.com/api/v3/urls"
CACHE_DB = "vt_cache.sqlite"
CACHE_TTL = 60 * 60 * 24  # cache results 24 hours
# ----------------------------

# ---------- Cache sqlite ----------
def init_cache():
    conn = sqlite3.connect(CACHE_DB)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS vt_cache (
        key TEXT PRIMARY KEY,
        response TEXT,
        ts INTEGER
    )
    """)
    conn.commit()
    return conn

cache_conn = init_cache()

def cache_get(key):
    cur = cache_conn.cursor()
    cur.execute("SELECT response, ts FROM vt_cache WHERE key=?", (key,))
    row = cur.fetchone()
    if not row:
        return None
    response, ts = row
    if time.time() - ts > CACHE_TTL:
        cur.execute("DELETE FROM vt_cache WHERE key=?", (key,))
        cache_conn.commit()
        return None
    return json.loads(response)

def cache_set(key, value):
    cur = cache_conn.cursor()
    cur.execute("REPLACE INTO vt_cache (key, response, ts) VALUES (?, ?, ?)",
                (key, json.dumps(value), int(time.time())))
    cache_conn.commit()

# ===== قراءة الإيميل =====
def parse_eml(file_path):
    # دعم ~ و relative -> absolute
    file_path = os.path.abspath(os.path.expanduser(file_path))
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"EML file not found: {file_path}")

    with open(file_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    subject = msg.get("subject")
    from_addr = msg.get("from")
    return_path = msg.get("return-path")

    body_text = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            try:
                content = part.get_content() or ""
            except Exception:
                content = part.get_payload(decode=True) or b""
                if isinstance(content, bytes):
                    try:
                        content = content.decode(errors="ignore")
                    except Exception:
                        content = str(content)
            if ctype == "text/plain":
                body_text += content
            elif ctype == "text/html":
                # ازالة html tags بشكل بسيط
                body_text += unescape(re.sub('<[^<]+?>', ' ', content))
    else:
        try:
            body_text = msg.get_content() or ""
        except Exception:
            body_text = msg.get_payload(decode=True) or ""
            if isinstance(body_text, bytes):
                try:
                    body_text = body_text.decode(errors="ignore")
                except Exception:
                    body_text = str(body_text)

    return subject, from_addr, return_path, body_text

# ===== استخراج الروابط =====
URL_REGEX = re.compile(r"""(?ix)\b((?:https?://|www\.)[^\s<>"'()]+)""")

def extract_links(text):
    if not text:
        return []
    text = unescape(text)
    links = URL_REGEX.findall(text)
    cleaned = []
    for l in links:
        l = l.rstrip(".,;:!)\"'")
        if l.startswith("www."):
            l = "http://" + l
        cleaned.append(l)
    return list(dict.fromkeys(cleaned))

def is_ip_domain(netloc):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", netloc) is not None

# ===== VirusTotal URL check (optional) =====
def vt_check_url(url):
    if not VT_API_KEY:
        return None
    cache_key = "vt:" + url
    cached = cache_get(cache_key)
    if cached:
        return cached
    headers = {"x-apikey": VT_API_KEY}
    try:
        resp = requests.post(VT_API_URL, headers=headers, data={"url": url}, timeout=15)
        resp.raise_for_status()
        j = resp.json()
        analysis_id = j.get("data", {}).get("id")
        if not analysis_id:
            cache_set(cache_key, {"error": "no_analysis_id", "raw": j})
            return {"error": "no_analysis_id", "raw": j}

        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        for _ in range(6):
            r2 = requests.get(analysis_url, headers=headers, timeout=15)
            r2.raise_for_status()
            j2 = r2.json()
            status = j2.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                stats = j2.get("data", {}).get("attributes", {}).get("stats", {})
                result = {
                    "analysis_id": analysis_id,
                    "status": status,
                    "stats": stats,
                    "raw_analysis": j2
                }
                cache_set(cache_key, result)
                return result
            time.sleep(2)
        cache_set(cache_key, {"error": "analysis_timeout"})
        return {"error": "analysis_timeout"}
    except Exception as e:
        cache_set(cache_key, {"error": "exception", "msg": str(e)})
        return {"error": "exception", "msg": str(e)}

# ===== تحليل الروابط =====
def analyze_links(links):
    suspicious = []
    for link in links:
        try:
            parsed = urlparse(link)
            netloc = parsed.netloc.split(":")[0]
            ext = tldextract.extract(netloc)
            domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
            entry = {"link": link, "domain": domain, "reasons": []}

            if is_ip_domain(netloc):
                entry["reasons"].append("Uses IP instead of domain")
            if not ext.suffix:
                entry["reasons"].append("No valid TLD")
            if "@" in link:
                entry["reasons"].append("URL contains @ (possible redirect/trick)")
            if re.search(r"-login|secure-login|update-account|verify-account", link, re.I):
                entry["reasons"].append("URL path looks like credential phishing (login/verify/update)")

            vt_res = vt_check_url(link)
            if vt_res:
                if "error" not in vt_res:
                    stats = vt_res.get("stats") or {}
                    malicious_votes = stats.get("malicious", 0) + stats.get("suspicious", 0)
                    entry["vt_stats"] = stats
                    entry["malicious_votes"] = malicious_votes
                    if malicious_votes > 0:
                        entry["reasons"].append(f"VirusTotal flagged ({malicious_votes} engines)")
                else:
                    entry["vt_error"] = vt_res.get("error")
            suspicious.append(entry)
        except Exception as e:
            suspicious.append({"link": link, "reasons": ["analysis_exception"], "msg": str(e)})
    return suspicious

# ===== تحليل الهيدر =====
def analyze_headers(from_addr, return_path):
    findings = []
    from_str = str(from_addr) if from_addr is not None else ""
    rp = str(return_path) if return_path is not None else ""
    if rp and from_str and rp.lower() not in from_str.lower():
        findings.append(f"Spoofed sender? From: {from_str} vs Return-Path: {rp}")
    return findings

# ===== تحليل الكلمات المفتاحية =====
def analyze_keywords(body_text):
    findings = []
    if not body_text:
        return findings
    body_lower = body_text.lower()
    suspicious_keywords = ["urgent", "verify", "password", "account", "login",
                           "click here", "update", "confirm", "bank", "social security", "ssn"]
    for word in suspicious_keywords:
        idx = body_lower.find(word)
        if idx != -1:
            start = max(0, idx - 30)
            end = idx + len(word) + 30
            snippet = body_text[start:end].replace("\n", " ")
            findings.append({"keyword": word, "snippet": snippet.strip()})
    return findings

# ===== تحليل مسار/مجلد كامل من ملفات eml =====
def analyze_path(path):
    path = os.path.expanduser(path)
    # wildcard
    if any(ch in path for ch in ["*", "?"]):
        candidates = glob.glob(path, recursive=True)
    elif os.path.isdir(path):
        candidates = []
        for root, _, files in os.walk(path):
            for f in files:
                if f.lower().endswith(".eml"):
                    candidates.append(os.path.join(root, f))
    else:
        candidates = [path]

    reports = []
    for p in candidates:
        if os.path.isfile(p) and p.lower().endswith(".eml"):
            reports.append(run_analysis_single(p))
    return reports

# ===== تحليل ملف واحد (جوّه run_analysis نستدعيه) =====
def run_analysis_single(file_path):
    subject, from_addr, return_path, body_text = parse_eml(file_path)
    links = extract_links(body_text)
    link_findings = analyze_links(links)
    keyword_findings = analyze_keywords(body_text)
    header_findings = analyze_headers(from_addr, return_path)

    # ===== حساب Risk Score (High Risk version) =====
    score = 0
    if any("Spoofed sender" in f for f in header_findings):
        score += 30
    score += min(35, 5 * len(keyword_findings))  # رفع من 25 → 35
    for lf in link_findings:
        if lf.get("malicious_votes", 0) > 0:
            score += 40
        else:
            if "Uses IP instead of domain" in lf.get("reasons", []):
                score += 20
            if any("login" in r.lower() or "verify" in r.lower() for r in lf.get("reasons", [])):
                score += 15
    if len(header_findings) > 1:
        score += 5
    if score > 100:
        score = 100

    overall_risk = "Low"
    if score >= 70:
        overall_risk = "High"
    elif score >= 40:
        overall_risk = "Medium"

    return {
        "file": os.path.abspath(file_path),
        "subject": subject,
        "from": from_addr,
        "return_path": return_path,
        "header_findings": header_findings,
        "keyword_findings": keyword_findings,
        "link_findings": link_findings,
        "risk_score": score,
        "overall_risk": overall_risk,
    }

# ===== الواجهة العامة: run_analysis (يحافظ على التوافق) =====
def run_analysis(path_or_file):
    # لو المدخل ملف واحد أو مجلد -> نرجع dict أو list حسب الحالة
    path_or_file = os.path.expanduser(path_or_file)
    if os.path.isdir(path_or_file) or ("*" in path_or_file) or path_or_file.lower().endswith(".eml"):
        reports = analyze_path(path_or_file)
        if len(reports) == 1:
            return reports[0]
        return reports
    else:
        # افتراض أنه ملف .eml واحد لكن لم ينتهي ب .eml — نجرب فتحه
        return run_analysis_single(path_or_file)

# CLI usage
if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "sample.eml"
    res = run_analysis(target)
    # احفظ تقرير واحد أو متعدد
    if isinstance(res, list):
        for i, r in enumerate(res, 1):
            out = f"report_{i}.json"
            with open(out, "w", encoding="utf-8") as f:
                json.dump(r, f, indent=4, ensure_ascii=False)
            print(f"[+] Saved {out}")
    else:
        with open("report.json", "w", encoding="utf-8") as f:
            json.dump(res, f, indent=4, ensure_ascii=False)
        print("[+] Saved report.json")
        print(json.dumps(res, indent=4, ensure_ascii=False))
