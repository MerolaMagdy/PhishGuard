# analysis_debug.py
import re, json, time, sqlite3, tldextract, requests
from urllib.parse import urlparse
from email import policy
from email.parser import BytesParser
from html import unescape

VT_API_KEY = None
VT_API_URL = "https://www.virustotal.com/api/v3/urls"
CACHE_DB = "vt_cache.sqlite"
CACHE_TTL = 60 * 60 * 24

# ---------- Cache ----------
def init_cache():
    conn = sqlite3.connect(CACHE_DB)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS vt_cache (
        key TEXT PRIMARY KEY,
        response TEXT,
        ts INTEGER
    )""")
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

# ---------- Parse EML ----------
def parse_eml(file_path):
    with open(file_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    subject = msg["subject"]
    from_addr = msg["from"]
    return_path = msg["return-path"]

    body_text = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain":
                body_text += part.get_content() or ""
            elif ctype == "text/html":
                body_text += unescape(re.sub('<[^<]+?>', ' ', part.get_content() or ""))
    else:
        body_text = msg.get_content() or ""

    ### DEBUG
    print("[DEBUG] Subject:", subject)
    print("[DEBUG] From:", from_addr)
    print("[DEBUG] Return-Path:", return_path)
    print("[DEBUG] Body length:", len(body_text))

    return subject, from_addr, return_path, body_text

# ---------- Link extraction ----------
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
    ### DEBUG
    print("[DEBUG] Extracted links:", cleaned)
    return list(dict.fromkeys(cleaned))

def is_ip_domain(netloc):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", netloc) is not None

# ---------- VirusTotal check ----------
def vt_check_url(url):
    if not VT_API_KEY:
        return None
    cache_key = "vt:" + url
    cached = cache_get(cache_key)
    if cached:
        return cached
    # (API calls unchanged)
    return None

# ---------- Analyze links ----------
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

            suspicious.append(entry)
        except Exception as e:
            suspicious.append({"link": link, "reason": "analysis_exception", "msg": str(e)})

    ### DEBUG
    print("[DEBUG] Link findings:", suspicious)
    return suspicious

# ---------- Analyze headers ----------
def analyze_headers(from_addr, return_path):
    findings = []
    if from_addr and return_path:
        f_str = str(from_addr)
        rp = str(return_path)
        if rp.lower() not in f_str.lower():
            findings.append(f"Spoofed sender? From: {f_str} vs Return-Path: {rp}")
    ### DEBUG
    print("[DEBUG] Header findings:", findings)
    return findings

# ---------- Analyze keywords ----------
def analyze_keywords(body_text):
    findings = []
    if not body_text:
        return findings
    body_lower = body_text.lower()
    suspicious_keywords = [
        "urgent","verify","password","account","login",
        "click here","update","confirm","bank","social security","ssn"
    ]
    for word in suspicious_keywords:
        if word in body_lower:
            findings.append(word)
    ### DEBUG
    print("[DEBUG] Keyword findings:", findings)
    return findings

# ---------- Full run ----------
def run_analysis(file_path):
    subject, from_addr, return_path, body_text = parse_eml(file_path)
    links = extract_links(body_text)
    link_findings = analyze_links(links)
    keyword_findings = analyze_keywords(body_text)
    header_findings = analyze_headers(from_addr, return_path)

    score = 0
    if any("Spoofed sender" in f for f in header_findings):
        score += 30
    score += min(25, 5 * len(keyword_findings))
    for lf in link_findings:
        if lf.get("malicious_votes", 0) > 0:
            score += 40
        else:
            if "Uses IP instead of domain" in lf.get("reasons", []):
                score += 15
            if any("login" in r.lower() or "verify" in r.lower() for r in lf.get("reasons", [])):
                score += 10
    if len(header_findings) > 1:
        score += 5
    score = min(score, 100)

    risk = "Low"
    if score >= 70:
        risk = "High"
    elif score >= 40:
        risk = "Medium"

    report = {
        "subject": subject,
        "from": from_addr,
        "return_path": return_path,
        "header_findings": header_findings,
        "keyword_findings": keyword_findings,
        "link_findings": link_findings,
        "risk_score": score,
        "overall_risk": risk
    }

    ### DEBUG
    print("[DEBUG] Final risk score:", score, "Overall risk:", risk)
    return report

if __name__ == "__main__":
    import sys
    fp = sys.argv[1] if len(sys.argv) > 1 else "sample.eml"
    r = run_analysis(fp)
    with open("report.json", "w", encoding="utf-8") as f:
        json.dump(r, f, indent=4, ensure_ascii=False)
    print(json.dumps(r, indent=4, ensure_ascii=False))
