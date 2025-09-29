# analysis.py  –  PhishGuard with explicit Safe / Suspicious status
import os, re, json, time, sqlite3, requests, tldextract
from urllib.parse import urlparse
from email import policy
from email.parser import BytesParser
from html import unescape

# ---------- CONFIG ----------
VT_API_KEY = None  # put your VirusTotal key here if you have one
VT_API_URL = "https://www.virustotal.com/api/v3/urls"
CACHE_DB = "vt_cache.sqlite"
CACHE_TTL = 60 * 60 * 24
# ----------------------------

# ---------- Cache ----------
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
    if not row: return None
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
    return subject, from_addr, return_path, body_text

# ---------- Extract Links ----------
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

# ---------- VirusTotal ----------
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
            cache_set(cache_key, {"error": "no_analysis_id"})
            return {"error": "no_analysis_id"}

        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        for _ in range(6):
            r2 = requests.get(analysis_url, headers=headers, timeout=15)
            r2.raise_for_status()
            j2 = r2.json()
            status = j2.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                stats = j2.get("data", {}).get("attributes", {}).get("stats", {})
                cache_set(cache_key, {"stats": stats})
                return {"stats": stats}
            time.sleep(2)
        cache_set(cache_key, {"error": "analysis_timeout"})
        return {"error": "analysis_timeout"}
    except Exception as e:
        cache_set(cache_key, {"error": "exception", "msg": str(e)})
        return {"error": "exception", "msg": str(e)}

# ---------- Categorize ----------
def categorize_link(link):
    parsed = urlparse(link)
    host = parsed.netloc.lower()
    path = parsed.path.lower()
    if "hubspot" in host: return "HubSpot tracking / marketing link"
    if "ngrok.com" in host: return "Ngrok asset or hosted resource"
    if path.endswith(".woff"): return "Web font file"
    if path.endswith((".jpg", ".jpeg", ".png", ".gif", ".svg")): return "Image resource"
    if path.endswith((".css", ".js")): return "Static script or stylesheet"
    return None

# ---------- Analyze Links with Safe/Suspicious ----------
def analyze_links(links):
    seen = set()
    results = []
    for link in links:
        if link in seen:
            continue
        seen.add(link)

        try:
            parsed = urlparse(link)
            netloc = parsed.netloc.split(":")[0]
            ext = tldextract.extract(netloc)
            domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

            reasons = []
            suspicious_flag = False  # track heuristics

            if is_ip_domain(netloc):
                reasons.append("Uses IP instead of domain")
                suspicious_flag = True
            if not ext.suffix:
                reasons.append("No valid TLD")
                suspicious_flag = True
            if "@" in link:
                reasons.append("URL contains @ (possible redirect/trick)")
                suspicious_flag = True
            if re.search(r"-login|secure-login|update-account|verify-account", link, re.I):
                reasons.append("URL path looks like credential phishing")
                suspicious_flag = True

            vt_votes = 0
            vt_res = vt_check_url(link)
            if vt_res and "error" not in vt_res:
                stats = vt_res.get("stats") or {}
                vt_votes = stats.get("malicious", 0) + stats.get("suspicious", 0)
                if vt_votes > 0:
                    reasons.append(f"VirusTotal flagged ({vt_votes} engines)")
                    suspicious_flag = True

            label = categorize_link(link)
            if label:
                reasons.append(label)

            if not reasons:
                reasons.append("No specific reason")

            # FINAL SAFE / SUSPICIOUS STATUS
            status = "Safe" if (vt_votes == 0 and not suspicious_flag) else "Suspicious"

            results.append({
                "link": link,
                "domain": domain,
                "reasons": reasons,
                "status": status
            })
        except Exception as e:
            results.append({
                "link": link,
                "domain": "",
                "reasons": [f"analysis error: {e}"],
                "status": "Suspicious"
            })
    return results

# ---------- Headers & Keywords ----------
def analyze_headers(from_addr, return_path):
    findings = []
    if from_addr and return_path:
        fstr = ", ".join(from_addr) if isinstance(from_addr,(list,tuple)) else str(from_addr)
        rp   = ", ".join(return_path) if isinstance(return_path,(list,tuple)) else str(return_path)
        if rp and fstr and rp.lower() not in fstr.lower():
            findings.append(f"Spoofed sender? From: {fstr} vs Return-Path: {rp}")
    return findings

def analyze_keywords(body_text):
    findings = []
    if not body_text: return findings
    lower = body_text.lower()
    suspicious = ["urgent","verify","password","account","login",
                  "click here","update","confirm","bank","social security","ssn"]
    for w in suspicious:
        idx = lower.find(w)
        if idx != -1:
            snippet = body_text[max(0,idx-30):idx+len(w)+30].replace("\n"," ")
            findings.append({"keyword": w, "snippet": snippet.strip()})
    return findings

# ---------- Risk Score ----------
def run_analysis(file_path):
    file_path = os.path.abspath(file_path)
    subject, from_addr, return_path, body_text = parse_eml(file_path)
    links = extract_links(body_text)
    link_findings = analyze_links(links)
    keyword_findings = analyze_keywords(body_text)
    header_findings = analyze_headers(from_addr, return_path)

    score = 0
    if any("Spoofed sender" in f for f in header_findings): score += 30
    score += min(35, 5 * len(keyword_findings))
    for lf in link_findings:
        if lf["status"] == "Suspicious":
            score += 20
    if len(header_findings) > 1: score += 5
    if score > 100: score = 100

    risk = "Low"
    if score >= 70: risk = "High"
    elif score >= 40: risk = "Medium"

    return {
        "subject": subject,
        "from": from_addr,
        "return_path": return_path,
        "header_findings": header_findings,
        "keyword_findings": keyword_findings,
        "link_findings": link_findings,
        "risk_score": score,
        "overall_risk": risk,
    }

if __name__ == "__main__":
    import sys
    fp = sys.argv[1] if len(sys.argv) > 1 else "sample.eml"
    result = run_analysis(fp)
    with open("report.json", "w", encoding="utf-8") as f:
        json.dump(result, f, indent=4, ensure_ascii=False)
    print(json.dumps(result, indent=4, ensure_ascii=False))
