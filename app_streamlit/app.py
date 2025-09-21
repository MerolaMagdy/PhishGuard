import re, json, time, sqlite3, requests, os
import tldextract
from urllib.parse import urlparse
from email import policy
from email.parser import BytesParser
from html import unescape

# ======================= إعدادات وتحليل البريد ==========================
VT_API_KEY = os.getenv("VT_API_KEY", None)
VT_API_URL = "https://www.virustotal.com/api/v3/urls"
CACHE_DB = "vt_cache.sqlite"
CACHE_TTL = 60 * 60 * 24  # 24 ساعة

def init_cache():
    conn = sqlite3.connect(CACHE_DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS vt_cache (
            key TEXT PRIMARY KEY,
            response TEXT,
            ts INTEGER
        )
    """)
    conn.commit()
    return conn

_cache_conn = init_cache()

def _cache_get(key):
    cur = _cache_conn.cursor()
    cur.execute("SELECT response, ts FROM vt_cache WHERE key=?", (key,))
    row = cur.fetchone()
    if not row: return None
    response, ts = row
    if time.time() - ts > CACHE_TTL:
        cur.execute("DELETE FROM vt_cache WHERE key=?", (key,))
        _cache_conn.commit()
        return None
    return json.loads(response)

def _cache_set(key, value):
    _cache_conn.execute(
        "REPLACE INTO vt_cache (key, response, ts) VALUES (?, ?, ?)",
        (key, json.dumps(value), int(time.time()))
    )
    _cache_conn.commit()

def parse_eml(path):
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return _extract_parts(msg)

def _extract_parts(msg):
    subject, from_addr, return_path = msg["subject"], msg["from"], msg["return-path"]
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain":
                body += part.get_content() or ""
            elif ctype == "text/html":
                body += unescape(re.sub("<[^<]+?>", " ", part.get_content() or ""))
    else:
        body = msg.get_content() or ""
    return subject, from_addr, return_path, body

URL_REGEX = re.compile(r"(?ix)\b((?:https?://|www\.)[^\s<>'\"()]+)")

def extract_links(text):
    if not text: return []
    text = unescape(text)
    links = URL_REGEX.findall(text)
    cleaned = []
    for l in links:
        l = l.rstrip(".,;:!)\"'")
        if l.startswith("www."): l = "http://" + l
        cleaned.append(l)
    return list(dict.fromkeys(cleaned))

def is_ip_domain(netloc):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", netloc) is not None

def vt_check_url(url):
    if not VT_API_KEY: return None
    cache_key = "vt:" + url
    cached = _cache_get(cache_key)
    if cached: return cached
    headers = {"x-apikey": VT_API_KEY}
    try:
        r = requests.post(VT_API_URL, headers=headers, data={"url": url}, timeout=15)
        r.raise_for_status()
        analysis_id = r.json().get("data", {}).get("id")
        if not analysis_id:
            _cache_set(cache_key, {"error": "no_id"})
            return {"error": "no_id"}
        check_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        for _ in range(6):
            r2 = requests.get(check_url, headers=headers, timeout=15)
            r2.raise_for_status()
            j2 = r2.json()
            status = j2.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                stats = j2["data"]["attributes"].get("stats", {})
                result = {"stats": stats, "analysis_id": analysis_id}
                _cache_set(cache_key, result)
                return result
            time.sleep(2)
        _cache_set(cache_key, {"error": "timeout"})
        return {"error": "timeout"}
    except Exception as e:
        _cache_set(cache_key, {"error": str(e)})
        return {"error": str(e)}

def analyze_links(links):
    results = []
    for link in links:
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
            entry["reasons"].append("Contains @ (possible redirect)")
        if re.search(r"-login|verify|update-account", link, re.I):
            entry["reasons"].append("URL resembles login/verify page")

       # vt = vt_check_url(link)
        #if vt and "stats" in vt:
            #mal = vt["stats"].get("malicious", 0) + vt["stats"].get("suspicious", 0)
            #if mal > 0:
               # entry["reasons"].append(f"VirusTotal flagged ({mal})")
               # entry["malicious_votes"] = mal
        results.append(entry)
    return results

def analyze_headers(frm, rpath):
    f, rp = str(frm or ""), str(rpath or "")
    if f and rp and rp.lower() not in f.lower():
        return [f"Spoofed sender? From: {f} vs Return-Path: {rp}"]
    return []

def analyze_keywords(body):
    if not body: return []
    kws = ["urgent","verify","password","account","login","click here",
           "update","confirm","bank","social security","ssn"]
    res, lower = [], body.lower()
    for k in kws:
        if k in lower: res.append(k)
    return res

def run_analysis(path):
    subject, frm, rpath, body = parse_eml(path)
    links = extract_links(body)
    link_findings = analyze_links(links)
    kw_findings = analyze_keywords(body)
    hdr_findings = analyze_headers(frm, rpath)

    score = 0
    if hdr_findings: score += 30
    score += min(25, 5 * len(kw_findings))
    for lf in link_findings:
        if lf.get("malicious_votes", 0) > 0: score += 40
        if any("login" in r.lower() or "verify" in r.lower()
               for r in lf.get("reasons", [])): score += 10
    score = min(score, 100)

    risk = "Low" if score < 40 else "Medium" if score < 70 else "High"
    return {
        "subject": subject,
        "from": frm,
        "return_path": rpath,
        "header_findings": hdr_findings,
        "keyword_findings": kw_findings,
        "link_findings": link_findings,
        "risk_score": score,
        "overall_risk": risk
    }

# ========================= واجهة Streamlit ===============================
import streamlit as st
import plotly.graph_objects as go
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

def save_report_pdf(report, pdf_path):
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(pdf_path)
    story = [
        Paragraph(f"Subject: {report.get('subject','')}", styles['Title']),
        Spacer(1,12),
        Paragraph(f"From: {report.get('from','')}", styles['Normal']),
        Paragraph(f"Return-Path: {report.get('return_path','')}", styles['Normal']),
        Spacer(1,12),
        Paragraph(f"Overall Risk: {report['overall_risk']} "
                  f"(Score: {report['risk_score']})", styles['Normal']),
        Spacer(1,12),
        Paragraph("Header Findings:", styles['Heading2'])
    ]
    for h in report.get("header_findings", []):
        story.append(Paragraph(str(h), styles['Normal']))
    story.append(Spacer(1,12))
    story.append(Paragraph("Keyword Findings:", styles['Heading2']))
    story.append(Paragraph(", ".join(report.get("keyword_findings", [])) or "None",
                           styles['Normal']))
    story.append(Spacer(1,12))
    story.append(Paragraph("Link Findings:", styles['Heading2']))
    for lf in report.get("link_findings", []):
        story.append(Paragraph(f"{lf.get('link')} — {', '.join(lf.get('reasons', []))}",
                               styles['Normal']))
    doc.build(story)

def show_gauge(score):
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        gauge={'axis': {'range': [0,100]},
               'bar': {'color': "darkred" if score>=70 else "orange" if score>=40 else "green"}},
        title={'text': "Risk Score"}
    ))
    fig.update_layout(height=280, margin=dict(l=20, r=20, t=30, b=10))
    st.plotly_chart(fig, use_container_width=True)

st.set_page_config(page_title="PhishGuard", layout="wide", page_icon="🛡️")
st.markdown("<h1 style='color:#00e5ff'>PhishGuard — Phishing Email Analyzer</h1>", unsafe_allow_html=True)
st.markdown("ارفع ملف `.eml` لتحليل البريد والحصول على تقرير PDF.")

uploaded = st.file_uploader("Upload a .eml file", type=["eml"])

if uploaded:
    with st.spinner("Analyzing email..."):
        os.makedirs("uploads", exist_ok=True)
        temp_path = os.path.join("uploads", uploaded.name)
        with open(temp_path, "wb") as f:
            f.write(uploaded.read())

        report = run_analysis(temp_path)
        pdf_path = temp_path + ".pdf"
        save_report_pdf(report, pdf_path)

        st.success(f"Analysis complete — Risk: {report['overall_risk']} "
                   f"(Score: {report['risk_score']})")

        col1, col2 = st.columns([1, 2])
        with col1:
            show_gauge(report['risk_score'])
            st.write("**Subject**", report.get("subject") or "N/A")
            st.write("**From**", report.get("from") or "N/A")
        with col2:
            st.subheader("Header Findings")
            for h in report.get("header_findings") or []:
                st.write("- " + str(h))
            st.subheader("Keywords")
            st.write(", ".join(report.get("keyword_findings", [])) or "None")
            st.subheader("Link Findings")
            for lf in report.get("link_findings") or []:
                st.write(f"- {lf.get('link')} — {', '.join(lf.get('reasons', []))}")
        if os.path.exists(pdf_path):
            with open(pdf_path, "rb") as f:
                st.download_button("Download PDF Report", f,
                                   file_name=os.path.basename(pdf_path))
