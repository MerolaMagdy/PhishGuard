import re
import json
import tldextract
from urllib.parse import urlparse
from email import policy
from email.parser import BytesParser
import streamlit as st


def parse_eml_from_bytes(file_bytes):
    """تحليل ملف EML من البايتات مباشرة"""
    msg = BytesParser(policy=policy.default).parsebytes(file_bytes)

    subject = msg["subject"]
    from_addr = msg["from"]
    return_path = msg["return-path"]

    body_text = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body_text += part.get_content()
    else:
        body_text = msg.get_content()

    return subject, from_addr, return_path, body_text


def extract_links(text):
    pattern = r"(https?://[^\s]+)"
    return re.findall(pattern, text)


def is_ip_domain(netloc):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", netloc) is not None


def analyze_links(links):
    suspicious = []
    for link in links:
        parsed = urlparse(link)
        netloc = parsed.netloc.split(":")[0]
        ext = tldextract.extract(netloc)
        if is_ip_domain(netloc):
            suspicious.append({"link": link, "reason": "Uses IP instead of domain"})
        elif not ext.suffix:
            suspicious.append({"link": link, "reason": "No valid TLD"})
    return suspicious


def analyze_headers(from_addr, return_path):
    findings = []
    if from_addr and return_path and return_path.lower() != from_addr.lower():
        findings.append(f"Spoofed sender? From: {from_addr} vs Return-Path: {return_path}")
    return findings


def analyze_keywords(body_text):
    findings = []
    body_lower = body_text.lower()
    suspicious_keywords = ["urgent", "verify", "password", "account", "login", "click here", "update"]
    for word in suspicious_keywords:
        if word in body_lower:
            findings.append(word)
    return findings


# ---------------- Streamlit UI -----------------
st.title("PhishGuard – Email Analysis")

uploaded_file = st.file_uploader("Upload .eml file", type="eml")

if uploaded_file is not None:
    # نقرأ البايتات مباشرة بدون حفظ الملف
    eml_bytes = uploaded_file.read()
    subject, from_addr, return_path, body_text = parse_eml_from_bytes(eml_bytes)

    links = extract_links(body_text)
    link_findings = analyze_links(links)
    keyword_findings = analyze_keywords(body_text)
    header_findings = analyze_headers(from_addr, return_path)

    risk_score = 0
    if any("Spoofed sender" in f for f in header_findings):
        risk_score += 40
    if keyword_findings:
        risk_score += 20
    if link_findings:
        risk_score += 20
    if header_findings:
        risk_score += 10

    overall_risk = "Low"
    if risk_score >= 70:
        overall_risk = "High"
    elif risk_score >= 40:
        overall_risk = "Medium"

    report = {
        "subject": subject,
        "from": from_addr,
        "return_path": return_path,
        "header_findings": header_findings,
        "keyword_findings": keyword_findings,
        "link_findings": link_findings,
        "risk_score": risk_score,
        "overall_risk": overall_risk,
    }

    # عرض النتيجة
    st.json(report)

    # حفظ التقرير اختيارياً
    with open("report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)
