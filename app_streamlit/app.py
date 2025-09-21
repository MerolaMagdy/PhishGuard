import streamlit as st
import os
import plotly.graph_objects as go
from analysis import run_analysis
import analysis as analysis_module

analysis_module.VT_API_KEY = os.getenv("VT_API_KEY", None)

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from xml.sax.saxutils import escape
from html import escape
import tempfile


# ===== PDF Generation with safe escaping =====
# ===== حفظ التقرير كـ PDF =====
def save_report_pdf(report, pdf_path):
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(pdf_path)
    story = []

    # helper to safely escape any value
    def safe(val):
        return escape(str(val if val is not None else ""))

    # --- Basic info ---
    story.append(Paragraph("Subject: " + safe(report.get("subject")), styles["Title"]))
    story.append(Paragraph(f"Subject: {report.get('subject', '')}", styles['Title']))
    story.append(Spacer(1, 12))
    story.append(Paragraph("From: " + safe(report.get("from")), styles["Normal"]))
    story.append(Paragraph("Return-Path: " + safe(report.get("return_path")), styles["Normal"]))
    story.append(Paragraph(f"From: {report.get('from', '')}", styles['Normal']))
    story.append(Paragraph(f"Return-Path: {report.get('return_path', '')}", styles['Normal']))
    story.append(Spacer(1, 12))
    story.append(Paragraph(
        f"Overall Risk: {safe(report.get('overall_risk','N/A'))} "
        f"(Score: {safe(report.get('risk_score',0))})",
        styles["Normal"]
    ))
    story.append(
        Paragraph(
            f"Overall Risk: {report.get('overall_risk', 'N/A')} "
            f"(Score: {report.get('risk_score', 0)})",
            styles['Normal']
        )
    )
    story.append(Spacer(1, 12))

    # --- Header findings ---
    story.append(Paragraph("Header Findings:", styles["Heading2"]))
    # Header findings
    story.append(Paragraph("Header Findings:", styles['Heading2']))
    for h in report.get("header_findings") or []:
        story.append(Paragraph(safe(h), styles["Normal"]))
        story.append(Paragraph(str(h), styles['Normal']))
    story.append(Spacer(1, 12))

    # --- Keyword findings ---
    story.append(Paragraph("Keyword Findings:", styles["Heading2"]))
    raw_keywords = report.get("keyword_findings")
    if not raw_keywords:
        story.append(Paragraph("None", styles["Normal"]))
    else:
        if not isinstance(raw_keywords, list):
            raw_keywords = [raw_keywords]
        kws = ", ".join(safe(k) for k in raw_keywords if k is not None)
        story.append(Paragraph(kws if kws else "None", styles["Normal"]))
    # Keyword findings
    story.append(Paragraph("Keyword Findings:", styles['Heading2']))
    raw_keywords = report.get("keyword_findings") or []
    if not isinstance(raw_keywords, list):
        raw_keywords = [raw_keywords]
    keywords = [str(k) for k in raw_keywords if k is not None]
    story.append(Paragraph(", ".join(keywords) if keywords else "None", styles['Normal']))
    story.append(Spacer(1, 12))

    # --- Link findings ---
    story.append(Paragraph("Link Findings:", styles["Heading2"]))
    # Link findings
    story.append(Paragraph("Link Findings:", styles['Heading2']))
    for lf in report.get("link_findings") or []:
        link_txt = safe(lf.get("link", ""))
        reasons_list = lf.get("reasons", [])
        if not isinstance(reasons_list, list):
            reasons_list = [reasons_list]
        reasons_txt = ", ".join(safe(r) for r in reasons_list) or "No specific reason"
        story.append(Paragraph(f"{link_txt} — {reasons_txt}", styles["Normal"]))
        link = str(lf.get('link', ''))
        reasons = lf.get('reasons', [])
        reasons_text = ", ".join(reasons) if reasons else "No specific reason"
        story.append(Paragraph(f"{link} — {reasons_text}", styles['Normal']))

    doc.build(story)


# ===== Streamlit UI =====
st.set_page_config(page_title="PhishGuard", layout="wide", page_icon="🛡️")
st.markdown("<h1 style='color:#00e5ff'>PhishGuard — Phishing Email Analyzer</h1>", unsafe_allow_html=True)
st.markdown("ارفع ملف `.eml` لتحليله وإصدار تقرير PDF.")
st.markdown("رفع ملف `.eml` لتحليل البريد واستخراج تقرير PDF.")

uploaded_file = st.file_uploader("Upload a .eml file", type=["eml"])


# ===== Gauge =====
def show_gauge(score):
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
@@ -89,25 +79,24 @@

if uploaded_file:
    with st.spinner("Analyzing email..."):
        os.makedirs("uploads", exist_ok=True)
        temp_path = os.path.join("uploads", uploaded_file.name)

        with open(temp_path, "wb") as f:
            f.write(uploaded_file.read())
        # حفظ الملف مؤقتاً على السيرفر
        with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp:
            tmp.write(uploaded_file.read())
            temp_path = tmp.name

        # تشغيل التحليل
        report = run_analysis(temp_path)

        pdf_path = temp_path + ".pdf"
        save_report_pdf(report, pdf_path)

        st.success(
            f"Analysis complete — Risk: {report.get('overall_risk','N/A')} "
            f"(Score: {report.get('risk_score',0)})"
            f"Analysis complete — Risk: {report['overall_risk']} (Score: {report['risk_score']})"
        )
        col1, col2 = st.columns([1, 2])

        with col1:
            show_gauge(report.get('risk_score', 0))
            show_gauge(report['risk_score'])
            st.write("**Subject**")
            st.write(report.get("subject") or "N/A")
            st.write("**From**")
@@ -128,11 +117,9 @@
            st.subheader("Link Findings")
            for lf in report.get("link_findings") or []:
                reasons = lf.get("reasons", [])
                if not isinstance(reasons, list):
                    reasons = [reasons]
                reasons_text = ", ".join(str(r) for r in reasons) if reasons else "No specific reason"
                reasons_text = ", ".join(reasons) if reasons else "No specific reason"
                st.write(f"- {lf.get('link')} — {reasons_text}")

        if os.path.exists(pdf_path):
            with open(pdf_path, "rb") as f:
                st.download_button("Download PDF Report", f, file_name=os.path.basename(pdf_path))
