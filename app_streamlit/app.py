import streamlit as st
import os
import plotly.graph_objects as go
from analysis import run_analysis
import analysis as analysis_module

analysis_module.VT_API_KEY = os.getenv("VT_API_KEY", None)

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from xml.sax.saxutils import escape


# ===== PDF Generation with safe escaping =====
def save_report_pdf(report, pdf_path):
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(pdf_path)
    story = []

    # helper to safely escape any value
    def safe(val):
        return escape(str(val if val is not None else ""))

    # --- Basic info ---
    story.append(Paragraph("Subject: " + safe(report.get("subject")), styles["Title"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph("From: " + safe(report.get("from")), styles["Normal"]))
    story.append(Paragraph("Return-Path: " + safe(report.get("return_path")), styles["Normal"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(
        f"Overall Risk: {safe(report.get('overall_risk','N/A'))} "
        f"(Score: {safe(report.get('risk_score',0))})",
        styles["Normal"]
    ))
    story.append(Spacer(1, 12))

    # --- Header findings ---
    story.append(Paragraph("Header Findings:", styles["Heading2"]))
    for h in report.get("header_findings") or []:
        story.append(Paragraph(safe(h), styles["Normal"]))
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
    story.append(Spacer(1, 12))

    # --- Link findings ---
    story.append(Paragraph("Link Findings:", styles["Heading2"]))
    for lf in report.get("link_findings") or []:
        link_txt = safe(lf.get("link", ""))
        reasons_list = lf.get("reasons", [])
        if not isinstance(reasons_list, list):
            reasons_list = [reasons_list]
        reasons_txt = ", ".join(safe(r) for r in reasons_list) or "No specific reason"
        story.append(Paragraph(f"{link_txt} — {reasons_txt}", styles["Normal"]))

    doc.build(story)


# ===== Streamlit UI =====
st.set_page_config(page_title="PhishGuard", layout="wide", page_icon="🛡️")
st.markdown("<h1 style='color:#00e5ff'>PhishGuard — Phishing Email Analyzer</h1>", unsafe_allow_html=True)
st.markdown("ارفع ملف `.eml` لتحليله وإصدار تقرير PDF.")

uploaded_file = st.file_uploader("Upload a .eml file", type=["eml"])


def show_gauge(score):
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        gauge={
            'axis': {'range': [0, 100]},
            'bar': {'color': "darkred" if score >= 70 else "orange" if score >= 40 else "green"}
        },
        title={'text': "Risk Score"}
    ))
    fig.update_layout(height=280, margin=dict(l=20, r=20, t=30, b=10))
    st.plotly_chart(fig, use_container_width=True)


if uploaded_file:
    with st.spinner("Analyzing email..."):
        os.makedirs("uploads", exist_ok=True)
        temp_path = os.path.join("uploads", uploaded_file.name)

        with open(temp_path, "wb") as f:
            f.write(uploaded_file.read())

        report = run_analysis(temp_path)

        pdf_path = temp_path + ".pdf"
        save_report_pdf(report, pdf_path)

        st.success(
            f"Analysis complete — Risk: {report.get('overall_risk','N/A')} "
            f"(Score: {report.get('risk_score',0)})"
        )
        col1, col2 = st.columns([1, 2])

        with col1:
            show_gauge(report.get('risk_score', 0))
            st.write("**Subject**")
            st.write(report.get("subject") or "N/A")
            st.write("**From**")
            st.write(report.get("from") or "N/A")

        with col2:
            st.subheader("Header Findings")
            for h in report.get("header_findings") or []:
                st.write("- " + str(h))

            st.subheader("Keywords")
            raw_keywords = report.get("keyword_findings") or []
            if not isinstance(raw_keywords, list):
                raw_keywords = [raw_keywords]
            safe_keywords = [str(k) for k in raw_keywords if k is not None]
            st.write(", ".join(safe_keywords) if safe_keywords else "None")

            st.subheader("Link Findings")
            for lf in report.get("link_findings") or []:
                reasons = lf.get("reasons", [])
                if not isinstance(reasons, list):
                    reasons = [reasons]
                reasons_text = ", ".join(str(r) for r in reasons) if reasons else "No specific reason"
                st.write(f"- {lf.get('link')} — {reasons_text}")

        if os.path.exists(pdf_path):
            with open(pdf_path, "rb") as f:
                st.download_button("Download PDF Report", f, file_name=os.path.basename(pdf_path))
