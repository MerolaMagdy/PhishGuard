import streamlit as st
import os
import plotly.graph_objects as go
from analysis import run_analysis
import analysis as analysis_module
# مفتاح VirusTotal من متغير البيئة لو مُعرّف
analysis_module.VT_API_KEY = os.getenv("VT_API_KEY", None)
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet


def save_report_pdf(report, pdf_path):
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(pdf_path)
    story = []

    story.append(Paragraph(f"Subject: {report.get('subject', '')}", styles['Title']))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"From: {report.get('from', '')}", styles['Normal']))
    story.append(Paragraph(f"Return-Path: {report.get('return_path', '')}", styles['Normal']))
    story.append(Spacer(1, 12))
    story.append(
        Paragraph(
            f"Overall Risk: {report.get('overall_risk', 'N/A')} "
            f"(Score: {report.get('risk_score', 0)})",
            styles['Normal']
        )
    )
    story.append(Spacer(1, 12))

    story.append(Paragraph("Header Findings:", styles['Heading2']))
    for h in report.get("header_findings") or []:
        story.append(Paragraph(str(h), styles['Normal']))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Keyword Findings:", styles['Heading2']))
    raw_keywords = report.get("keyword_findings") or []
    if not isinstance(raw_keywords, list):
        raw_keywords = [raw_keywords]
    keywords = [str(k) for k in raw_keywords if k is not None]
    story.append(Paragraph(", ".join(keywords) if keywords else "None", styles['Normal']))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Link Findings:", styles['Heading2']))
    for lf in report.get("link_findings") or []:
        link = str(lf.get('link', ''))
        reason = str(lf.get('reason', ''))
        story.append(Paragraph(f"{link} — {reason}", styles['Normal']))
    
    print("DEBUG report:", report)
    doc.build(story)



st.set_page_config(page_title="PhishGuard", layout="wide", page_icon="🛡️")
st.markdown("<h1 style='color:#00e5ff'>PhishGuard — Phishing Email Analyzer</h1>", unsafe_allow_html=True)
st.markdown("رفع ملف `.eml` لتحليل البريد واستخراج تقرير PDF.")

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
        # احفظ الملف موقتًا
        with open(temp_path, "wb") as f:
            f.write(uploaded_file.read())

        # شغّل التحليل مباشرة
        report = run_analysis(temp_path)

        # أنشئ ملف الـ PDF
        pdf_path = temp_path + ".pdf"
        save_report_pdf(report, pdf_path)

        st.success(
            f"Analysis complete — Risk: {report['overall_risk']} (Score: {report['risk_score']})"
        )
        col1, col2 = st.columns([1, 2])

        with col1:
            show_gauge(report['risk_score'])
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
                st.write(f"- {lf.get('link')} — {lf.get('reason')}")

        if os.path.exists(pdf_path):
            with open(pdf_path, "rb") as f:
                st.download_button("Download PDF Report", f, file_name=os.path.basename(pdf_path))
