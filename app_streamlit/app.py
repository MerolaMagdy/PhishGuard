import os
import streamlit as st
import plotly.graph_objects as go
from html import escape
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import analysis as analysis_module

# لو عندك مفتاح VirusTotal
analysis_module.VT_API_KEY = os.getenv("VT_API_KEY", None)

import streamlit as st
from analysis import analyze_links

uploaded_file = st.file_uploader("Choose a .eml file", type="eml")
if uploaded_file is not None:
    content = uploaded_file.read()
    # parse content with your analysis code
    results = analyze_links_from_bytes(content)
    st.write(results)


# ===== حفظ التقرير كـ PDF =====
def save_report_pdf(report, pdf_path):
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(pdf_path)
    story = []

    story.append(Paragraph(f"Subject: {escape(str(report.get('subject', '')))}", styles['Title']))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"From: {escape(str(report.get('from', '')))}", styles['Normal']))
    story.append(Paragraph(f"Return-Path: {escape(str(report.get('return_path', '')))}", styles['Normal']))
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
        story.append(Paragraph(escape(str(h)), styles['Normal']))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Keyword Findings:", styles['Heading2']))
    keywords = [str(k) for k in (report.get("keyword_findings") or [])]
    story.append(Paragraph(", ".join(keywords) if keywords else "None", styles['Normal']))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Link Findings:", styles['Heading2']))
    for lf in report.get("link_findings") or []:
        link = str(lf.get('link', ''))
        reasons = lf.get('reasons', [])
        reasons_text = ", ".join(reasons) if reasons else "No specific reason"
        story.append(Paragraph(f"{escape(link)} — {escape(reasons_text)}", styles['Normal']))

    doc.build(story)


# ===== Streamlit UI =====
st.set_page_config(page_title="PhishGuard", layout="wide", page_icon="🛡️")
st.markdown("<h1 style='color:#00e5ff'>PhishGuard — Phishing Email Analyzer</h1>", unsafe_allow_html=True)
st.markdown("ارفع ملف `.eml` لتحليل البريد واستخراج تقرير PDF.")

uploaded_file = st.file_uploader("اختر ملف .eml من جهازك", type=["eml"])

# ===== Gauge =====
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
        # نقرأ المحتوى مباشرة من الذاكرة
        from analysis import run_analysis_bytes  # لازم تكوني ضيفتيها في analysis.py
        report = run_analysis_bytes(uploaded_file.read())

        # إنشاء تقرير PDF في ذاكرة مؤقتة
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp_pdf:
            save_report_pdf(report, tmp_pdf.name)
            pdf_path = tmp_pdf.name

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
            keywords = [str(k) for k in (report.get("keyword_findings") or [])]
            st.write(", ".join(keywords) if keywords else "None")

            st.subheader("Link Findings")
            for lf in report.get("link_findings") or []:
                reasons = lf.get("reasons", [])
                reasons_text = ", ".join(reasons) if reasons else "No specific reason"
                st.write(f"- {lf.get('link')} — {reasons_text}")

        # زر لتحميل التقرير PDF
        with open(pdf_path, "rb") as f:
            st.download_button("Download PDF Report", f, file_name="phishguard_report.pdf")
