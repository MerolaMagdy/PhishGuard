import streamlit as st
import os
import plotly.graph_objects as go
import os
from .analysis import run_analysis
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

def save_report_pdf(report, pdf_path):
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(pdf_path)
    story = []

    story.append(Paragraph(f"Subject: {report['subject']}", styles['Title']))
    story.append(Spacer(1,12))
    story.append(Paragraph(f"From: {report['from']}", styles['Normal']))
    story.append(Paragraph(f"Return-Path: {report['return_path']}", styles['Normal']))
    story.append(Spacer(1,12))
    story.append(Paragraph(f"Overall Risk: {report['overall_risk']} (Score: {report['risk_score']})", styles['Normal']))
    story.append(Spacer(1,12))

    story.append(Paragraph("Header Findings:", styles['Heading2']))
    for h in report['header_findings']:
        story.append(Paragraph(str(h), styles['Normal']))
    story.append(Spacer(1,12))

    story.append(Paragraph("Keyword Findings:", styles['Heading2']))
    story.append(Paragraph(", ".join(report['keyword_findings'] or ["None"]), styles['Normal']))
    story.append(Spacer(1,12))

    story.append(Paragraph("Link Findings:", styles['Heading2']))
    for lf in report['link_findings']:
        story.append(Paragraph(f"{lf['link']} — {lf['reason']}", styles['Normal']))

    doc.build(story)




st.set_page_config(page_title="PhishGuard", layout="wide", page_icon="🛡️")
st.markdown("<h1 style='color:#00e5ff'>PhishGuard — Phishing Email Analyzer</h1>", unsafe_allow_html=True)
st.markdown("رفع ملف `.eml` لتحليل البريد واستخراج تقرير PDF.")

uploaded_file = st.file_uploader("Upload a .eml file", type=["eml"])

def show_gauge(score):
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        gauge={'axis': {'range': [0,100]},
               'bar': {'color': "darkred" if score>=70 else "orange" if score>=40 else "green"}},
        title={'text': "Risk Score"}
    ))
    fig.update_layout(height=280, margin=dict(l=20,r=20,t=30,b=10))
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


        st.success(f"Analysis complete — Risk: {report['overall_risk']} (Score: {report['risk_score']})")
        col1, col2 = st.columns([1,2])

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
            st.write(", ".join(report.get("keyword_findings") or ["None"]))

            st.subheader("Link Findings")
            for lf in report.get("link_findings") or []:
                st.write(f"- {lf.get('link')} — {lf.get('reason')}")

        if os.path.exists(pdf_path):
            with open(pdf_path, "rb") as f:
                st.download_button("Download PDF Report", f, file_name=os.path.basename(pdf_path))
            
        

