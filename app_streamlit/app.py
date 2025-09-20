import streamlit as st
import os
import tempfile
from analysis import run_analysis, save_report_pdf  # use your analysis.py functions
import plotly.graph_objects as go

# ===== Streamlit page setup =====
st.set_page_config(page_title="PhishGuard", layout="wide", page_icon="🛡️")
st.markdown("<h1 style='color:#00e5ff'>PhishGuard — Phishing Email Analyzer</h1>", unsafe_allow_html=True)
st.markdown("رفع ملف .eml لتحليل البريد أو إدخال مسار الملف الكامل.")

# ===== Helper: Gauge =====
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

# ===== File input =====
uploaded_file = st.file_uploader("Upload a .eml file", type=["eml"])
local_path_input = st.text_input("Or enter full path to .eml file", "")

# Determine which file to analyze
eml_path = None
if uploaded_file:
    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp:
        tmp.write(uploaded_file.read())
        eml_path = tmp.name
elif local_path_input and os.path.isfile(local_path_input):
    eml_path = os.path.abspath(local_path_input)

# ===== Run analysis if file exists =====
if eml_path:
    with st.spinner("Analyzing email..."):
        report = run_analysis(eml_path)

        # Save PDF report
        pdf_path = eml_path + ".pdf"
        save_report_pdf(report, pdf_path)

        st.success(f"Analysis complete — Risk: {report['overall_risk']} (Score: {report['risk_score']})")

        # ===== Show gauge & findings =====
        col1, col2 = st.columns([1, 2])
        with col1:
            show_gauge(report['risk_score'])
            st.write("**Subject**", report.get("subject", "N/A"))
            st.write("**From**", report.get("from", "N/A"))
        with col2:
            st.subheader("Header Findings")
            for h in report.get("header_findings") or []:
                st.write("- " + str(h))
            st.subheader("Keywords")
            raw_keywords = report.get("keyword_findings") or []
            safe_keywords = [str(k) for k in raw_keywords if k is not None]
            st.write(", ".join(safe_keywords) if safe_keywords else "None")
            st.subheader("Link Findings")
            for lf in report.get("link_findings") or []:
                reasons = lf.get("reasons") or []
                reasons_text = ", ".join(reasons) if reasons else "No specific reason"
                st.write(f"- {lf.get('link')} — {reasons_text}")

        # PDF download
        if os.path.exists(pdf_path):
            with open(pdf_path, "rb") as f:
                st.download_button("Download PDF Report", f, file_name=os.path.basename(pdf_path))
else:
    st.info("Please upload a .eml file or enter a valid file path.")
