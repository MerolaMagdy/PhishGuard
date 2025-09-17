import streamlit as st
import requests
import os
import plotly.graph_objects as go

API_URL = "http://127.0.0.1:8000/analyze"

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
    with st.spinner("Uploading & analyzing..."):
        files = {"file": (uploaded_file.name, uploaded_file.read(), "message/rfc822")}
        try:
            resp = requests.post(API_URL, files=files, timeout=30)
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            st.error(f"Could not reach backend API: {e}")
            st.info("تأكدي إنّ الـ backend (FastAPI) شغّال على http://127.0.0.1:8000")
            st.stop()

        data = resp.json()
        report = data.get("report") or data

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

        pdf_path = data.get("pdf")
        if pdf_path and os.path.exists(pdf_path):
            with open(pdf_path, "rb") as f:
                st.download_button("Download PDF Report", f, file_name=os.path.basename(pdf_path))
        else:
            st.info("No PDF available (backend may not have generated it).")
