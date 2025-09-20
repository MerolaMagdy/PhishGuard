# ===== Imports =====
import streamlit as st
import email
from urllib.parse import urlparse
import tldextract
import re
import pandas as pd
import plotly.graph_objects as go
from analysis import analyze_links  # تأكدي دالتك جاهزة

# ===== Streamlit page config MUST be at the top =====
st.set_page_config(page_title="PhishGuard", layout="wide")

# ===== Title =====
st.title("PhishGuard – Email Phishing Detection")

# ===== File uploader =====
uploaded_file = st.file_uploader("Upload a .eml file", type="eml")

if uploaded_file is not None:
    try:
        # قراءة محتوى الملف
        content = uploaded_file.read()
        msg = email.message_from_bytes(content)
        
        # جمع كل الروابط في البريد
        links = []
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body = part.get_payload(decode=True).decode(errors="ignore")
                    links += re.findall(r'https?://\S+', body)
        else:
            body = msg.get_payload(decode=True).decode(errors="ignore")
            links += re.findall(r'https?://\S+', body)

        # ===== تحليل الروابط =====
        results = analyze_links(links)

        # ===== تحضير DataFrame للعرض =====
        df_data = []
        for r in results:
            df_data.append({
                "Link": r.get("link"),
                "Reasons": ", ".join(r.get("reasons", [])) if r.get("reasons") else "Safe"
            })
        df = pd.DataFrame(df_data)

        # ===== عرض النتائج =====
        st.subheader("Analysis Results")
        st.dataframe(df, use_container_width=True)

        # ===== Plotly Indicator =====
        suspicious_count = sum(1 for r in results if r.get("reasons"))
        total_links = len(results)
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=suspicious_count,
            number={'suffix': f'/{total_links} suspicious'},
            title={'text': "Suspicious Links Count"}
        ))
        st.plotly_chart(fig)

    except Exception as e:
        st.error(f"Error processing the file: {e}")
