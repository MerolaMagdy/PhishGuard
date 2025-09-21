import streamlit as st
from analysis import run_analysis   # يستدعي ملف التحليل

st.title("PhishGuard — Phishing Email Analyzer")

uploaded_file = st.file_uploader("Upload a .eml file", type="eml")
if uploaded_file is not None:
    # نحفظ الملف المرفوع مؤقتًا
    with open("temp.eml", "wb") as f:
        f.write(uploaded_file.read())

    # نحلل الملف باستخدام الدالة من analysis.py
    report = run_analysis("temp.eml")

    # نعرض النتيجة
    st.json(report)
