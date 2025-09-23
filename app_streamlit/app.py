import streamlit as st
import os
import plotly.graph_objects as go
from analysis import run_analysis
import analysis as analysis_module
analysis_module.VT_API_KEY = os.getenv("VT_API_KEY", None)
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from html import escape
import tempfile
import json

# ===== حفظ التقرير كـ PDF =====
def save_report_pdf(report, pdf_path):
    try:
        styles = getSampleStyleSheet()
        doc = SimpleDocTemplate(pdf_path)
        story = []

        # إضافة عنوان التقرير
        story.append(Paragraph("PhishGuard - Phishing Email Analysis Report", styles['Title']))
        story.append(Spacer(1, 12))
        
        # معلومات البريد الأساسية
        story.append(Paragraph(f"Subject: {report.get('subject', 'N/A')}", styles['Heading2']))
        story.append(Spacer(1, 6))
        story.append(Paragraph(f"From: {report.get('from', 'N/A')}", styles['Normal']))
        story.append(Paragraph(f"Return-Path: {report.get('return_path', 'N/A')}", styles['Normal']))
        story.append(Spacer(1, 12))
        
        # تقييم المخاطر
        risk_level = report.get('overall_risk', 'N/A')
        risk_score = report.get('risk_score', 0)
        story.append(
            Paragraph(
                f"Overall Risk: {risk_level} (Score: {risk_score})",
                styles['Heading2']
            )
        )
        story.append(Spacer(1, 12))

        # نتائج تحليل الرأس
        story.append(Paragraph("Header Analysis Findings:", styles['Heading2']))
        header_findings = report.get("header_findings") or []
        if header_findings:
            for h in header_findings:
                story.append(Paragraph(f"- {h}", styles['Normal']))
        else:
            story.append(Paragraph("No significant header issues found.", styles['Normal']))
        story.append(Spacer(1, 12))

        # نتائج الكلمات المفتاحية
        story.append(Paragraph("Keyword Analysis Findings:", styles['Heading2']))
        keyword_findings = report.get("keyword_findings") or []
        if keyword_findings and isinstance(keyword_findings, list) and len(keyword_findings) > 0:
            keywords_text = ", ".join([str(k) for k in keyword_findings if k is not None])
            story.append(Paragraph(keywords_text, styles['Normal']))
        else:
            story.append(Paragraph("No suspicious keywords found.", styles['Normal']))
        story.append(Spacer(1, 12))

        # نتائج تحليل الروابط
        story.append(Paragraph("Link Analysis Findings:", styles['Heading2']))
        link_findings = report.get("link_findings") or []
        if link_findings:
            for lf in link_findings:
                link = lf.get('link', '')
                reasons = lf.get('reasons', [])
                reasons_text = ", ".join(reasons) if reasons else "No specific reason"
                story.append(Paragraph(f"- {link}", styles['Normal']))
                story.append(Paragraph(f"  Reasons: {reasons_text}", styles['Normal']))
        else:
            story.append(Paragraph("No suspicious links found.", styles['Normal']))

        # بناء التقرير
        doc.build(story)
        return True
    except Exception as e:
        st.error(f"Error generating PDF: {str(e)}")
        return False

# ===== رسم مقياس المخاطر =====
def show_gauge(score):
    try:
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=score,
            number={'suffix': "%"},
            domain={'x': [0, 1], 'y': [0, 1]},
            gauge={
                'axis': {'range': [0, 100], 'tickwidth': 1},
                'bar': {'color': "darkblue"},
                'steps': [
                    {'range': [0, 30], 'color': "lightgreen"},
                    {'range': [30, 70], 'color': "yellow"},
                    {'range': [70, 100], 'color': "red"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': score
                }
            },
            title={'text': "Risk Score", 'font': {'size': 24}}
        ))
        fig.update_layout(height=300, margin=dict(l=20, r=20, t=50, b=10))
        st.plotly_chart(fig, use_container_width=True)
    except Exception as e:
        st.error(f"Error creating gauge: {str(e)}")

# ===== واجهة Streamlit =====
def main():
    st.set_page_config(page_title="PhishGuard", layout="wide", page_icon="🛡️")
    
    # ترويسة التطبيق
    st.markdown("""
        <div style='background-color:#0e1117; padding:20px; border-radius:10px; margin-bottom:20px;'>
            <h1 style='color:#00e5ff; text-align:center;'>PhishGuard — Phishing Email Analyzer</h1>
            <p style='color:#ffffff; text-align:center;'>Upload a .eml file to analyze email content and generate a PDF report</p>
        </div>
    """, unsafe_allow_html=True)
    
    # قسم رفع الملف
    uploaded_file = st.file_uploader("Choose a .eml file", type=["eml"], help="Select an email file in .eml format to analyze")
    
     if uploaded_file is not None:
        try:
            with st.spinner("Analyzing email content..."):
                # حفظ الملف مؤقتاً
                with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp_file:
                    tmp_file.write(uploaded_file.getvalue())
                    temp_path = tmp_file.name
                
                # تحليل الملف
                report = run_analysis(temp_path)
                
                # تنظيف الملف المؤقت
                try:
                    os.unlink(temp_path)
                except:
                    pass
                
                if report:
                    # إنشاء التقرير PDF
                    pdf_path = "phishguard_report.pdf"
                    pdf_success = save_report_pdf(report, pdf_path)
                    
                    # عرض النتائج
                    st.success("✅ Analysis completed successfully!")
                    
                    # تقسيم الصفحة إلى أعمدة
                    col1, col2 = st.columns([1, 2])
                    
                    with col1:
                        st.subheader("Email Overview")
                        show_gauge(report.get('risk_score', 0))
                        
                        st.info(f"**Risk Level:** {report.get('overall_risk', 'N/A')}")
                        
                        st.write("**Subject**")
                        st.code(report.get("subject", "N/A"), language=None)
                        
                        st.write("**From**")
                        st.code(report.get("from", "N/A"), language=None)
                        
                        st.write("**Return Path**")
                        st.code(report.get("return_path", "N/A"), language=None)
                    
                    with col2:
                        st.subheader("Detailed Analysis")
                        
                        # نتائج تحليل الرأس
                        with st.expander("Header Analysis Results"):
                            header_findings = report.get("header_findings") or []
                            if header_findings:
                                for finding in header_findings:
                                    st.write(f"• {finding}")
                            else:
                                st.info("No header issues detected.")
                        
                        # نتائج الكلمات المفتاحية
                        with st.expander("Keyword Analysis Results"):
                            keyword_findings = report.get("keyword_findings") or []
                            if keyword_findings and isinstance(keyword_findings, list) and len(keyword_findings) > 0:
                                keywords_text = ", ".join([str(k) for k in keyword_findings if k is not None])
                                st.write(keywords_text)
                            else:
                                st.info("No suspicious keywords found.")
                        
                        # نتائج تحليل الروابط
                        with st.expander("Link Analysis Results"):
                            link_findings = report.get("link_findings") or []
                            if link_findings:
                                for lf in link_findings:
                                    link = lf.get('link', '')
                                    reasons = lf.get('reasons', [])
                                    reasons_text = ", ".join(reasons) if reasons else "No specific reason"
                                    st.warning(f"**Link:** {link}")
                                    st.write(f"**Reasons:** {reasons_text}")
                                    st.write("---")
                            else:
                                st.info("No suspicious links found.")
                    
                    # زر تحميل التقرير
                    if pdf_success:
                        with open(pdf_path, "rb") as f:
                            st.download_button(
                                label="📄 Download PDF Report",
                                data=f,
                                file_name=pdf_path,
                                mime="application/pdf",
                                use_container_width=True
                            )
                        try:
                            os.unlink(pdf_path)
                        except:
                            pass
                else:
                    st.error("Failed to analyze the email. Please check the file format and try again.")
        
        except Exception as e:
            st.error(f"An error occurred during analysis: {str(e)}")
    else:
        # تعليمات الاستخدام عندما لا يكون هناك ملف مرفوع
        st.info("👆 Please upload a .eml file to begin analysis.")
        
        with st.expander("How to get a .eml file?"):
            st.markdown("""
            **From Gmail:**
            1. Open the email you want to analyze
            2. Click on the three dots (more options) in the top right
            3. Select "Download message"
            
            **From Outlook:**
            1. Right-click on the email in your inbox
            2. Select "Save As"
            3. Choose "Outlook Message Format (.eml)" as the file type
            
            **From Thunderbird:**
            1. Right-click on the email
            2. Select "Save As"
            3. Choose "File" and save as .eml format
            """)

if __name__ == "__main__":
    main()
