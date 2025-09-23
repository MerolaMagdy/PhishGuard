import streamlit as st
import os
import plotly.graph_objects as go
import tempfile
from html import escape
import sys

# Add the parent directory to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import analysis functions directly (in-memory version)
from email import policy
from email.parser import BytesParser
import re
from html import unescape
from urllib.parse import urlparse
import tldextract

# ===== تحليل البريد الإلكتروني (الإصدار المحسن) =====
def parse_eml_from_bytes(file_bytes):
    """Parse EML content directly from bytes (no file system access)"""
    try:
        msg = BytesParser(policy=policy.default).parsebytes(file_bytes)
        
        subject = msg.get("subject", "No Subject") or "No Subject"
        from_addr = msg.get("from", "Unknown Sender") or "Unknown Sender"
        return_path = msg.get("return-path", from_addr) or from_addr

        body_text = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                
                # Skip attachments
                if "attachment" in content_disposition:
                    continue
                    
                if content_type == "text/plain":
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_text += payload.decode('utf-8', errors='ignore') + "\n"
                    except Exception as e:
                        try:
                            content = part.get_content()
                            if content:
                                body_text += str(content) + "\n"
                        except:
                            pass
                            
                elif content_type == "text/html":
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            html_content = payload.decode('utf-8', errors='ignore')
                            text_content = re.sub('<[^<]+?>', ' ', html_content)
                            body_text += unescape(text_content) + "\n"
                    except Exception as e:
                        pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    body_text = payload.decode('utf-8', errors='ignore')
                else:
                    body_text = msg.get_payload() or ""
            except Exception as e:
                body_text = msg.get_payload() or ""
                
        return subject, from_addr, return_path, body_text
        
    except Exception as e:
        return "Error", "Error", "Error", ""

def extract_links(text):
    """Extract links from text"""
    if not text:
        return []
    try:
        URL_REGEX = re.compile(r"""(?ix)\b((?:https?://|www\.)[^\s<>"'()]+)""")
        text = unescape(text)
        links = URL_REGEX.findall(text)
        cleaned = []
        for l in links:
            l = l.rstrip(".,;:!)\"'")
            if l.startswith("www."):
                l = "http://" + l
            cleaned.append(l)
        return list(dict.fromkeys(cleaned))
    except:
        return []

def analyze_links(links):
    """Analyze links for suspicious characteristics"""
    suspicious = []
    for link in links:
        try:
            parsed = urlparse(link)
            netloc = parsed.netloc.split(":")[0]
            ext = tldextract.extract(netloc)
            domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
            entry = {"link": link, "domain": domain, "reasons": []}

            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", netloc):
                entry["reasons"].append("Uses IP instead of domain")
            if not ext.suffix:
                entry["reasons"].append("No valid TLD")
            if "@" in link:
                entry["reasons"].append("URL contains @ (possible redirect/trick)")
            if re.search(r"-login|secure-login|update-account|verify-account", link, re.I):
                entry["reasons"].append("URL path looks like credential phishing (login/verify/update)")

            suspicious.append(entry)
        except:
            suspicious.append({"link": link, "reason": "analysis_error"})
    return suspicious

def analyze_keywords(body_text):
    """Analyze text for suspicious keywords"""
    findings = []
    if not body_text:
        return findings
    try:
        body_lower = body_text.lower()
        suspicious_keywords = ["urgent", "verify", "password", "account", "login",
                               "click here", "update", "confirm", "bank", "social security", "ssn"]
        for word in suspicious_keywords:
            idx = body_lower.find(word)
            if idx != -1:
                start = max(0, idx - 30)
                end = idx + len(word) + 30
                snippet = body_text[start:end].replace("\n", " ")
                findings.append({"keyword": word, "snippet": snippet.strip()})
    except:
        pass
    return findings

def analyze_headers(from_addr, return_path):
    """Analyze email headers"""
    findings = []
    try:
        if from_addr and return_path:
            from_str = ", ".join(from_addr) if isinstance(from_addr, (list, tuple)) else str(from_addr)
            rp = ", ".join(return_path) if isinstance(return_path, (list, tuple)) else str(return_path)
            if rp and from_str and rp.lower() not in from_str.lower():
                findings.append(f"Spoofed sender? From: {from_str} vs Return-Path: {rp}")
    except:
        pass
    return findings

def run_analysis(file_bytes):
    """Main analysis function that works in memory"""
    try:
        subject, from_addr, return_path, body_text = parse_eml_from_bytes(file_bytes)
        
        if not body_text or body_text == "":
            return None
            
        links = extract_links(body_text)
        link_findings = analyze_links(links)
        keyword_findings = analyze_keywords(body_text)
        header_findings = analyze_headers(from_addr, return_path)

        # ===== حساب Risk Score (High Risk version) =====
        score = 0
        if any("Spoofed sender" in f for f in header_findings):
            score += 30
        score += min(35, 5 * len(keyword_findings))
        
        for lf in link_findings:
            if lf.get("reasons"):
                if "Uses IP instead of domain" in lf.get("reasons", []):
                    score += 20
                if any("login" in r.lower() or "verify" in r.lower() for r in lf.get("reasons", [])):
                    score += 15
                score += 10  # Base score for any suspicious link

        if len(header_findings) > 1:
            score += 5
            
        score = min(100, score)

        overall_risk = "Low"
        if score >= 70:
            overall_risk = "High"
        elif score >= 40:
            overall_risk = "Medium"

        return {
            "subject": subject,
            "from": from_addr,
            "return_path": return_path,
            "header_findings": header_findings,
            "keyword_findings": keyword_findings,
            "link_findings": link_findings,
            "risk_score": score,
            "overall_risk": overall_risk,
        }
        
    except Exception as e:
        return None

# ===== حفظ التقرير كـ PDF =====
def save_report_pdf(report, pdf_path):
    try:
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet
        
        styles = getSampleStyleSheet()
        doc = SimpleDocTemplate(pdf_path)
        story = []

        story.append(Paragraph("PhishGuard - Phishing Email Analysis Report", styles['Title']))
        story.append(Spacer(1, 12))
        
        story.append(Paragraph(f"Subject: {report.get('subject', 'N/A')}", styles['Heading2']))
        story.append(Spacer(1, 6))
        story.append(Paragraph(f"From: {report.get('from', 'N/A')}", styles['Normal']))
        story.append(Paragraph(f"Return-Path: {report.get('return_path', 'N/A')}", styles['Normal']))
        story.append(Spacer(1, 12))
        
        risk_level = report.get('overall_risk', 'N/A')
        risk_score = report.get('risk_score', 0)
        story.append(
            Paragraph(
                f"Overall Risk: {risk_level} (Score: {risk_score})",
                styles['Heading2']
            )
        )
        story.append(Spacer(1, 12))

        story.append(Paragraph("Header Analysis Findings:", styles['Heading2']))
        header_findings = report.get("header_findings") or []
        if header_findings:
            for h in header_findings:
                story.append(Paragraph(f"- {h}", styles['Normal']))
        else:
            story.append(Paragraph("No significant header issues found.", styles['Normal']))
        story.append(Spacer(1, 12))

        story.append(Paragraph("Keyword Analysis Findings:", styles['Heading2']))
        keyword_findings = report.get("keyword_findings") or []
        if keyword_findings:
            for kf in keyword_findings:
                story.append(Paragraph(f"- {kf.get('keyword', 'N/A')}: {kf.get('snippet', '')}", styles['Normal']))
        else:
            story.append(Paragraph("No suspicious keywords found.", styles['Normal']))
        story.append(Spacer(1, 12))

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
                # معالجة الملف مباشرة من الذاكرة (بدون ملفات مؤقتة)
                file_bytes = uploaded_file.getvalue()
                report = run_analysis(file_bytes)
                
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
                            if keyword_findings:
                                for finding in keyword_findings:
                                    st.write(f"• **{finding['keyword']}**: {finding['snippet']}")
                            else:
                                st.info("No suspicious keywords found.")
                        
                        # نتائج تحليل الروابط
                        with st.expander("Link Analysis Results"):
                            link_findings = report.get("link_findings") or []
                            if link_findings:
                                for lf in link_findings:
                                    link = lf.get('link', '')
                                    reasons = lf.get('reasons', [])
                                    if reasons:
                                        st.warning(f"**Link:** {link}")
                                        st.write(f"**Reasons:** {', '.join(reasons)}")
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
