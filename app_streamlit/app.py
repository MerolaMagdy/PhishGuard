import streamlit as st
import tempfile
import os
import sys
from email import policy
from email.parser import BytesParser
import re
from html import unescape
from urllib.parse import urlparse
import tldextract

# Add the parent directory to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

st.set_page_config(page_title="PhishGuard", layout="wide", page_icon="🛡️")

# ترويسة التطبيق
st.markdown("""
    <div style='background-color:#0e1117; padding:20px; border-radius:10px; margin-bottom:20px;'>
        <h1 style='color:#00e5ff; text-align:center;'>PhishGuard — Phishing Email Analyzer</h1>
        <p style='color:#ffffff; text-align:center;'>Upload a .eml file to analyze email content and generate a PDF report</p>
    </div>
""", unsafe_allow_html=True)

# Simplified analysis functions that work in memory
def parse_eml_from_bytes(file_bytes):
    """Parse EML content directly from bytes (no file system access)"""
    try:
        msg = BytesParser(policy=policy.default).parsebytes(file_bytes)
        
        subject = msg.get("subject", "No Subject") or "No Subject"
        from_addr = msg.get("from", "Unknown Sender") or "Unknown Sender"
        return_path = msg.get("return-path", from_addr) or from_addr

        body_text = ""
        
        # Debug: Show what parts we found
        st.write(f"📧 Email parts: Multipart={msg.is_multipart()}")
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                
                # Skip attachments
                if "attachment" in content_disposition:
                    continue
                    
                if content_type == "text/plain":
                    try:
                        # Get payload and decode properly
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_text += payload.decode('utf-8', errors='ignore') + "\n"
                    except Exception as e:
                        st.write(f"❌ Error reading text/plain: {e}")
                        try:
                            # Fallback: get content without decoding
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
                            # Simple HTML to text conversion
                            text_content = re.sub('<[^<]+?>', ' ', html_content)
                            body_text += unescape(text_content) + "\n"
                    except Exception as e:
                        st.write(f"❌ Error reading text/html: {e}")
        else:
            # Not multipart - single part email
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    body_text = payload.decode('utf-8', errors='ignore')
                else:
                    body_text = msg.get_payload() or ""
            except Exception as e:
                st.write(f"❌ Error reading single part: {e}")
                body_text = msg.get_payload() or ""
        
        # Debug information
        st.write(f"📝 Subject: {subject}")
        st.write(f"👤 From: {from_addr}")
        st.write(f"📨 Body length: {len(body_text)} characters")
        
        if len(body_text) > 500:
            st.write(f"📄 Body preview: {body_text[:500]}...")
        else:
            st.write(f"📄 Body: {body_text}")
                
        return subject, from_addr, return_path, body_text
        
    except Exception as e:
        st.error(f"❌ Error parsing EML: {e}")
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

            # Basic link analysis
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", netloc):
                entry["reasons"].append("Uses IP instead of domain")
            if not ext.suffix:
                entry["reasons"].append("No valid TLD")
            if "@" in link:
                entry["reasons"].append("URL contains @")
            if re.search(r"-login|secure-login|update-account|verify-account", link, re.I):
                entry["reasons"].append("Suspicious URL path")

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
            if word in body_lower:
                findings.append({"keyword": word, "snippet": f"Found '{word}' in email"})
    except:
        pass
    return findings

def analyze_headers(from_addr, return_path):
    """Analyze email headers"""
    findings = []
    try:
        if from_addr and return_path and from_addr != return_path:
            findings.append(f"Sender mismatch: From: {from_addr} vs Return-Path: {return_path}")
    except:
        pass
    return findings

def run_analysis(file_bytes):
    """Main analysis function that works in memory"""
    try:
        subject, from_addr, return_path, body_text = parse_eml_from_bytes(file_bytes)
        
        if not body_text:
            return None
            
        links = extract_links(body_text)
        link_findings = analyze_links(links)
        keyword_findings = analyze_keywords(body_text)
        header_findings = analyze_headers(from_addr, return_path)

        # Calculate risk score
        score = 0
        if header_findings:
            score += 30
        score += min(35, 5 * len(keyword_findings))
        
        for lf in link_findings:
            if lf.get("reasons"):
                score += 20

        score = min(100, score)
        
        overall_risk = "High" if score >= 70 else "Medium" if score >= 40 else "Low"

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
        st.error(f"Analysis error: {e}")
        return None

# Simplified UI functions
def show_gauge(score):
    """Simple gauge display"""
    st.metric("Risk Score", f"{score}/100")
    
def save_report_pdf(report, filename):
    """Simple PDF report (placeholder)"""
    # For now, just return success - you can implement PDF generation later
    return True

def main():
    uploaded_file = st.file_uploader("Choose a .eml file", type=["eml"], 
                                   help="Select an email file in .eml format to analyze")
    
    if uploaded_file is not None:
        # Debug: Show file information
        st.write(f"📁 File uploaded: {uploaded_file.name}")
        st.write(f"📊 File size: {len(uploaded_file.getvalue())} bytes")
        
        # Show first 200 characters of the file content
        file_content_preview = uploaded_file.getvalue()[:200]
        st.write(f"🔍 File preview: {file_content_preview}")
        
        # Reset file pointer for processing
        uploaded_file.seek(0)
        
        try:
            with st.spinner("Analyzing email content..."):
                # Process the file directly from memory
                file_bytes = uploaded_file.getvalue()
                report = run_analysis(file_bytes)

if __name__ == "__main__":
    main()
