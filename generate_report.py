import json
from analysis import run_analysis
import mailparser

from test_mailparser import analyze_headers   # الدوال اللي عملناها قبل كده
from test_mailparser import analyze_keywords # لو حطيناها في ملف مستقل
from test_mailparser import analyze_links       # لو عندنا فحص روابط


def generate_report(file_path):
    report = run_analysis(file_path)
    with open("report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)
    print("[+] JSON report generated: report.json")
    print(json.dumps(report, indent=4, ensure_ascii=False))

if __name__ == "__main__":
    generate_report("sample.eml")

def generate_report(file_path):
    mail = mailparser.parse_from_file(file_path)

    header_findings = test_mailparser(mail)
    keyword_findings = analyze_keywords(mail)
    link_findings = analyze_links(mail)

    
    risk_score = 0
    if any("Spoofed sender" in f for f in header_findings):
        risk_score += 40
    if keyword_findings:
        risk_score += 20
    if link_findings:
        risk_score += 20
    if len(header_findings) > 1:  # مثلا وجود Received chain طويل
        risk_score += 10

    overall_risk = "Low"
    if risk_score >= 70:
        overall_risk = "High"
    elif risk_score >= 40:
        overall_risk = "Medium"

    report = {
        "subject": mail.subject,
        "from": mail.from_,
        "return_path": mail.return_path,
        "header_findings": header_findings,
        "keyword_findings": keyword_findings,
        "link_findings": link_findings,
        "risk_score": risk_score,
        "overall_risk": overall_risk
    }

    
    with open("report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)

    print("[+] JSON report generated: report.json")
    print(json.dumps(report, indent=4, ensure_ascii=False))

if __name__ == "__main__":
    generate_report("sample.eml")
