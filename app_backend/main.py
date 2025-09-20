from fastapi import FastAPI, UploadFile, File
from fastapi.responses import JSONResponse, FileResponse
import analysis as analysis_module
analysis_module.VT_API_KEY = os.getenv("VT_API_KEY", None)
import os
from analysis import run_analysis
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

app = FastAPI()
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

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
    for lf in report.get('link_findings') or []:
        link = lf.get('link', '')
        reasons = lf.get('reasons', [])
        reasons_text = ", ".join(reasons) if reasons else "No specific reason"
        story.append(Paragraph(f"{link} — {reasons_text}", styles['Normal']))
    
    doc.build(story)

@app.post("/analyze")
async def analyze_email(file: UploadFile = File(...)):
    try:
        file_path = os.path.join(UPLOAD_DIR, file.filename)
        with open(file_path, "wb") as f:
            f.write(await file.read())

        report = run_analysis(file_path)
        pdf_path = os.path.join(UPLOAD_DIR, file.filename + ".pdf")
        save_report_pdf(report, pdf_path)

        return JSONResponse(content={"report": report, "pdf": pdf_path})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/download-pdf")
def download_pdf(path: str):
    return FileResponse(path, media_type='application/pdf', filename=os.path.basename(path))
