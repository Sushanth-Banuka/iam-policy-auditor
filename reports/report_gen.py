import csv
import io

try:
    from fpdf import FPDF
    FPDF_AVAILABLE = True
except ImportError:
    FPDF_AVAILABLE = False

def generate_pdf(results, scan_time):
    if not FPDF_AVAILABLE:
        return b"%PDF-1.4\n%Fallback PDF. Please install fpdf2.\n"

    pdf = FPDF(orientation="P", unit="mm", format="A4")
    pdf.add_page()
    
    # Dark header bar
    pdf.set_fill_color(22, 27, 34)
    pdf.rect(0, 0, 210, 30, style="F")
    
    pdf.set_font("Helvetica", style="B", size=16)
    pdf.set_text_color(255, 255, 255)
    pdf.set_xy(10, 10)
    pdf.cell(0, 10, "IAM Policy Auditor - Audit Report", align="L")
    
    pdf.set_font("Helvetica", size=10)
    pdf.set_xy(10, 18)
    pdf.cell(0, 10, f"Scan Timestamp: {scan_time}", align="L")
    
    # Reset formatting for body
    pdf.set_y(40)
    pdf.set_text_color(0, 0, 0)
    
    summary = results.get("summary", {})
    score = summary.get("security_score", 0)
    grade = summary.get("score_grade", ("N/A", "#000000", "Unknown"))
    
    pdf.set_font("Helvetica", style="B", size=14)
    pdf.cell(0, 10, "Executive Summary", ln=True)
    pdf.set_font("Helvetica", size=11)
    
    pdf.cell(0, 8, f"Security Score: {score}/100 - Grade: {grade[0]} ({grade[2]})", ln=True)
    pdf.cell(0, 8, f"Total Findings: {summary.get('total', 0)}", ln=True)
    pdf.cell(0, 8, f"Critical: {summary.get('critical', 0)} | High: {summary.get('high', 0)} | Medium: {summary.get('medium', 0)} | Low: {summary.get('low', 0)}", ln=True)
    pdf.ln(5)
    
    pdf.set_font("Helvetica", style="B", size=14)
    pdf.cell(0, 10, "Findings Detail", ln=True)
    
    SEV_WEIGHT = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    findings = sorted(results.get("findings", []), key=lambda x: SEV_WEIGHT.get(x.get("severity", "Low"), 0), reverse=True)
    
    for f in findings:
        if pdf.get_y() > 250:
            pdf.add_page()
            
        sev = f.get("severity", "Unknown")
        f_type = f.get("type", "Unknown")
        
        pdf.set_font("Helvetica", style="B", size=11)
        if sev == "Critical":
            pdf.set_text_color(220, 53, 69)
        elif sev == "High":
            pdf.set_text_color(253, 126, 20)
        elif sev == "Medium":
            pdf.set_text_color(255, 193, 7)
        else:
            pdf.set_text_color(40, 167, 69)
            
        pdf.cell(20, 8, f"[{sev}]")
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 8, f"{f_type}", ln=True)
        
        pdf.set_font("Helvetica", size=10)
        
        def clean_text(text):
            return str(text).encode('latin-1', 'replace').decode('latin-1')

        pdf.cell(0, 6, clean_text(f"Principal: {f.get('principal', 'Unknown')} (Role: {f.get('role', '')})"), ln=True)
        pdf.cell(0, 6, clean_text(f"Scope: {f.get('scope', '')}"), ln=True)
        pdf.multi_cell(0, 6, clean_text(f"Description: {f.get('description', '')}"))
        pdf.set_x(10)
        pdf.multi_cell(0, 6, clean_text(f"Recommendation: {f.get('recommendation', '')}"))
        pdf.set_x(10)
        pdf.multi_cell(0, 6, clean_text(f"MITRE: {f.get('mitre_id', '')} - {f.get('mitre_name', '')} ({f.get('mitre_tactic', '')})"))
        
        pdf.set_font("Courier", size=9)
        pdf.set_fill_color(240, 240, 240)
        cli_text = clean_text(f.get('remediation_cli', ''))
        pdf.set_x(10)
        pdf.multi_cell(0, 5, cli_text, fill=True)
        pdf.ln(3)

    pdf.set_y(-15)
    pdf.set_font("Helvetica", size=8)
    pdf.set_text_color(128, 128, 128)
    pdf.cell(0, 10, "IAM Policy Auditor | Built by Sushanth Banuka | github.com/Sushanth-Banuka", align="C")
    
    res = pdf.output()
    if isinstance(res, str):
        return res.encode('latin-1')
    return bytes(res)

def generate_csv(findings):
    output = io.StringIO()
    if not findings:
        return ""
    
    keys = findings[0].keys()
    writer = csv.DictWriter(output, fieldnames=keys)
    writer.writeheader()
    writer.writerows(findings)
    return output.getvalue()
