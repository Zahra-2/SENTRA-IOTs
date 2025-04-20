import csv
from io import StringIO
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
import json

FILENAME = "vulnerability_report.pdf"


def generate_vulnerability_report(nmap_results, scan_results, dns_results, output_file, device_name, device_type, target, logo_path="app/logo.png"):
    # Initialize the PDF document with defined margins and page size
    doc = SimpleDocTemplate(output_file, pagesize=A4, leftMargin=0.75 * inch, rightMargin=0.75 * inch, topMargin=1 * inch, bottomMargin=1 * inch)
    elements = []

    # Define custom paragraph styles for title, headings, subheadings, and body text
    title_style = ParagraphStyle('TitleStyle', fontName='Helvetica-Bold', fontSize=22, spaceAfter=20, alignment=1)
    heading_style = ParagraphStyle('HeadingStyle', fontName='Helvetica-Bold', fontSize=18, spaceAfter=14)
    subheading_style = ParagraphStyle('SubheadingStyle', fontName='Helvetica-Bold', fontSize=14, spaceAfter=8)
    body_style = ParagraphStyle('BodyStyle', fontName='Helvetica', fontSize=12, spaceAfter=6)

    # Insert logo at the top (if exists)
    if logo_path:
        logo = Image(logo_path, width=4 * inch, height=3 * inch)
        elements.append(logo)

    # Add report title and device info
    elements.append(Paragraph("Network Vulnerability Scanner Report", title_style))
    elements.append(Spacer(1, 4))
    elements.append(Paragraph(f"Device Name: {device_name}", heading_style))
    elements.append(Paragraph(f"Device Type: {device_type}", heading_style))
    elements.append(Paragraph(f"URL/IP: {target}", heading_style))
    elements.append(Spacer(1, 2))

    # Summary table with risk levels
    elements.append(Paragraph("Summary", heading_style))
    summary_data = [
        ["Overall Risk Level:", scan_results.get('risk_level', 'No risk level available')],  # Update message if no risk level is found
        ["Critical:", scan_results.get('critical', 'No critical issues')],  # Update to provide more descriptive text
        ["High:", scan_results.get('high', 'No high risk issues')],
        ["Medium:", scan_results.get('medium', 'No medium risk issues')],
        ["Low:", scan_results.get('low', 'No low risk issues')],
        ["Info:", scan_results.get('info', 'No info level issues')],
        ["Scan Duration:", scan_results.get('duration', 'No duration available')]  # Provide fallback message
    ]

    # Create a table to display the summary
    summary_table = Table(summary_data, colWidths=[200, 200])
    summary_table.setStyle(TableStyle([
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 16))

    # Nmap results section - Display each finding with title, description, and recommendation
    for finding in nmap_results:
        elements.append(Spacer(1, 10))
        elements.append(Paragraph(finding['title'], subheading_style))
        elements.append(Paragraph(f"<b>Risk Description:</b> {finding['risk_description']}", body_style))
        elements.append(Paragraph(f"<b>Recommendation:</b> {finding['recommendation']}", body_style))
        elements.append(Spacer(1, 20))

    # Vulnerability findings section
    elements.append(Paragraph("Findings", heading_style))
    for finding in scan_results.get('findings', []):
        elements.append(Spacer(1, 10))
        elements.append(Paragraph(finding['title'], subheading_style))
        elements.append(Paragraph(f"<b>Risk Description:</b> {finding['risk_description']}", body_style))
        elements.append(Paragraph(f"<b>Recommendation:</b> {finding['recommendation']}", body_style))
        elements.append(Spacer(1, 20))

    # DNS Records table (if available) - Show DNS records or a message if not found
    elements.append(Paragraph("DNS Records", heading_style))
    if dns_results:
        dns_data = [[record_type, ', '.join(records) if isinstance(records, list) else records] for record_type, records in dns_results.items()]
        dns_table = Table(dns_data, colWidths=[200, 250])
        dns_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(dns_table)
    else:
        elements.append(Paragraph("No DNS records found, or unable to retrieve data.", body_style))  # Improved message

    elements.append(PageBreak())  # Add page break for a clean separation of sections

    # Generate and save the PDF
    doc.build(elements)
    print(f"Report saved to {output_file}")


# Map WSTG category codes to risk levels (now it's handles unknown categories)
def get_wstg_risk_level(wstg_code):
    risk_mapping = {
        "INPV": "Critical",
        "ATHN": "Critical",
        "ATHZ": "Critical",
        "SESS": "High",
        "CLNT": "Medium",
        "SRVV": "High",
        "CONF": "Medium",
        "BUSL": "High",
        "DVCS": "Medium",
        "INFO": "Low"
    }

    parts = wstg_code.split("-")
    if len(parts) < 3:
        return "Unknown"  # Return 'Unknown' for malformed WSTG codes
    category = parts[1]
    return risk_mapping.get(category, "Unknown")


# Determine overall risk level from counts (now includes fallback for missing data)
def determine_overall_risk(risks):
    if risks['critical'] > 0:
        return 'Critical'
    elif risks['high'] > 0:
        return 'High'
    elif risks['medium'] > 0:
        return 'Medium'
    elif risks['low'] > 0:
        return 'Low'
    elif risks['info'] > 0:
        return 'Info'
    else:
        return 'No risks found'  # Return message if no risks are found


# Main function to process results and generate report
def main(results: dict, device_name, device_type, target):
    risk_levels = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }

    nmap_results = []

    # Parse Nmap results
    for record in results.get("Nmap", []):
        name = record.get("name", "Unknown")
        protocol = record.get("protocol", "Unknown")
        port = record.get("port", "N/A")

        findings = {
            "title": f"Service: {name} | Protocol: {protocol} | Port: {port}",
            "risk_description": "Info",  # Default risk level
            "recommendation": "Update to the latest stable version with security patches available"
        }
        nmap_results.append(findings)

    dns_results = results.get("DNS", {})

    vulnerability_scan_results = []
    if "WebScan" in results:
        data = results["WebScan"]

        for vuln_name, issues in data.get("vulnerabilities", {}).items():
            if not issues:
                continue

            wstg_code = data["classifications"].get(vuln_name, {}).get("wstg", ["Unknown"])[0]
            recommendation = data["classifications"].get(vuln_name, {}).get("sol", "No recommendation available")

            findings = {
                "title": vuln_name,
                "risk_description": get_wstg_risk_level(wstg_code),
                "recommendation": recommendation
            }

            # Count risk level for summary
            level = findings["risk_description"].lower()
            if level in risk_levels:
                risk_levels[level] += 1

            vulnerability_scan_results.append(findings)

    # Create scan summary object
    scan_results = {
        "risk_level": determine_overall_risk(risk_levels),
        "critical": risk_levels["critical"] if risk_levels["critical"] > 0 else 'No critical issues',
        "high": risk_levels["high"] if risk_levels["high"] > 0 else 'No high risk issues',
        "medium": risk_levels["medium"] if risk_levels["medium"] > 0 else 'No medium risk issues',
        "low": risk_levels["low"] if risk_levels["low"] > 0 else 'No low risk issues',
        "info": risk_levels["info"] if risk_levels["info"] > 0 else 'No info level issues',
        "duration": results.get("duration", 'No duration available'),
        "findings": vulnerability_scan_results
    }

    # Call report generation function
    generate_vulnerability_report(nmap_results, scan_results, dns_results, FILENAME, device_name, device_type, target)

