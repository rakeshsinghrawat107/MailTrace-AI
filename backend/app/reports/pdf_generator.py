"""
MailTrace.AI - Courtroom-Admissible Digital Forensic Dossier PDF Generator
Section 63 Bharatiya Sakshya Adhiniyam (BSA) 2023 & ISO/IEC 27037 Forensic Reporting Engine
"""
import io
from datetime import datetime, timezone
from typing import Dict, Any, List
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

class ForensicPDFGenerator:
    """Generates courtroom-admissible PDF forensic reports."""

    def generate(self, analysis_result: Dict[str, Any], cert_data: Dict[str, Any]) -> bytes:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )
        
        styles = getSampleStyleSheet()
        
        # Custom Forensic Styles
        title_style = ParagraphStyle(
            'ForensicTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=18,
            leading=22,
            textColor=colors.HexColor('#0f172a'),
            spaceAfter=4
        )
        subtitle_style = ParagraphStyle(
            'ForensicSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=12,
            textColor=colors.HexColor('#475569'),
            spaceAfter=12
        )
        h2_style = ParagraphStyle(
            'ForensicH2',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=12,
            leading=15,
            textColor=colors.HexColor('#1e293b'),
            spaceBefore=10,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            'ForensicBody',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor('#334155')
        )
        code_style = ParagraphStyle(
            'ForensicCode',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=7.5,
            leading=9.5,
            textColor=colors.HexColor('#0f172a')
        )

        elements = []

        # 1. Header Banner
        elements.append(Paragraph("<b>MAILTRACE.AI — ELECTRONIC FORENSIC INTELLIGENCE REPORT</b>", title_style))
        elements.append(Paragraph(
            f"Statutory Authority: <b>Section 63, Bharatiya Sakshya Adhiniyam (BSA), 2023</b> | FIPS 140-3 Cryptographic Integrity<br/>"
            f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | Case ID: <b>{analysis_result.get('case_id', 'UNKNOWN')}</b>",
            subtitle_style
        ))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284c7'), spaceAfter=10))

        # 2. Case & Evidence Digest Table
        fraud_score = analysis_result.get('fraud_score', 0.0)
        risk_tier = analysis_result.get('risk_tier', 'UNKNOWN')
        score_color = '#dc2626' if fraud_score >= 75 else ('#ea580c' if fraud_score >= 50 else ('#d97706' if fraud_score >= 25 else '#16a34a'))

        digest_data = [
            [Paragraph("<b>Target File Name:</b>", body_style), Paragraph(str(analysis_result.get('filename', 'email.eml')), body_style),
             Paragraph("<b>Fraud Score:</b>", body_style), Paragraph(f"<font color='{score_color}'><b>{fraud_score:.1f} / 100</b></font>", body_style)],
            [Paragraph("<b>Pre-Parse SHA-256:</b>", body_style), Paragraph(f"<font name='Courier' size='7'>{analysis_result.get('evidence_sha256', 'N/A')}</font>", body_style),
             Paragraph("<b>Risk Tier:</b>", body_style), Paragraph(f"<b>{risk_tier}</b>", body_style)],
            [Paragraph("<b>From:</b>", body_style), Paragraph(str(analysis_result.get('headers', {}).get('from', 'N/A'))[:50], body_style),
             Paragraph("<b>Domain Alignment:</b>", body_style), Paragraph("ALIGNED" if analysis_result.get('protocols', {}).get('domain_aligned') else "<font color='#dc2626'><b>MISMATCH</b></font>", body_style)],
            [Paragraph("<b>Subject:</b>", body_style), Paragraph(str(analysis_result.get('headers', {}).get('subject', 'N/A'))[:50], body_style),
             Paragraph("<b>Total MTA Hops:</b>", body_style), Paragraph(str(len(analysis_result.get('hops', []))), body_style)]
        ]
        digest_table = Table(digest_data, colWidths=[110, 240, 90, 100])
        digest_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('TOPPADDING', (0,0), (-1,-1), 4),
        ]))
        elements.append(digest_table)
        elements.append(Spacer(1, 10))

        # 3. Chronological MTA Hop Provenance Table
        elements.append(Paragraph("<b>MTA Relay Provenance & Inter-Hop Latency Analysis</b>", h2_style))
        hop_rows = [["Hop", "Relay IP", "Country", "ASN / Organization", "Latency", "Infrastructure"]]
        for h in analysis_result.get('hops', []):
            infra = "TOR EXIT" if h.get('is_tor_exit') else ("LAN" if h.get('is_private_ip') else "COMMERCIAL")
            hop_rows.append([
                str(h.get('hop_sequence', 1)),
                h.get('relay_ip', '127.0.0.1'),
                f"{h.get('city', '')}, {h.get('country_code', '')}",
                str(h.get('asn', ''))[:30],
                f"{h.get('latency_seconds', 0.0):.1f}s",
                infra
            ])
        
        hop_table = Table(hop_rows, colWidths=[28, 85, 110, 180, 50, 87])
        hop_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 7.5),
            ('BOTTOMPADDING', (0,0), (-1,0), 4),
            ('TOPPADDING', (0,0), (-1,0), 4),
            ('FONTNAME', (0,1), (-1,-1), 'Helvetica'),
            ('FONTSIZE', (0,1), (-1,-1), 7),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        elements.append(hop_table)
        elements.append(Spacer(1, 10))

        # 4. Evidence-Grounded Forensic Findings
        elements.append(Paragraph("<b>Identified Adversarial Threat Indicators & MITRE ATT&CK Mapping</b>", h2_style))
        findings = analysis_result.get('findings', [])
        if findings:
            find_rows = [["Code", "Category", "Severity", "Evidence Finding", "MITRE ATT&CK"]]
            for f in findings:
                find_rows.append([
                    f.get('code', '[F-000]'),
                    f.get('category', 'GENERAL'),
                    f.get('severity', 'MEDIUM'),
                    Paragraph(f.get('finding', ''), body_style),
                    f.get('mitre', 'T1566')
                ])
            find_table = Table(find_rows, colWidths=[40, 110, 55, 235, 100])
            find_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,0), 7.5),
                ('BOTTOMPADDING', (0,0), (-1,-1), 3),
                ('TOPPADDING', (0,0), (-1,-1), 3),
                ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ]))
            elements.append(find_table)
        else:
            elements.append(Paragraph("No critical adversarial indicators detected. Electronic message exhibits standard cryptographic alignment.", body_style))
        
        elements.append(Spacer(1, 10))

        # 5. Section 63 BSA 2023 Statutory Certificate Extract
        elements.append(Paragraph("<b>Statutory Certificate of Electronic Record Admissibility (Section 63 BSA 2023)</b>", h2_style))
        cert_body = cert_data.get('certificate_text', '')
        # Format lines safely
        cert_paragraphs = [Paragraph(line.replace(' ', '&nbsp;'), code_style) for line in cert_body.strip().split('\n')[:25]]
        elements.extend(cert_paragraphs)

        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()

pdf_generator = ForensicPDFGenerator()
