from fpdf import FPDF
from datetime import datetime
def _safe(text: str) -> str:
    """Remove any character outside latin-1 so fpdf2 never crashes."""
    return ''.join(c if ord(c) < 256 else '-' for c in str(text))

class SentinelReport(FPDF):
    """Custom FPDF class with Sentinel header and footer on every page."""

    def header(self):
        # Blue header bar
        self.set_fill_color(23, 43, 77)        # Dark navy
        self.rect(0, 0, 210, 18, 'F')

        # Title in header
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 11)
        self.set_xy(10, 5)
        self.cell(0, 8, "PROJECT SENTINEL  -  Executive Security Report", ln=False)

        # Date in header right side
        self.set_font("Helvetica", "", 8)
        self.set_xy(140, 6)
        self.cell(60, 6, datetime.now().strftime("%B %d, %Y"), align="R")

        self.set_text_color(0, 0, 0)
        self.ln(14)

    def footer(self):
        self.set_y(-12)
        self.set_fill_color(23, 43, 77)
        self.rect(0, 285, 210, 15, 'F')
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "I", 8)
        self.set_xy(10, 287)
        self.cell(0, 6,
                  f"CONFIDENTIAL  |  Project Sentinel CNAPP  |  Page {self.page_no()}",
                  align="C")


# -----------------------------------------------------------------------------
# Colour palette
# -----------------------------------------------------------------------------
RED    = (192,  0,  0)
ORANGE = (255, 102,  0)
YELLOW = (204, 153,  0)
GREEN  = ( 0,  153,  51)
NAVY   = ( 23,  43,  77)
LGRAY  = (245, 245, 245)
DGRAY  = ( 80,  80,  80)
WHITE  = (255, 255, 255)


def _severity_color(level: str):
    return {
        "CRITICAL": RED,
        "HIGH":     ORANGE,
        "MEDIUM":   YELLOW,
        "LOW":      GREEN,
    }.get(level.upper(), DGRAY)


def _score_color(score: int):
    if score >= 80: return GREEN
    if score >= 60: return YELLOW
    return RED


def _section_header(pdf: FPDF, title: str):
    """Draws a full-width navy section header."""
    pdf.set_fill_color(*NAVY)
    pdf.set_text_color(*WHITE)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 8, f"  {title}", ln=True, fill=True)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(2)


def _kv_row(pdf: FPDF, label: str, value: str, shade: bool = False):
    """Draws a shaded key-value row."""
    if shade:
        pdf.set_fill_color(*LGRAY)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(60, 6, f"  {label}", fill=True)
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0,  6, str(value), fill=True, ln=True)
    else:
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(60, 6, f"  {label}")
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0,  6, str(value), ln=True)


def generate_executive_report(data: dict) -> bytes:
    """
    Generates the PDF and returns it as bytes for Streamlit's download_button.

    Expected keys in `data`:
        compliance_score    int         e.g. 43
        passed_checks       int
        failed_checks       int
        stale_keys          int
        missing_mfa         int
        tenant_id           str
        scan_date           str         e.g. "2025-07-05"
        incidents           list[dict]  from sentinel-tenant-registry
        gd_findings         list[dict]  from sentinel-guardduty-findings
        ec2_threats         list[dict]  from run_ec2_security_scan()
        vpc_threats         list[dict]  from run_vpc_network_scan()
    """

    pdf = SentinelReport()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()
    pdf.set_margins(10, 22, 10)

    score       = int(data.get('compliance_score', 0))
    passed      = int(data.get('passed_checks',   0))
    failed      = int(data.get('failed_checks',   0))
    stale_keys  = int(data.get('stale_keys',      0))
    missing_mfa = int(data.get('missing_mfa',     0))
    tenant_id   = data.get('tenant_id', 'admin')
    scan_date   = data.get('scan_date',  datetime.now().strftime('%Y-%m-%d'))
    incidents   = data.get('incidents',   [])
    gd_findings = data.get('gd_findings', [])
    ec2_threats = data.get('ec2_threats', [])
    vpc_threats = data.get('vpc_threats', [])

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    # -- COVER BLOCK -----------------------------------------------------------
    pdf.set_fill_color(*LGRAY)
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(*NAVY)
    pdf.cell(0, 14, "SECURITY POSTURE EXECUTIVE REPORT", ln=True, align="C")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*DGRAY)
    pdf.cell(0, 6, f"Tenant: {_safe(tenant_id)}   |   Scan Date: {scan_date}   |   Generated: {generated_at}",
             ln=True, align="C")
    pdf.ln(4)

    # -- COMPLIANCE SCORE BOX -------------------------------------------------
    sc, sg, sr = _score_color(score)
    pdf.set_fill_color(sc, sg, sr)
    pdf.set_text_color(*WHITE)
    pdf.set_font("Helvetica", "B", 36)
    pdf.cell(0, 20, f"{score}%", ln=True, align="C", fill=True)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "CIS BENCHMARK COMPLIANCE SCORE", ln=True, align="C", fill=True)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(5)

    # -- QUICK STATS ROW -------------------------------------------------------
    _section_header(pdf, "1. QUICK STATS")

    col_w = 47
    stats = [
        ("Passed Checks",     str(passed),      GREEN),
        ("Failed Checks",     str(failed),      RED if failed > 0 else GREEN),
        ("Stale Access Keys", str(stale_keys),  RED if stale_keys > 0 else GREEN),
        ("Users Without MFA", str(missing_mfa), RED if missing_mfa > 0 else GREEN),
    ]

    for label, value, color in stats:
        x = pdf.get_x()
        y = pdf.get_y()
        pdf.set_fill_color(*color)
        pdf.rect(x, y, col_w - 2, 14, 'F')
        pdf.set_text_color(*WHITE)
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_xy(x, y + 1)
        pdf.cell(col_w - 2, 7, value, align="C")
        pdf.set_font("Helvetica", "", 7)
        pdf.set_xy(x, y + 7)
        pdf.cell(col_w - 2, 6, label, align="C")
        pdf.set_xy(x + col_w, y)

    pdf.set_text_color(0, 0, 0)
    pdf.ln(18)

    # -- GUARDDUTY FINDINGS ----------------------------------------------------
    pdf.ln(2)
    _section_header(pdf, "2. GUARDDUTY THREAT INTELLIGENCE")

    if not gd_findings:
        pdf.set_font("Helvetica", "I", 9)
        pdf.cell(0, 6, "  No GuardDuty findings recorded.", ln=True)
    else:
        high   = sum(1 for f in gd_findings if f.get('severity_label') == 'HIGH')
        medium = sum(1 for f in gd_findings if f.get('severity_label') == 'MEDIUM')
        low    = sum(1 for f in gd_findings if f.get('severity_label') == 'LOW')
        active = sum(1 for f in gd_findings if f.get('status') == 'ACTIVE')

        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 5,
                 f"  Total: {len(gd_findings)}  |  "
                 f"HIGH: {high}  |  MEDIUM: {medium}  |  LOW: {low}  |  Active: {active}",
                 ln=True)
        pdf.ln(2)

        # Table header
        pdf.set_fill_color(*NAVY)
        pdf.set_text_color(*WHITE)
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(12,  6, "  Sev",   fill=True)
        pdf.cell(70,  6, "Finding Type",  fill=True)
        pdf.cell(45,  6, "Resource",      fill=True)
        pdf.cell(30,  6, "MITRE Tactic",  fill=True)
        pdf.cell(33,  6, "Status",        fill=True, ln=True)
        pdf.set_text_color(0, 0, 0)

        shade = False
        for f in gd_findings[:20]:   # cap at 20 rows
            sev   = f.get('severity_label', 'LOW')
            sc, sg, sr = _severity_color(sev)
            pdf.set_fill_color(sc, sg, sr)
            pdf.set_text_color(*WHITE)
            pdf.set_font("Helvetica", "B", 7)
            pdf.cell(12, 5, f"  {sev[:3]}", fill=True)

            if shade:
                pdf.set_fill_color(*LGRAY)
            else:
                pdf.set_fill_color(*WHITE)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Helvetica", "", 7)

            ftype    = _safe(str(f.get('finding_type', '')))[:38]
            resource = _safe(str(f.get('resource_id',  '')))[:22]
            tactic   = _safe(str(f.get('tactic',       '')))[:18]
            status   = _safe(str(f.get('status',       '')))[:16]
            
            pdf.cell(70, 5, ftype,    fill=True)
            pdf.cell(45, 5, resource, fill=True)
            pdf.cell(30, 5, tactic,   fill=True)
            pdf.cell(33, 5, status,   fill=True, ln=True)
            shade = not shade

        if len(gd_findings) > 20:
            pdf.set_font("Helvetica", "I", 8)
            pdf.cell(0, 5, f"  ... and {len(gd_findings) - 20} more findings. See dashboard for full list.", ln=True)

    pdf.ln(3)

    # -- CLOUDTRAIL INCIDENTS --------------------------------------------------
    _section_header(pdf, "3. CLOUDTRAIL ANOMALY INCIDENTS")

    ct_incidents = [i for i in incidents if i.get('service', '').upper() == 'CLOUDTRAIL']
    if not ct_incidents:
        pdf.set_font("Helvetica", "I", 9)
        pdf.cell(0, 6, "  No CloudTrail anomaly incidents recorded.", ln=True)
    else:
        pdf.set_fill_color(*NAVY)
        pdf.set_text_color(*WHITE)
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(50, 6, "  Event",       fill=True)
        pdf.cell(40, 6, "Risk Level",    fill=True)
        pdf.cell(50, 6, "Actor",         fill=True)
        pdf.cell(50, 6, "Detected At",   fill=True, ln=True)
        pdf.set_text_color(0, 0, 0)

        shade = False
        for i in ct_incidents[:15]:
            risk  = i.get('risk_level', i.get('status', 'UNKNOWN'))
            rc, rg, rb = _severity_color(risk)

            if shade:
                pdf.set_fill_color(*LGRAY)
            else:
                pdf.set_fill_color(*WHITE)

            pdf.set_font("Helvetica", "", 7)
            event_label = _safe(str(i.get('file_key', i.get('event_name', ''))).replace('🟡','').replace('🟠','').replace('🔴','').strip())[:28]
            pdf.cell(50, 5, f"  {event_label}", fill=True)

            pdf.set_fill_color(rc, rg, rb)
            pdf.set_text_color(*WHITE)
            pdf.set_font("Helvetica", "B", 7)
            pdf.cell(40, 5, f"  {risk[:12]}", fill=True)

            if shade:
                pdf.set_fill_color(*LGRAY)
            else:
                pdf.set_fill_color(*WHITE)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Helvetica", "", 7)
            actor    = _safe(str(i.get('actor_name', 'Unknown')))[:25]
            detected = _safe(str(i.get('detected_at', i.get('updated_at', ''))))[:22]
            pdf.cell(50, 5, actor,   fill=True)
            pdf.cell(50, 5, detected, fill=True, ln=True)
            shade = not shade

    pdf.ln(3)

    # -- EC2 / VPC THREATS ----------------------------------------------------
    _section_header(pdf, "4. COMPUTE & NETWORK THREATS")

    all_infra = (
        [dict(t, layer="EC2") for t in ec2_threats] +
        [dict(t, layer="VPC") for t in vpc_threats]
    )

    if not all_infra:
        pdf.set_font("Helvetica", "I", 9)
        pdf.cell(0, 6, "  No EC2 or VPC threats detected.", ln=True)
    else:
        pdf.set_fill_color(*NAVY)
        pdf.set_text_color(*WHITE)
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(15, 6, "  Layer",     fill=True)
        pdf.cell(40, 6, "Resource",    fill=True)
        pdf.cell(80, 6, "Threat",      fill=True)
        pdf.cell(55, 6, "Resolution",  fill=True, ln=True)
        pdf.set_text_color(0, 0, 0)

        shade = False
        for t in all_infra[:15]:
            if shade:
                pdf.set_fill_color(*LGRAY)
            else:
                pdf.set_fill_color(*WHITE)
            pdf.set_font("Helvetica", "", 7)
            pdf.cell(15, 5, f"  {t.get('layer','')}",                           fill=True)
            pdf.cell(40, 5, str(t.get('resource_id',''))[:22],                   fill=True)
            pdf.cell(80, 5, str(t.get('threat_type',''))[:45],                   fill=True)
            pdf.cell(55, 5, str(t.get('resolution',''))[:32],                    fill=True, ln=True)
            shade = not shade

    pdf.ln(3)

    # -- IAM SUMMARY -----------------------------------------------------------
    _section_header(pdf, "5. IAM SECURITY SUMMARY")

    iam_incidents = [i for i in incidents if i.get('service', '').upper() == 'IAM']
    shade = False
    _kv_row(pdf, "Active Root Login Alerts",  str(len(iam_incidents)), shade); shade = not shade
    _kv_row(pdf, "Stale Access Keys (>90d)",  str(stale_keys),         shade); shade = not shade
    _kv_row(pdf, "Users Without MFA",         str(missing_mfa),        shade)
    pdf.ln(3)

    # -- RECOMMENDATIONS -------------------------------------------------------
    pdf.add_page()
    _section_header(pdf, "6. RECOMMENDATIONS")

    recs = []

    if score < 80:
        recs.append(("HIGH",     "Compliance Score Below 80%",
                      f"Current score is {score}%. Run Prowler remediation on the top failed checks "
                      "to reach the 80% CIS Benchmark threshold."))
    if missing_mfa > 0:
        recs.append(("CRITICAL", "Users Missing MFA",
                      f"{missing_mfa} IAM user(s) have no MFA configured. Enable MFA immediately - "
                      "this is the single most effective control against credential theft."))
    if stale_keys > 0:
        recs.append(("HIGH",     "Stale Programmatic Access Keys",
                      f"{stale_keys} access key(s) unused for 90+ days. Rotate or deactivate them "
                      "to reduce the attack surface for credential-based attacks."))

    high_gd = [f for f in gd_findings if f.get('severity_label') == 'HIGH']
    if high_gd:
        recs.append(("CRITICAL", f"{len(high_gd)} High-Severity GuardDuty Findings Unresolved",
                      "Review and acknowledge all HIGH findings in the GuardDuty SIEM tab. "
                      "High findings indicate active or imminent threats requiring immediate investigation."))

    if any(t.get('threat_type','').startswith('IMDSv1') for t in ec2_threats):
        recs.append(("HIGH",     "IMDSv1 Active on EC2 Instances",
                      "EC2 instances with IMDSv1 are vulnerable to SSRF credential theft attacks. "
                      "Enforce IMDSv2 via the EC2 Compute tab in Sentinel."))

    if vpc_threats:
        recs.append(("HIGH",     "Open Management Ports to Internet",
                      f"{len(vpc_threats)} Security Group rule(s) expose SSH or RDP to 0.0.0.0/0. "
                      "Restrict access to a trusted IP range or VPN immediately."))

    if not recs:
        recs.append(("LOW",      "No Critical Recommendations",
                      "Security posture is within acceptable parameters. "
                      "Continue daily Prowler scans and monitor GuardDuty for emerging threats."))

    for idx, (level, title, detail) in enumerate(recs):
        rc, rg, rb = _severity_color(level)
        pdf.set_fill_color(rc, rg, rb)
        pdf.set_text_color(*WHITE)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(0, 7, f"  [{level}]  {title}", fill=True, ln=True)
        pdf.set_fill_color(*LGRAY)
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "", 8)
        pdf.multi_cell(0, 5, f"  {_safe(detail)}", fill=True)
        pdf.ln(2)

    # -- SIGN-OFF --------------------------------------------------------------
    pdf.ln(5)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(*DGRAY)
    pdf.multi_cell(0, 5,
        "This report was automatically generated by Project Sentinel CNAPP. "
        "All findings are based on real-time AWS API data and GuardDuty threat intelligence. "
        "For questions, review the full dashboard or contact your cloud security team.",
        align="C"
    )

    return bytes(pdf.output())