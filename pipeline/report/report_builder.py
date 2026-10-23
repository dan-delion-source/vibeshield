"""Deterministic, evidence-based exports for completed or incomplete scans."""
from collections import Counter
from datetime import datetime, timezone
from html import escape
from io import BytesIO
import json
import re

REMEDIATIONS = {
    'IDOR': ('Review object ownership before returning data. Compare the resource owner with the authenticated principal, or constrain the lookup to authorized objects. Verify a correction using two owned test accounts.', 'The AST rule identifies missing-check patterns; it does not prove an authorization bypass.'),
    'SECRET_EXPOSURE': ('Review the redacted match locally. If it is a real credential, revoke or rotate it and remove it from source and relevant history. Do not include the secret in shared reports.', 'A pattern match does not prove that a credential is active.'),
    'vibeshield-missing-nosniff': ('Consider returning X-Content-Type-Options: nosniff and correct Content-Type headers. Recheck the same endpoint after the change.', 'A missing header alone does not establish exploitability.'),
    '10021': ('Consider returning X-Content-Type-Options: nosniff and correct Content-Type headers. Recheck the same endpoint after the change.', 'A missing header alone does not establish exploitability.'),
    '10036': ('Review whether the Server response header needs to disclose software versions. Configure the application or reverse proxy to reduce unnecessary version disclosure.', 'Version disclosure does not prove the software is vulnerable.'),
}


def finding_guidance(finding):
    kind = finding['vulnerability_type']
    if kind in REMEDIATIONS:
        action, limitation = REMEDIATIONS[kind]
    elif 'avoid_app_run_with_bad_host' in kind:
        action = 'Review the bind address and port publishing. For this fixture, bind Docker host ports to 127.0.0.1; a container-internal 0.0.0.0 bind is not proof of public exposure.'
        limitation = 'Review deployment context before classifying this configuration as a vulnerability.'
    elif 'flask-debug-enabled' in kind:
        action, limitation = 'Disable Flask debug mode outside controlled local development.', 'Confirm the actual deployed configuration.'
    else:
        action, limitation = 'Review the source rule, affected location, and application context. Reproduce only within the authorized scope before choosing a fix.', 'No rule-specific remediation is implemented for this finding.'
    return {'recommendation': action, 'limitation': limitation}


def severity(finding):
    value = finding.get('details', {}).get('severity', '').upper()
    return {'WARNING': 'MEDIUM', 'ERROR': 'HIGH', 'INFORMATIONAL': 'INFO', '': 'UNRATED'}.get(value, value)


def report_data(scan):
    findings = [{**item, 'display_severity': severity(item), **finding_guidance(item)} for item in scan['findings']]
    return {
        'schema_version': '1.0', 'project': 'VibeShield', 'generated_at': datetime.now(timezone.utc).isoformat(),
        'scan_id': scan['id'], 'target': scan['target'], 'target_type': scan['target_type'],
        'status': scan['status'], 'complete': scan['status'] == 'completed',
        'created_at': scan['created_at'], 'finished_at': scan.get('finished_at'),
        'authorization': scan.get('authorization', {}), 'repository_commit': scan.get('repository_commit'),
        'summary': {'candidate_count': len(findings), 'by_severity': dict(Counter(item['display_severity'] for item in findings))},
        'stages': scan['stages'], 'errors': scan['errors'], 'findings': findings,
        'limitations': [
            'All findings are candidates. No exploit verification, numeric risk score, or LLM analysis was performed.',
            'Tool severity and evidence confidence are different. AST IDOR candidates have no assigned severity.',
            'Overlapping findings from different scanners are preserved.',
            'An incomplete scan or empty result does not establish safety.',
            'Nuclei currently uses one bundled missing-nosniff header template. ZAP performs passive analysis.',
        ],
    }


def json_report(scan):
    return json.dumps(report_data(scan), indent=2, ensure_ascii=False).encode('utf-8')


def pdf_report(scan):
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_LEFT
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
    data = report_data(scan)
    output = BytesIO()
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle('BodyV', fontName='Helvetica', fontSize=9.5, leading=14, textColor=colors.HexColor('#26352e'), spaceAfter=9))
    styles.add(ParagraphStyle('SmallV', parent=styles['BodyV'], fontSize=8, leading=11))
    def p(text, style='BodyV'):
        # Report content is untrusted scanner/target text, never ReportLab markup.
        value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', str(text))
        return Paragraph(escape(value).replace('\n', '<br/>'), styles[style])
    story = [p('VibeShield / Security assessment', 'Title'), Spacer(1, 10), p(data['target'], 'Heading2'),
             p(f"Scan {data['scan_id']} | {data['status'].upper()} | {len(data['findings'])} candidate findings"),
             p(f"Started: {data['created_at']} | Finished: {data['finished_at'] or 'not recorded'}", 'SmallV'),
             p('This report records deterministic scanner observations. It is not an exploit-verification report or a certification of safety.')]
    if data['repository_commit']:
        story.append(p('Repository commit: ' + data['repository_commit'], 'SmallV'))
    story.append(p('Scan coverage', 'Heading2'))
    rows = [[p('Tool'), p('Result'), p('Findings')]]
    for stage in data['stages']:
        rows.append([p(stage['name']), p(stage['status']), p(stage.get('finding_count', '—'))])
    table = Table(rows, colWidths=[160, 210, 105], repeatRows=1, hAlign='LEFT')
    table.setStyle(TableStyle([('BACKGROUND', (0,0),(-1,0),colors.HexColor('#eeeae4')), ('LINEBELOW',(0,0),(-1,0),0.6,colors.HexColor('#b7beb8')), ('VALIGN',(0,0),(-1,-1),'TOP'), ('BOTTOMPADDING',(0,0),(-1,-1),8)]))
    story.extend([table, Spacer(1, 12)])
    if data['errors']:
        story.append(p('Incomplete coverage', 'Heading2'))
        for error in data['errors']:
            story.append(p(f"{error['source_tool']}: {error['error']}"))
    story.append(p('Candidate findings', 'Heading2'))
    if not data['findings']:
        story.append(p('No candidates were emitted by the completed scanner stages. Review coverage and errors before interpreting this result.'))
    for index, finding in enumerate(data['findings'], 1):
        details = finding['details']
        title = details.get('message') or finding['vulnerability_type']
        story.append(KeepTogether([p(f'{index}. {title}', 'Heading3'), p(f"{finding['source_tool']} | Severity: {finding['display_severity']} | Confidence: {finding['confidence']}", 'SmallV')]))
        story.append(p(f"Location: {finding['file_or_endpoint']}" + (f":{details['line']}" if details.get('line') else ''), 'SmallV'))
        story.append(p('Evidence: ' + (details.get('reason') or details.get('message') or 'See native rule identifier.')))
        if details.get('source_snippet'):
            story.append(p('Source: ' + details['source_snippet'], 'SmallV'))
        story.extend([p('Suggested review: ' + finding['recommendation']), p(finding['limitation'], 'SmallV')])
    story.append(p('Method and limitations', 'Heading2'))
    story.extend(p(item) for item in data['limitations'])
    story.append(p('Authorized coursework only. Test only systems you own or have explicit permission to assess.'))
    def footer(canvas, doc):
        canvas.saveState(); canvas.setFont('Helvetica', 8); canvas.setFillColor(colors.HexColor('#59685e'))
        canvas.drawString(42, 27, 'VibeShield · Deterministic research report')
        canvas.drawRightString(553, 27, str(doc.page)); canvas.restoreState()
    SimpleDocTemplate(output, title='VibeShield security assessment', author='VibeShield',
                      leftMargin=42, rightMargin=42, topMargin=42, bottomMargin=45).build(story, onFirstPage=footer, onLaterPages=footer)
    return output.getvalue()
