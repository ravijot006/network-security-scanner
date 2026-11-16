from flask import Flask, render_template, request, send_file
import socket
from datetime import datetime
import os
import concurrent.futures
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

app = Flask(__name__)

REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

# In-memory session logs and scan history (replaces browser localStorage/JS state)
SCAN_HISTORY = []
CURRENT_LOGS = [
    {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "level": "INFO",
        "message": "Terminal initialized securely in pure Python/CSS mode. Awaiting target recon command..."
    }
]
LATEST_SCAN = None

COMMON_PORTS = {
    21: "FTP (File Transfer)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Insecure Remote)",
    25: "SMTP (Mail Server)",
    53: "DNS (Domain Name System)",
    80: "HTTP (Web Server)",
    110: "POP3 (Email Retrieval)",
    143: "IMAP (Email Sync)",
    443: "HTTPS (Secure Web Server)",
    445: "SMB (File Sharing)",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop)",
    5432: "PostgreSQL Database",
    6379: "Redis Cache",
    8080: "HTTP Proxy / Alt Web"
}

def add_log(level, message):
    CURRENT_LOGS.append({
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "level": level,
        "message": message
    })

def grab_banner(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.4)
        s.connect((ip, port))
        banner_data = ""
        try:
            banner_data = s.recv(1024).decode('utf-8', errors='ignore').strip()
        except socket.timeout:
            pass
        if not banner_data and port in [80, 8080, 443]:
            try:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner_data = s.recv(1024).decode('utf-8', errors='ignore').strip()
            except Exception:
                pass
        s.close()
        if banner_data:
            return banner_data.split('\n')[0][:45]
    except Exception:
        pass
    return COMMON_PORTS.get(port, "Unknown / Custom Service")

def scan_single_port(target_ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        result = s.connect_ex((target_ip, port))
        if result == 0:
            service = grab_banner(target_ip, port)
            s.close()
            return {'port': port, 'service': service}
        s.close()
    except Exception:
        pass
    return None

@app.route('/', methods=['GET', 'POST'])
def index():
    global LATEST_SCAN

    target = request.form.get('target', '127.0.0.1').strip()
    ports_range = request.form.get('ports', '1-100').strip()
    action = request.form.get('action', '')
    active_filter = request.args.get('filter', 'ALL').upper()
    drawer_open = request.args.get('drawer', 'closed') == 'open'

    if request.method == 'POST':
        if action == 'full_range':
            ports_range = '1-65535'
            add_log('INFO', 'Port range configured to full spectrum [1-65535].')

        elif action == 'clear_history':
            SCAN_HISTORY.clear()
            add_log('WARN', 'Case log archives purged by operator.')

        elif action == 'scan':
            add_log('INFO', f'Initiating reconnaissance protocol on target: {target} [Ports: {ports_range}]')
            try:
                if '-' in ports_range:
                    start_port, end_port = map(int, ports_range.split('-'))
                else:
                    start_port = end_port = int(ports_range)

                start_port = max(1, start_port)
                end_port = min(65535, end_port)
                if start_port > end_port:
                    start_port, end_port = end_port, start_port

                target_ip = socket.gethostbyname(target)
                add_log('INFO', f'Target resolved successfully. Host IP: {target_ip}')

                open_ports_info = []
                with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                    futures = [executor.submit(scan_single_port, target_ip, port) for port in range(start_port, end_port + 1)]
                    for future in concurrent.futures.as_completed(futures):
                        res = future.result()
                        if res:
                            open_ports_info.append(res)

                open_ports_info.sort(key=lambda x: x['port'])
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                LATEST_SCAN = {
                    'target': target,
                    'target_ip': target_ip,
                    'ports_scanned': f'{start_port}-{end_port}',
                    'open_ports': open_ports_info,
                    'timestamp': timestamp
                }
                SCAN_HISTORY.insert(0, LATEST_SCAN)
                if len(SCAN_HISTORY) > 15:
                    SCAN_HISTORY.pop()

                if open_ports_info:
                    add_log('WARN', f'Discovered {len(open_ports_info)} active open ports across target range.')
                    for item in open_ports_info:
                        severity = 'INFO'
                        if item['port'] in [21, 23, 3389, 445]:
                            severity = 'CRITICAL'
                        elif item['port'] in [22, 3306, 5432, 80, 443]:
                            severity = 'WARN'
                        add_log(severity, f"TCP PORT {item['port']} OPEN — Fingerprint: {item['service']}")
                    add_log('INFO', 'Reconnaissance scan complete. Audit report ready for export.')
                else:
                    add_log('INFO', f'Scan completed on {target_ip}. No open ports responded in range {start_port}-{end_port}.')

            except ValueError:
                add_log('CRITICAL', 'Invalid port range format. Use start-end (e.g., 1-100).')
            except socket.gaierror:
                add_log('CRITICAL', f'Unable to resolve hostname: {target}')
            except Exception as e:
                add_log('CRITICAL', f'Scan failure: {str(e)}')

    filtered_logs = [
        log for log in CURRENT_LOGS
        if active_filter == 'ALL' or log['level'] == active_filter
    ]

    return render_template(
        'index.html',
        target=target,
        ports=ports_range,
        logs=filtered_logs,
        total_logs=len(CURRENT_LOGS),
        active_filter=active_filter,
        history=SCAN_HISTORY,
        latest_scan=LATEST_SCAN,
        drawer_open=drawer_open
    )

@app.route('/download-report', methods=['POST'])
def download_report():
    if not LATEST_SCAN:
        return "No scan data available to generate report.", 400

    target = LATEST_SCAN['target']
    target_ip = LATEST_SCAN['target_ip']
    ports_scanned = LATEST_SCAN['ports_scanned']
    open_ports = LATEST_SCAN['open_ports']
    timestamp = LATEST_SCAN['timestamp']

    filename = f"Security_Audit_Report_{target.replace('.', '_')}.pdf"
    filepath = os.path.join(REPORTS_DIR, filename)

    doc = SimpleDocTemplate(filepath, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    story = []
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle('ReportTitle', parent=styles['Heading1'], fontName='Helvetica-Bold', fontSize=20, textColor=colors.HexColor('#00ff66'), spaceAfter=6)
    subtitle_style = ParagraphStyle('ReportSubtitle', parent=styles['Normal'], fontName='Courier', fontSize=10, textColor=colors.HexColor('#555555'), spaceAfter=20)
    heading_style = ParagraphStyle('SectionHeading', parent=styles['Heading2'], fontName='Helvetica-Bold', fontSize=12, textColor=colors.HexColor('#00aa44'), spaceBefore=12, spaceAfter=8)
    body_style = ParagraphStyle('ReportBody', parent=styles['Normal'], fontName='Courier', fontSize=9, textColor=colors.HexColor('#222222'), spaceAfter=6)

    story.append(Paragraph("GHOST_SEC // NETWORK SECURITY AUDIT REPORT", title_style))
    story.append(Paragraph(f"Generated Timestamp: {timestamp}", subtitle_style))

    meta_data = [
        [Paragraph("<b>Target Host:</b>", body_style), Paragraph(target, body_style)],
        [Paragraph("<b>Resolved IP:</b>", body_style), Paragraph(target_ip, body_style)],
        [Paragraph("<b>Probed Range:</b>", body_style), Paragraph(ports_scanned, body_style)],
        [Paragraph("<b>Total Open Ports:</b>", body_style), Paragraph(str(len(open_ports)), body_style)]
    ]
    meta_table = Table(meta_data, colWidths=[120, 400])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f0f9f4')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#00ff66')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 15))
    story.append(Paragraph("DISCOVERED OPEN PORTS & SERVICES", heading_style))

    if open_ports:
        port_rows = [[Paragraph("<b>Port</b>", body_style), Paragraph("<b>Service / Banner Fingerprint</b>", body_style)]]
        for p in open_ports:
            port_rows.append([Paragraph(f"TCP {p['port']}", body_style), Paragraph(p['service'], body_style)])
        port_table = Table(port_rows, colWidths=[100, 420])
        port_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#00ff66')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(port_table)
    else:
        story.append(Paragraph("No open ports or active services discovered in the scanned range.", body_style))

    doc.build(story)
    return send_file(filepath, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)