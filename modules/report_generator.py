"""
Report Generator Module
Generates structured security assessment reports in multiple formats.
"""

import json
import os
from datetime import datetime


class ReportGenerator:
    """Generates security assessment reports in TXT, JSON, and HTML formats."""

    SEVERITY_COLORS = {
        "CRITICAL": "#dc2626",
        "HIGH": "#ea580c",
        "MEDIUM": "#d97706",
        "LOW": "#65a30d",
        "INFO": "#6b7280",
        "SECURE": "#16a34a",
    }

    def __init__(self, scan_data, target, output_dir="reports"):
        self.scan_data = scan_data
        self.target = target
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.report_date = datetime.now().strftime("%B %d, %Y %H:%M:%S")
        safe = target.replace("/", "_").replace(".", "_")
        self.base_name = f"{output_dir}/vuln_report_{safe}_{self.timestamp}"

    def _severity_order(self, vuln):
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        return order.get(vuln.get("severity", "INFO"), 4)

    def generate_text_report(self):
        """Generate plain-text security report."""
        path = self.base_name + ".txt"
        lines = []

        def h(text, char="="):
            lines.append(char * 60)
            lines.append(f"  {text}")
            lines.append(char * 60)

        h("VULNERABILITY SCAN REPORT")
        lines.append(f"  Target:       {self.target}")
        lines.append(f"  Scan Date:    {self.report_date}")
        lines.append(f"  Scanner:      Nmap {self.scan_data['scan_info'].get('version', '')}")
        lines.append(f"  Scan Args:    {self.scan_data['scan_info'].get('args', '')}")
        lines.append(f"  Duration:     {self.scan_data['scan_info'].get('elapsed', 'N/A')}s")
        lines.append("")

        h("EXECUTIVE SUMMARY", "-")
        summary = self.scan_data.get("summary", {})
        lines.append(f"  Hosts Scanned:  {summary.get('total', 0)}")
        lines.append(f"  Hosts Up:       {summary.get('up', 0)}")
        lines.append(f"  Hosts Down:     {summary.get('down', 0)}")
        total_ports = sum(len(h["ports"]) for h in self.scan_data["hosts"])
        total_vulns = sum(len(h.get("vulnerabilities", [])) for h in self.scan_data["hosts"])
        lines.append(f"  Open Ports:     {total_ports}")
        lines.append(f"  Total Findings: {total_vulns}")
        lines.append("")

        for host in self.scan_data["hosts"]:
            h(f"HOST: {host.get('ip', 'Unknown')} [{host.get('hostname', '')}]", "=")
            lines.append(f"  Status:       {host.get('status', '').upper()}")
            lines.append(f"  IP Address:   {host.get('ip', 'N/A')}")
            lines.append(f"  Hostname:     {host.get('hostname', 'N/A')}")
            lines.append(f"  OS:           {host.get('os', 'Unknown')}")
            lines.append(f"  Risk Rating:  {host.get('risk_rating', 'N/A')}")
            lines.append(f"  Risk Score:   {host.get('risk_score', 0)}/100")
            lines.append("")

            # Open Ports
            lines.append("  OPEN PORTS:")
            lines.append("  " + "-" * 56)
            lines.append(f"  {'PORT':<10} {'PROTO':<8} {'SERVICE':<15} {'PRODUCT/VERSION'}")
            lines.append("  " + "-" * 56)
            for port in host.get("ports", []):
                pv = f"{port.get('product', '')} {port.get('version', '')}".strip()
                lines.append(f"  {port['port']:<10} {port['protocol']:<8} {port['service']:<15} {pv}")
            lines.append("")

            # Vulnerabilities
            vulns = sorted(host.get("vulnerabilities", []), key=self._severity_order)
            if vulns:
                lines.append(f"  VULNERABILITIES & FINDINGS ({len(vulns)} total):")
                lines.append("  " + "-" * 56)
                for i, v in enumerate(vulns, 1):
                    lines.append(f"  [{i}] [{v['severity']}] {v['title']}")
                    lines.append(f"      Port:        {v.get('port', 'N/A')}")
                    lines.append(f"      Type:        {v.get('type', 'N/A')}")
                    if v.get("cve"):
                        lines.append(f"      CVE:         {v['cve']}")
                    lines.append(f"      Description: {v.get('description', '')}")
                    lines.append(f"      Fix:         {v.get('recommendation', '')}")
                    lines.append("")
            else:
                lines.append("  [✓] No known vulnerabilities detected on this host.")
                lines.append("")

        h("RECOMMENDATIONS", "-")
        all_vulns = []
        for host in self.scan_data["hosts"]:
            all_vulns.extend(host.get("vulnerabilities", []))

        critical = [v for v in all_vulns if v["severity"] == "CRITICAL"]
        high = [v for v in all_vulns if v["severity"] == "HIGH"]

        if critical:
            lines.append("  !! CRITICAL PRIORITY:")
            for v in critical:
                lines.append(f"     • {v['title']}: {v['recommendation']}")
            lines.append("")
        if high:
            lines.append("  ! HIGH PRIORITY:")
            for v in high:
                lines.append(f"     • {v['title']}: {v['recommendation']}")
            lines.append("")

        lines.append("  GENERAL HARDENING GUIDELINES:")
        lines.append("     1. Disable all unused services and close unnecessary ports")
        lines.append("     2. Apply all pending OS and software security patches")
        lines.append("     3. Implement strict firewall rules (default-deny policy)")
        lines.append("     4. Use encrypted protocols (SSH, HTTPS, SFTP) only")
        lines.append("     5. Enable intrusion detection/prevention systems (IDS/IPS)")
        lines.append("     6. Regularly audit accounts and enforce least-privilege access")
        lines.append("     7. Schedule periodic vulnerability assessments")
        lines.append("")

        h("END OF REPORT", "=")
        lines.append(f"  Generated by: Automated Vulnerability Scanner")
        lines.append(f"  Report Date:  {self.report_date}")

        with open(path, "w") as f:
            f.write("\n".join(lines))

        print(f"[✓] Text report saved: {path}")
        return path

    def generate_json_report(self):
        """Generate machine-readable JSON report."""
        path = self.base_name + ".json"

        report = {
            "report_metadata": {
                "title": "Vulnerability Scan Report",
                "target": self.target,
                "generated_at": self.report_date,
                "tool": "Automated Vulnerability Scanner",
            },
            "scan_info": self.scan_data.get("scan_info", {}),
            "summary": {
                **self.scan_data.get("summary", {}),
                "total_open_ports": sum(len(h["ports"]) for h in self.scan_data["hosts"]),
                "total_findings": sum(len(h.get("vulnerabilities", [])) for h in self.scan_data["hosts"]),
                "critical_findings": sum(
                    len([v for v in h.get("vulnerabilities", []) if v["severity"] == "CRITICAL"])
                    for h in self.scan_data["hosts"]
                ),
            },
            "hosts": self.scan_data.get("hosts", []),
        }

        with open(path, "w") as f:
            json.dump(report, f, indent=2)

        print(f"[✓] JSON report saved: {path}")
        return path

    def generate_html_report(self):
        """Generate styled HTML security report."""
        path = self.base_name + ".html"

        all_vulns = []
        for host in self.scan_data["hosts"]:
            all_vulns.extend(host.get("vulnerabilities", []))

        total_ports = sum(len(h["ports"]) for h in self.scan_data["hosts"])
        critical_count = len([v for v in all_vulns if v["severity"] == "CRITICAL"])
        high_count = len([v for v in all_vulns if v["severity"] == "HIGH"])
        medium_count = len([v for v in all_vulns if v["severity"] == "MEDIUM"])

        def severity_badge(sev):
            color = self.SEVERITY_COLORS.get(sev, "#6b7280")
            return f'<span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:bold;">{sev}</span>'

        hosts_html = ""
        for host in self.scan_data["hosts"]:
            risk = host.get("risk_rating", "UNKNOWN")
            risk_color = self.SEVERITY_COLORS.get(risk, "#6b7280")

            ports_rows = ""
            for p in host.get("ports", []):
                pv = f"{p.get('product', '')} {p.get('version', '')}".strip() or "—"
                port_risk = "🔴" if p["port"] in ["23", "21", "445", "3389", "4444"] else "🟡" if p["port"] in ["3306", "5432", "6379", "27017"] else "🟢"
                ports_rows += f"""
                <tr>
                  <td><b>{p['port']}/{p['protocol']}</b></td>
                  <td>{p['service']}</td>
                  <td>{pv}</td>
                  <td>{port_risk}</td>
                </tr>"""

            vulns_html = ""
            vulns = sorted(host.get("vulnerabilities", []), key=self._severity_order)
            for v in vulns:
                cve_badge = f'<span style="font-family:monospace;background:#1e293b;color:#94a3b8;padding:1px 6px;border-radius:3px;">{v.get("cve","")}</span>' if v.get("cve") else ""
                vulns_html += f"""
                <div style="border:1px solid #e2e8f0;border-left:4px solid {self.SEVERITY_COLORS.get(v['severity'],'#ccc')};border-radius:4px;padding:12px 16px;margin-bottom:10px;">
                  <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;">
                    {severity_badge(v['severity'])}
                    <b>{v['title']}</b>
                    {cve_badge}
                  </div>
                  <div style="color:#475569;font-size:13px;">
                    <b>Port:</b> {v.get('port','N/A')} &nbsp;|&nbsp; <b>Type:</b> {v.get('type','N/A')}
                  </div>
                  <div style="margin-top:6px;color:#334155;">{v.get('description','')}</div>
                  <div style="margin-top:6px;background:#f0fdf4;border-radius:4px;padding:6px 10px;color:#166534;font-size:13px;">
                    💡 <b>Fix:</b> {v.get('recommendation','')}
                  </div>
                </div>"""

            if not vulns_html:
                vulns_html = '<div style="color:#16a34a;padding:10px;">✅ No known vulnerabilities detected.</div>'

            hosts_html += f"""
            <div style="background:white;border:1px solid #e2e8f0;border-radius:8px;padding:24px;margin-bottom:24px;box-shadow:0 1px 3px rgba(0,0,0,0.05);">
              <div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:16px;">
                <div>
                  <h2 style="margin:0;font-size:18px;">🖥️ {host.get('ip','Unknown')}</h2>
                  <div style="color:#64748b;font-size:13px;">{host.get('hostname','') or 'No hostname'} &nbsp;|&nbsp; {host.get('os','OS unknown')}</div>
                </div>
                <div style="text-align:right;">
                  <div style="background:{risk_color};color:white;padding:4px 14px;border-radius:20px;font-weight:bold;">{risk} RISK</div>
                  <div style="color:#64748b;font-size:12px;margin-top:4px;">Score: {host.get('risk_score',0)}</div>
                </div>
              </div>

              <h3 style="font-size:14px;color:#475569;text-transform:uppercase;letter-spacing:0.5px;">Open Ports</h3>
              <table style="width:100%;border-collapse:collapse;font-size:13px;margin-bottom:20px;">
                <tr style="background:#f8fafc;"><th style="text-align:left;padding:8px 10px;">Port</th><th style="text-align:left;padding:8px 10px;">Service</th><th style="text-align:left;padding:8px 10px;">Version</th><th style="padding:8px 10px;">Risk</th></tr>
                {ports_rows}
              </table>

              <h3 style="font-size:14px;color:#475569;text-transform:uppercase;letter-spacing:0.5px;">Findings ({len(vulns)})</h3>
              {vulns_html}
            </div>"""

        summary = self.scan_data.get("summary", {})

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vulnerability Scan Report - {self.target}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f1f5f9; color: #1e293b; }}
  table tr:hover {{ background: #f8fafc; }}
  table td {{ padding: 8px 10px; border-bottom: 1px solid #f1f5f9; }}
  @media print {{ body {{ background: white; }} }}
</style>
</head>
<body>
<div style="max-width:900px;margin:0 auto;padding:32px 16px;">

  <!-- Header -->
  <div style="background:linear-gradient(135deg,#0f172a,#1e3a5f);color:white;border-radius:12px;padding:32px;margin-bottom:24px;">
    <div style="font-size:12px;text-transform:uppercase;letter-spacing:2px;opacity:0.7;margin-bottom:8px;">Security Assessment Report</div>
    <h1 style="font-size:28px;font-weight:700;margin-bottom:4px;">Vulnerability Scan Report</h1>
    <div style="opacity:0.8;">Target: <b>{self.target}</b> &nbsp;|&nbsp; {self.report_date}</div>
    <div style="opacity:0.6;font-size:12px;margin-top:6px;">Generated by: Automated Vulnerability Scanner & Report Generator</div>
  </div>

  <!-- Summary Cards -->
  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px;">
    <div style="background:white;border-radius:8px;padding:16px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,0.05);">
      <div style="font-size:28px;font-weight:700;color:#3b82f6;">{summary.get('up',0)}</div>
      <div style="color:#64748b;font-size:13px;">Hosts Up</div>
    </div>
    <div style="background:white;border-radius:8px;padding:16px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,0.05);">
      <div style="font-size:28px;font-weight:700;color:#8b5cf6;">{total_ports}</div>
      <div style="color:#64748b;font-size:13px;">Open Ports</div>
    </div>
    <div style="background:white;border-radius:8px;padding:16px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,0.05);">
      <div style="font-size:28px;font-weight:700;color:#dc2626;">{critical_count}</div>
      <div style="color:#64748b;font-size:13px;">Critical Findings</div>
    </div>
    <div style="background:white;border-radius:8px;padding:16px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,0.05);">
      <div style="font-size:28px;font-weight:700;color:#ea580c;">{high_count}</div>
      <div style="color:#64748b;font-size:13px;">High Findings</div>
    </div>
  </div>

  <!-- Host Results -->
  {hosts_html}

  <!-- Footer -->
  <div style="text-align:center;color:#94a3b8;font-size:12px;margin-top:24px;padding:16px;border-top:1px solid #e2e8f0;">
    Automated Vulnerability Scanner &amp; Report Generator &nbsp;|&nbsp; {self.report_date}<br>
    <i>This report is for authorized security assessment purposes only.</i>
  </div>

</div>
</body>
</html>"""

        with open(path, "w") as f:
            f.write(html)

        print(f"[✓] HTML report saved: {path}")
        return path
