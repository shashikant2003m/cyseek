#!/usr/bin/env python3
"""
Automated Vulnerability Scanner & Report Generator
Author: Security Assessment Tool
Description: Automates Nmap-based network scanning and generates structured security reports.
"""

import subprocess
import json
import os
import sys
import argparse
import re
from datetime import datetime
from modules.report_generator import ReportGenerator
from modules.vulnerability_analyzer import VulnerabilityAnalyzer


def check_nmap():
    """Check if nmap is installed."""
    try:
        result = subprocess.run(["nmap", "--version"], capture_output=True, text=True)
        version_line = result.stdout.splitlines()[0] if result.stdout else "Unknown version"
        print(f"[✓] Nmap found: {version_line}")
        return True
    except FileNotFoundError:
        print("[✗] Nmap not found. Please install it: sudo apt install nmap")
        return False


def run_nmap_scan(target, scan_type="standard", ports=None, output_file=None):
    """
    Run Nmap scan with specified parameters.
    
    Scan types:
    - quick: Fast scan of common ports
    - standard: Service/version detection on top 1000 ports
    - full: Comprehensive scan with OS detection and scripts
    - stealth: SYN scan (requires root)
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = re.sub(r'[^a-zA-Z0-9._-]', '_', target)
    xml_output = output_file or f"reports/scan_{safe_target}_{timestamp}.xml"

    scan_profiles = {
        "quick": ["-T4", "--top-ports", "100"],
        "standard": ["-sV", "-sC", "-T4", "--top-ports", "1000"],
        "full": ["-sV", "-sC", "-O", "-A", "-T4", "-p-"],
        "stealth": ["-sS", "-sV", "-T2", "--top-ports", "1000"],
    }

    nmap_args = scan_profiles.get(scan_type, scan_profiles["standard"])
    
    if ports:
        nmap_args += ["-p", ports]

    cmd = ["nmap"] + nmap_args + ["-oX", xml_output, "--open", target]
    
    print(f"\n[*] Starting {scan_type.upper()} scan on target: {target}")
    print(f"[*] Command: {' '.join(cmd)}")
    print(f"[*] Output file: {xml_output}")
    print("-" * 60)

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        output_lines = []
        for line in process.stdout:
            print(line, end="")
            output_lines.append(line)

        process.wait()

        if process.returncode == 0:
            print(f"\n[✓] Scan completed successfully.")
            return xml_output, "\n".join(output_lines)
        else:
            print(f"\n[✗] Scan failed with return code {process.returncode}")
            return None, "\n".join(output_lines)

    except PermissionError:
        print("[✗] Permission denied. Some scan types require root: sudo python3 scanner.py ...")
        return None, ""
    except Exception as e:
        print(f"[✗] Scan error: {e}")
        return None, ""


def parse_nmap_xml(xml_file):
    """Parse Nmap XML output using Python's xml library."""
    import xml.etree.ElementTree as ET

    if not os.path.exists(xml_file):
        print(f"[✗] XML file not found: {xml_file}")
        return None

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"[✗] Failed to parse XML: {e}")
        return None

    scan_data = {
        "scan_info": {},
        "hosts": [],
        "summary": {}
    }

    # Scan metadata
    nmaprun = root.attrib
    scan_data["scan_info"] = {
        "scanner": nmaprun.get("scanner", "nmap"),
        "version": nmaprun.get("version", "unknown"),
        "args": nmaprun.get("args", ""),
        "start_time": nmaprun.get("startstr", ""),
        "elapsed": ""
    }

    runstats = root.find("runstats")
    if runstats is not None:
        finished = runstats.find("finished")
        if finished is not None:
            scan_data["scan_info"]["elapsed"] = finished.get("elapsed", "")
            scan_data["scan_info"]["end_time"] = finished.get("timestr", "")

        hosts_elem = runstats.find("hosts")
        if hosts_elem is not None:
            scan_data["summary"] = {
                "up": hosts_elem.get("up", "0"),
                "down": hosts_elem.get("down", "0"),
                "total": hosts_elem.get("total", "0"),
            }

    # Parse hosts
    for host in root.findall("host"):
        host_data = {
            "status": "",
            "ip": "",
            "hostname": "",
            "os": "",
            "ports": [],
            "scripts": []
        }

        # Status
        status = host.find("status")
        if status is not None:
            host_data["status"] = status.get("state", "")

        # Addresses
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                host_data["ip"] = addr.get("addr", "")
            elif addr.get("addrtype") == "mac":
                host_data["mac"] = addr.get("addr", "")

        # Hostnames
        hostnames = host.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                host_data["hostname"] = hn.get("name", "")

        # OS Detection
        os_elem = host.find("os")
        if os_elem is not None:
            osmatch = os_elem.find("osmatch")
            if osmatch is not None:
                host_data["os"] = f"{osmatch.get('name', '')} (accuracy: {osmatch.get('accuracy', '')}%)"

        # Ports
        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                state = port.find("state")
                service = port.find("service")

                port_data = {
                    "port": port.get("portid", ""),
                    "protocol": port.get("protocol", ""),
                    "state": state.get("state", "") if state is not None else "",
                    "service": service.get("name", "") if service is not None else "",
                    "version": "",
                    "product": "",
                    "extra_info": "",
                    "scripts": []
                }

                if service is not None:
                    port_data["product"] = service.get("product", "")
                    port_data["version"] = service.get("version", "")
                    port_data["extra_info"] = service.get("extrainfo", "")

                # Port scripts (NSE)
                for script in port.findall("script"):
                    port_data["scripts"].append({
                        "id": script.get("id", ""),
                        "output": script.get("output", "")
                    })

                host_data["ports"].append(port_data)

        # Host-level scripts
        hostscript = host.find("hostscript")
        if hostscript is not None:
            for script in hostscript.findall("script"):
                host_data["scripts"].append({
                    "id": script.get("id", ""),
                    "output": script.get("output", "")
                })

        scan_data["hosts"].append(host_data)

    return scan_data


def demo_scan(target):
    """Generate a simulated scan result for demo/testing without actual Nmap."""
    print(f"\n[*] Running DEMO scan on target: {target}")
    print("[*] (Simulated results - install Nmap for real scanning)")
    print("-" * 60)

    import time
    time.sleep(1)
    print("Starting Nmap 7.94 ( https://nmap.org )")
    time.sleep(0.5)
    print(f"Nmap scan report for {target}")
    print("Host is up (0.0023s latency).")
    time.sleep(0.3)
    print("Not shown: 994 closed ports")
    print("PORT     STATE SERVICE     VERSION")
    print("22/tcp   open  ssh         OpenSSH 8.2p1")
    print("80/tcp   open  http        Apache httpd 2.4.41")
    print("443/tcp  open  https       Apache httpd 2.4.41")
    print("3306/tcp open  mysql       MySQL 5.7.33")
    print("8080/tcp open  http-proxy  Squid http proxy 4.10")
    time.sleep(0.5)
    print("\nNmap done: 1 IP address (1 host up) scanned in 4.23 seconds")

    # Return simulated structured data
    return {
        "scan_info": {
            "scanner": "nmap",
            "version": "7.94 (demo)",
            "args": f"nmap -sV -sC -T4 {target}",
            "start_time": datetime.now().strftime("%a %b %d %H:%M:%S %Y"),
            "end_time": datetime.now().strftime("%a %b %d %H:%M:%S %Y"),
            "elapsed": "4.23"
        },
        "hosts": [
            {
                "status": "up",
                "ip": target if re.match(r'\d+\.\d+\.\d+\.\d+', target) else "192.168.1.100",
                "hostname": target if not re.match(r'\d+\.\d+\.\d+\.\d+', target) else "",
                "os": "Linux 4.x (Ubuntu) (accuracy: 95%)",
                "ports": [
                    {"port": "22", "protocol": "tcp", "state": "open", "service": "ssh",
                     "product": "OpenSSH", "version": "8.2p1", "extra_info": "Ubuntu",
                     "scripts": [{"id": "ssh-hostkey", "output": "RSA 3072 sha256:..."}]},
                    {"port": "80", "protocol": "tcp", "state": "open", "service": "http",
                     "product": "Apache httpd", "version": "2.4.41", "extra_info": "",
                     "scripts": [{"id": "http-title", "output": "Apache2 Ubuntu Default Page"}]},
                    {"port": "443", "protocol": "tcp", "state": "open", "service": "https",
                     "product": "Apache httpd", "version": "2.4.41", "extra_info": "",
                     "scripts": [{"id": "ssl-cert", "output": "Subject: commonName=localhost"}]},
                    {"port": "3306", "protocol": "tcp", "state": "open", "service": "mysql",
                     "product": "MySQL", "version": "5.7.33", "extra_info": "",
                     "scripts": [{"id": "mysql-info", "output": "Protocol: 10\n  Version: 5.7.33"}]},
                    {"port": "8080", "protocol": "tcp", "state": "open", "service": "http-proxy",
                     "product": "Squid http proxy", "version": "4.10", "extra_info": "",
                     "scripts": []},
                ],
                "scripts": []
            }
        ],
        "summary": {"up": "1", "down": "0", "total": "1"}
    }


def main():
    parser = argparse.ArgumentParser(
        description="Automated Vulnerability Scanner & Report Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scanner.py --target 192.168.1.1
  python3 scanner.py --target 192.168.1.0/24 --scan-type full
  python3 scanner.py --target example.com --ports 80,443,8080
  python3 scanner.py --target 10.0.0.1 --demo
  python3 scanner.py --target scanme.nmap.org --report-format html
        """
    )
    parser.add_argument("--target", "-t", required=True,
                        help="Target IP, hostname, or CIDR range")
    parser.add_argument("--scan-type", "-s", default="standard",
                        choices=["quick", "standard", "full", "stealth"],
                        help="Scan intensity/type (default: standard)")
    parser.add_argument("--ports", "-p", default=None,
                        help="Specific ports to scan (e.g., 22,80,443 or 1-1024)")
    parser.add_argument("--report-format", "-f", default="both",
                        choices=["txt", "json", "html", "both"],
                        help="Report output format (default: both)")
    parser.add_argument("--output-dir", "-o", default="reports",
                        help="Directory for output files (default: reports/)")
    parser.add_argument("--demo", action="store_true",
                        help="Run in demo mode with simulated results (no Nmap needed)")

    args = parser.parse_args()

    print("=" * 60)
    print("  AUTOMATED VULNERABILITY SCANNER & REPORT GENERATOR")
    print("=" * 60)

    os.makedirs(args.output_dir, exist_ok=True)

    if args.demo:
        scan_data = demo_scan(args.target)
    else:
        if not check_nmap():
            print("\n[!] Tip: Run with --demo flag to test without Nmap")
            sys.exit(1)

        xml_file, raw_output = run_nmap_scan(
            args.target,
            scan_type=args.scan_type,
            ports=args.ports,
            output_file=f"{args.output_dir}/scan_{re.sub(r'[^a-zA-Z0-9._-]', '_', args.target)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
        )

        if not xml_file:
            print("[✗] Scan failed. Check permissions or target.")
            sys.exit(1)

        print(f"\n[*] Parsing scan results from: {xml_file}")
        scan_data = parse_nmap_xml(xml_file)

    if not scan_data:
        print("[✗] No scan data to process.")
        sys.exit(1)

    # Analyze vulnerabilities
    print("\n[*] Analyzing vulnerabilities...")
    analyzer = VulnerabilityAnalyzer()
    scan_data = analyzer.analyze(scan_data)

    # Generate reports
    print("[*] Generating security report...")
    generator = ReportGenerator(scan_data, args.target, args.output_dir)

    generated = []
    if args.report_format in ("txt", "both"):
        txt_path = generator.generate_text_report()
        generated.append(txt_path)

    if args.report_format in ("json", "both"):
        json_path = generator.generate_json_report()
        generated.append(json_path)

    if args.report_format == "html":
        html_path = generator.generate_html_report()
        generated.append(html_path)

    print("\n" + "=" * 60)
    print("  SCAN COMPLETE")
    print("=" * 60)
    print(f"  Target:       {args.target}")
    print(f"  Hosts Found:  {scan_data['summary'].get('up', 0)} up / {scan_data['summary'].get('total', 0)} total")
    total_ports = sum(len(h['ports']) for h in scan_data['hosts'])
    total_vulns = sum(len(h.get('vulnerabilities', [])) for h in scan_data['hosts'])
    print(f"  Open Ports:   {total_ports}")
    print(f"  Findings:     {total_vulns}")
    print(f"\n  Reports saved:")
    for f in generated:
        print(f"    → {f}")
    print("=" * 60)


if __name__ == "__main__":
    main()
