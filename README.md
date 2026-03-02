# Automated Vulnerability Scanner & Report Generator

A Python-based network vulnerability assessment tool that automates Nmap scanning and generates structured security reports.

## Features

- **Automated Nmap Scanning** — Supports quick, standard, full, and stealth scan profiles
- **Vulnerability Analysis** — Identifies risky ports, vulnerable service versions, and CVE matches
- **Multi-Format Reports** — Outputs TXT (human-readable), JSON (machine-readable), and HTML (visual) reports
- **Demo Mode** — Run without Nmap installed to test the report pipeline

## Project Structure

```
vuln_scanner/
├── scanner.py                  # Main entry point
├── modules/
│   ├── vulnerability_analyzer.py  # Vulnerability detection logic
│   └── report_generator.py        # TXT / JSON / HTML report generation
├── reports/                    # Output directory (auto-created)
└── README.md
```

## Requirements

```bash
pip install python3  # Python 3.7+
sudo apt install nmap  # Nmap (required for real scans)
```

## Usage

### Demo Mode (no Nmap needed)
```bash
python3 scanner.py --target 192.168.1.1 --demo
```

### Standard Scan
```bash
python3 scanner.py --target 192.168.1.1
```

### Full Scan with HTML Report
```bash
sudo python3 scanner.py --target 192.168.1.1 --scan-type full --report-format html
```

### Scan Specific Ports
```bash
python3 scanner.py --target 10.0.0.1 --ports 22,80,443,3306,8080
```

### Scan a Network Range
```bash
sudo python3 scanner.py --target 192.168.1.0/24 --scan-type quick
```

## Scan Types

| Type     | Description                               | Speed  |
|----------|-------------------------------------------|--------|
| quick    | Top 100 ports, no version detection       | Fast   |
| standard | Top 1000 ports, service/version detection | Medium |
| full     | All ports, OS detection, scripts          | Slow   |
| stealth  | SYN scan, requires root                   | Slow   |

## Report Formats

- **TXT** — Human-readable text report with all findings
- **JSON** — Structured data for integration with other tools
- **HTML** — Visual report with color-coded severity ratings

## Vulnerability Detection

The analyzer checks for:
- Risky exposed services (FTP, Telnet, RDP, SMB, Redis, MongoDB, etc.)
- Known vulnerable software versions with CVE references
- NSE script findings from Nmap
- SSL/TLS misconfigurations
- Anonymous authentication

## Ethical Use

This tool is for **authorized security assessments only**. Only scan systems you own or have explicit written permission to test. Unauthorized scanning may violate laws including the Computer Fraud and Abuse Act (CFAA).

## Skills Demonstrated

- Python automation and subprocess management
- Nmap integration and XML parsing
- Network security fundamentals
- Structured security reporting
- Linux scanning workflows
- CVE database concepts
