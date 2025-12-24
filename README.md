# ReconMaster Pro v2.0

<div align="center">

```
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║          ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗     ║
║          ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║     ║
║          ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║     ║
║          ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║     ║
║          ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║     ║
║          ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝     ║
║                                                           ║
║              M A S T E R   P R O   v2.0.0                 ║
║          All-in-One Reconnaissance Suite                  ║
╚═══════════════════════════════════════════════════════════╝
```

**The Ultimate All-in-One Reconnaissance Toolkit**

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)
![Version](https://img.shields.io/badge/Version-2.0.0-orange.svg)

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Documentation](#-documentation) • [Examples](#-examples)

</div>

---

## 🎯 Overview

**ReconMaster Pro** is a cutting-edge, all-in-one reconnaissance framework designed for security professionals, penetration testers, bug bounty hunters, and red team operators. Combining multiple OSINT and reconnaissance techniques into a single, powerful tool with a beautiful Terminal User Interface (TUI).

Built entirely from scratch in Python, it consolidates hours of manual reconnaissance work into automated, streamlined workflows.

### ⚡ Why ReconMaster Pro?

- **All-in-One Solution** - No need for multiple tools
- **Beautiful TUI** - Intuitive terminal interface with progress tracking
- **Production Ready** - Enterprise-grade error handling and retry logic
- **Multiple Export Formats** - TXT, JSON, CSV support
- **Session Management** - Save and resume scans
- **Zero Dependencies (Almost)** - Just Python + Rich library
- **Single File** - Deploy anywhere in seconds

---

## ✨ Features

### 🔍 Core Modules

| Module | Description | Key Features |
|--------|-------------|--------------|
| **CT Scanner** | Certificate Transparency subdomain discovery | Multiple CT log sources, auto-retry, wildcard cleaning |
| **GitHub Secret Scanner** | Leaked credentials & API key detection | 15+ secret patterns, entropy analysis, confidence scoring |
| **Company Intel** | OSINT intelligence gathering | Email enumeration, tech stack detection, social media discovery |
| **Host Validator** | Live host verification | Multi-threaded, HTTP/HTTPS/DNS validation, title extraction |
| **WHOIS Lookup** | Domain registration information | Registrar, dates, nameservers extraction |
| **Port Scanner** | Common port enumeration | 13 common ports, service detection |

### 🎨 Advanced Capabilities

- **Entropy Analysis** - Detect high-entropy secrets automatically
- **Multi-threaded Operations** - Fast concurrent scanning (15 workers)
- **Retry Logic** - Automatic retries with exponential backoff
- **Session Persistence** - Save/load scan sessions
- **Multiple Export Formats** - TXT, JSON, CSV
- **Real Web Scraping** - Extract emails and tech from websites
- **Progress Tracking** - Beautiful progress bars and status indicators
- **Error Recovery** - Graceful handling of failures

### 📊 Secret Detection Patterns

ReconMaster Pro can detect **15+ types** of sensitive information:

- AWS Access Keys & Secret Keys
- GitHub Personal Access Tokens (Classic & Fine-grained)
- Google API Keys
- Slack Tokens & Webhooks
- Stripe API Keys
- SendGrid API Keys
- Twilio API Keys
- JWT Tokens
- Database Connection Strings (MongoDB, PostgreSQL, MySQL, Redis)
- Private SSH Keys
- Generic API Keys & Secrets
- Hardcoded Passwords
- And more...

---

## 🚀 Installation

### Prerequisites

- **Python 3.8+** (Python 3.10+ recommended)
- **pip** (Python package manager)
- **whois** command-line tool (optional, for WHOIS lookups)

### Quick Install

```bash
# Clone or download the tool
git clone https://github.com/yourusername/reconmaster-pro.git
cd reconmaster-pro

# Install dependencies
pip3 install rich requests

# Make executable
chmod +x recon_suite.py

# Run it!
./recon_suite.py
```

### Manual Install

```bash
# Download single file
wget https://raw.githubusercontent.com/yourusername/reconmaster-pro/main/recon_suite.py

# Install dependencies
pip3 install rich requests

# Make executable
chmod +x recon_suite.py
```

### Dependencies

```bash
pip3 install rich requests
```

That's it! Only 2 dependencies required.

---

## 📖 Usage

### Interactive Mode (Recommended)

Launch the beautiful TUI interface:

```bash
./recon_suite.py
```

**Interactive Menu:**
```
═══ Main Menu ═══
[1]  Set Target Domain/Company
[2]  Certificate Transparency Scan
[3]  GitHub Secret Scan
[4]  Company Intelligence Gathering
[5]  Validate Live Hosts
[6]  WHOIS Lookup
[7]  Port Scan (Live Hosts)
[8]  Run All Modules
[9]  Display Results
[10] Generate Report (TXT)
[11] Export to JSON
[12] Export to CSV
[13] Save Session
[14] Load Session
[15] Exit
```

### Command-Line Mode

For automation and integration:

```bash
# Full reconnaissance
./recon_suite.py -t example.com --all

# Specific modules
./recon_suite.py -t example.com --ct --github
./recon_suite.py -t example.com --intel --whois

# With output
./recon_suite.py -t example.com --all -o report.txt

# Export to JSON/CSV
./recon_suite.py -t example.com --all --json --csv

# Use GitHub token (recommended)
./recon_suite.py -t example.com --github --github-token ghp_yourtoken

# Save session for later
./recon_suite.py -t example.com --all --save myscan.json

# Resume previous session
./recon_suite.py --load myscan.json
```

### Command-Line Arguments

```
-t, --target TARGET        Target domain or company name
--ct                       Certificate Transparency scan
--github                   GitHub secret scan
--intel                    Company intelligence gathering
--validate                 Validate live hosts
--whois                    WHOIS lookup
--ports                    Port scanning
--all                      Run all modules
-o, --output FILE          Report filename (TXT)
--json                     Export to JSON
--csv                      Export to CSV
--github-token TOKEN       GitHub API token
--save FILE                Save session
--load FILE                Load session
```

---

## 💡 Examples

### Example 1: Basic Subdomain Discovery

```bash
./recon_suite.py -t tesla.com --ct --validate
```

**Output:**
```
✓ Found 127 subdomains
✓ Found 43 live hosts

Discovered Subdomains
┌────────────────────────────┬──────────┬─────────────────┐
│ Subdomain                  │ Status   │ IP              │
├────────────────────────────┼──────────┼─────────────────┤
│ www.tesla.com              │ live     │ 23.227.38.64    │
│ shop.tesla.com             │ live     │ 184.25.56.182   │
│ www.tesla.com              │ live     │ 23.227.38.64    │
└────────────────────────────┴──────────┴─────────────────┘
```

### Example 2: GitHub Secret Hunting

```bash
./recon_suite.py -t "acme-corp" --github --github-token ghp_xxxxx
```

**Output:**
```
✓ Found 8 potential secrets

GitHub Secrets Found
┌─────────────────────┬──────────────────────┬──────────────────┬────────────┐
│ Type                │ Repository           │ File             │ Confidence │
├─────────────────────┼──────────────────────┼──────────────────┼────────────┤
│ AWS Access Key      │ acme-corp/backend    │ config/aws.yml   │ High       │
│ Sensitive Config    │ acme-corp/api        │ .env             │ High       │
│ GitHub Token        │ acme-corp/scripts    │ deploy.sh        │ Medium     │
└─────────────────────┴──────────────────────┴──────────────────┴────────────┘
```

### Example 3: Full Automated Scan

```bash
./recon_suite.py -t hackerone.com --all --json -o hackerone_report.txt
```

**Performs:**
1. WHOIS lookup
2. CT subdomain enumeration
3. GitHub secret scanning
4. Company intelligence gathering
5. Live host validation
6. Generates TXT report
7. Exports JSON data
8. Saves session automatically

### Example 4: Resume Previous Scan

```bash
# Start scan (interrupted midway)
./recon_suite.py -t example.com --all --save scan.json

# Resume later
./recon_suite.py --load scan.json
```

---

## 📋 Output Formats

### Text Report

Comprehensive, human-readable report:

```
================================================================================
RECONNAISSANCE REPORT - example.com
Generated: 2025-12-23 14:32:15
ReconMaster Pro v2.0.0
================================================================================

[+] WHOIS INFORMATION
--------------------------------------------------------------------------------
  REGISTRAR: MarkMonitor Inc.
  CREATION_DATE: 1995-08-14T04:00:00Z
  EXPIRATION_DATE: 2025-08-13T04:00:00Z

[+] SUBDOMAINS DISCOVERED
--------------------------------------------------------------------------------
  Total: 127
  - www.example.com [live] (93.184.216.34)
  - mail.example.com [live] (93.184.216.35)
  ...

[+] GITHUB SECRETS/LEAKS
--------------------------------------------------------------------------------
  Total: 3
  Type: AWS Access Key
  Repo: example-org/backend
  File: config/credentials.yml
  Confidence: High
  URL:  https://github.com/example-org/backend/blob/main/config/credentials.yml
  ...
```

### JSON Export

Structured data for integration:

```json
{
  "target": "example.com",
  "timestamp": "2025-12-23T14:32:15.123456",
  "version": "2.0.0",
  "results": {
    "subdomains": ["www.example.com", "api.example.com"],
    "live_hosts": {
      "www.example.com": {
        "status": "live",
        "protocol": "https",
        "status_code": 200,
        "ip": "93.184.216.34",
        "server": "nginx"
      }
    },
    "git_secrets": [...],
    "emails": [...],
    "technologies": [...],
    "whois": {...}
  }
}
```

### CSV Export

Perfect for spreadsheet analysis:

```csv
SUBDOMAINS
Domain,Status,IP,Protocol,Status Code
www.example.com,live,93.184.216.34,https,200
api.example.com,live,93.184.216.35,https,200

GITHUB SECRETS
Type,Repository,File,URL,Confidence
AWS Access Key,example-org/backend,config/aws.yml,https://...,High
```

---

## 🔧 Advanced Usage

### GitHub Token Setup

For unlimited API requests and better results:

1. Go to https://github.com/settings/tokens
2. Click "Generate new token (classic)"
3. Select scopes: `public_repo`, `read:org`, `read:user`
4. Copy token and use:

```bash
./recon_suite.py -t target.com --github --github-token ghp_yourtoken
```

### Workflow Examples

**Bug Bounty Workflow:**
```bash
# 1. Initial recon
./recon_suite.py -t target.com --ct --save target_scan.json

# 2. Validate and scan
./recon_suite.py --load target_scan.json
# Then select option 5 (Validate Live Hosts) in TUI
# Then select option 7 (Port Scan)

# 3. Look for secrets
./recon_suite.py -t "target-company" --github --github-token ghp_xxx

# 4. Generate final report
./recon_suite.py --load target_scan.json
# Select option 10 (Generate Report)
```

**Red Team Workflow:**
```bash
# Silent, comprehensive scan
./recon_suite.py -t corporation.com --all --json --csv -o corp_intel.txt

# Review results
cat corp_intel.txt

# Export to other tools
cat recon_export_*.json | jq '.results.live_hosts'
```

---

## 🛡️ Legal & Ethical Use

### ⚠️ IMPORTANT DISCLAIMER

This tool is designed for **AUTHORIZED SECURITY TESTING ONLY**.

### ✅ Authorized Use Cases

- Penetration testing with **written permission**
- Bug bounty programs (within scope)
- Security research on **your own** infrastructure
- Red team exercises with proper authorization
- Educational purposes in controlled environments
- CTF competitions
- Defensive security operations

### ❌ Prohibited Activities

- Scanning targets without explicit authorization
- Violating terms of service
- Unauthorized access to systems
- Data theft or malicious reconnaissance
- Any illegal activities

**You are solely responsible for your use of this tool. Always obtain proper authorization before scanning.**

---

## 🎓 How It Works

### Certificate Transparency Scanner

1. Queries public CT log APIs (crt.sh, etc.)
2. Extracts all certificate entries for target domain
3. Parses `name_value` and `common_name` fields
4. Cleans wildcards and duplicates
5. Returns unique subdomain list

### GitHub Secret Scanner

1. Searches GitHub API for target-related repositories
2. Looks for sensitive filename patterns (`.env`, `credentials.json`, etc.)
3. Performs pattern matching for known secret types
4. Calculates Shannon entropy for confidence scoring
5. Deduplicates and returns findings with URLs

### Company Intelligence

1. Generates common email patterns
2. Attempts to scrape company website
3. Extracts emails using regex
4. Detects technologies from HTML/headers
5. Checks social media presence (LinkedIn, Twitter, GitHub)

### Live Host Validator

1. Resolves DNS for each subdomain
2. Tests HTTPS connectivity (preferred)
3. Falls back to HTTP if needed
4. Extracts server headers and page titles
5. Optionally scans common ports
6. Multi-threaded for performance

---

## 📊 Performance

- **Subdomain Discovery**: ~50-200 subdomains/minute (depends on CT logs)
- **Live Host Validation**: ~15 hosts/second (15 concurrent threads)
- **GitHub Scanning**: ~5 repos/minute (API rate limits)
- **Port Scanning**: ~100 ports/second
- **Memory Usage**: <100MB typical
- **CPU Usage**: Moderate (multi-threaded)

---

## 🐛 Troubleshooting

### "ModuleNotFoundError: No module named 'rich'"

```bash
pip3 install rich requests
# or
python3 -m pip install rich requests
```

### GitHub API Rate Limit

**Problem:** `403 Forbidden` or rate limit errors

**Solution:**
```bash
# Use a GitHub token
./recon_suite.py -t target.com --github --github-token ghp_yourtoken
```

### WHOIS Command Not Found

**Problem:** `whois: command not found`

**Solution:**
```bash
# Debian/Ubuntu
sudo apt install whois

# macOS
brew install whois

# RHEL/CentOS
sudo yum install jwhois
```

### Permission Denied

```bash
chmod +x recon_suite.py
```

### SSL Certificate Errors

```bash
pip3 install --upgrade certifi requests urllib3
```

---

## 🗺️ Roadmap

### Upcoming Features

- [ ] Shodan/Censys API integration
- [ ] Passive DNS lookups
- [ ] Wayback Machine integration
- [ ] Screenshot capture of live hosts
- [ ] Nuclei template execution
- [ ] Custom wordlist support
- [ ] VPN/Proxy support
- [ ] Email verification (SMTP)
- [ ] Advanced reporting (HTML, PDF)
- [ ] Integration with other tools (Amass, Subfinder)
- [ ] Distributed scanning
- [ ] Web dashboard
- [ ] Plugin system

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

### Reporting Issues

- Use GitHub Issues to report bugs
- Include reproduction steps
- Provide error messages and logs
- Mention your OS and Python version

### Suggesting Features

- Open a GitHub Issue with the `enhancement` label
- Describe the use case
- Explain why it would be valuable

### Code Contributions

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test thoroughly
5. Commit (`git commit -m 'Add amazing feature'`)
6. Push (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Code Style

- Follow PEP 8
- Add docstrings to functions
- Keep single-file architecture
- Minimize dependencies
- Add error handling

---

## 📄 License

```
MIT License

Copyright (c) 2025 DarkSec LabZ

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 🙏 Acknowledgments

- **Rich Library** - Beautiful terminal formatting by Will McGugan
- **crt.sh** - Certificate Transparency log database
- **GitHub API** - Code search capabilities
- **Python Community** - For amazing libraries and support

---

## 📧 Contact & Support

- **GitHub Issues**: Bug reports and feature requests
- **Security Issues**: Report privately via GitHub Security Advisories
- **Documentation**: See `/docs` folder for detailed guides

---

## ⭐ Star History

If you find this tool useful, please give it a star!

---

## 🎯 Quick Reference

### Essential Commands

```bash
# Interactive mode
./recon_suite.py

# Full scan
./recon_suite.py -t example.com --all

# Subdomain discovery only
./recon_suite.py -t example.com --ct --validate

# GitHub secrets only
./recon_suite.py -t "company" --github --github-token ghp_xxx

# Export all formats
./recon_suite.py -t example.com --all --json --csv -o report.txt

# Save and resume
./recon_suite.py -t example.com --all --save scan.json
./recon_suite.py --load scan.json
```

### One-Liner Install & Run

```bash
wget https://raw.githubusercontent.com/yourusername/reconmaster-pro/main/recon_suite.py && chmod +x recon_suite.py && pip3 install rich requests && ./recon_suite.py
```

---

<div align="center">

**Built with ❤️ by [DarkSec LabZ](https://github.com/yourusername)**

*Reconnaissance made simple, powerful, and beautiful.*

[⬆ Back to Top](#reconmaster-pro-v20)

</div>
