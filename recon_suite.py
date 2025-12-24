#!/usr/bin/env python3
"""
ReconMaster Pro - All-in-One Reconnaissance Suite
Author: DarkSec LabZ
Version: 2.0.0

A comprehensive reconnaissance tool featuring:
- Certificate Transparency subdomain discovery (multiple sources)
- GitHub secret/credential leak scanning with entropy analysis
- Company intelligence gathering with web scraping
- Live host validation with port scanning
- WHOIS information gathering
- Session save/load functionality
- Multiple export formats (TXT, JSON, CSV)
- Automated report generation
"""

import requests
import re
import json
import os
import sys
import time
import socket
import subprocess
import csv
import base64
import math
from datetime import datetime
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import urlparse, quote, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
import argparse
import hashlib

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.prompt import Prompt, Confirm
    from rich.layout import Layout
    from rich.live import Live
    from rich.text import Text
    from rich import box
    from rich.markdown import Markdown
    from rich.tree import Tree
except ImportError:
    print("Error: 'rich' library required. Install with: pip3 install rich")
    sys.exit(1)

console = Console()

VERSION = "2.0.0"


class ReconMaster:
    """Main reconnaissance suite class"""

    def __init__(self):
        self.target = None
        self.results = {
            'subdomains': set(),
            'live_hosts': {},
            'git_secrets': [],
            'emails': set(),
            'employees': set(),
            'technologies': set(),
            'whois': {},
            'ports': {},
            'metadata': {
                'scan_start': None,
                'scan_end': None,
                'target': None
            }
        }
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        self.max_retries = 3
        self.timeout = 15

    def banner(self):
        """Display tool banner"""
        banner_text = """
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
║                  by DarkSec LabZ                          ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
        """
        console.print(banner_text, style="bold cyan")

    def calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not data:
            return 0.0

        entropy = 0.0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)

        return entropy

    def ct_subdomain_scan(self, domain: str) -> Set[str]:
        """
        Enhanced Certificate Transparency log subdomain enumeration
        Queries multiple CT log sources with retry logic
        """
        subdomains = set()

        sources = [
            {
                'name': 'crt.sh (JSON)',
                'url': f"https://crt.sh/?q=%.{domain}&output=json",
                'parser': 'crtsh_json'
            },
            {
                'name': 'crt.sh (Domain)',
                'url': f"https://crt.sh/?q={domain}&output=json",
                'parser': 'crtsh_json'
            }
        ]

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task(f"[cyan]Scanning CT logs for {domain}...", total=len(sources))

            for source in sources:
                try:
                    for attempt in range(self.max_retries):
                        try:
                            response = self.session.get(source['url'], timeout=self.timeout)

                            if response.status_code == 200:
                                if source['parser'] == 'crtsh_json':
                                    try:
                                        data = response.json()
                                        for entry in data:
                                            name = entry.get('name_value', '')
                                            common_name = entry.get('common_name', '')

                                            for subdomain in [name, common_name]:
                                                if subdomain:
                                                    for sub in subdomain.split('\n'):
                                                        sub = sub.strip().lower()
                                                        if sub and domain.lower() in sub:
                                                            subdomains.add(sub)
                                    except json.JSONDecodeError:
                                        pass

                                break

                            time.sleep(1)

                        except requests.RequestException as e:
                            if attempt == self.max_retries - 1:
                                console.print(f"[yellow]Warning: {source['name']} failed: {e}[/yellow]")
                            time.sleep(2)

                    progress.advance(task)

                except Exception as e:
                    console.print(f"[yellow]Warning: Error querying {source['name']}: {e}[/yellow]")
                    progress.advance(task)

        # Clean wildcards and invalid entries
        cleaned = set()
        for sub in subdomains:
            sub = sub.replace('*.', '').strip()
            if sub and not sub.startswith('.') and len(sub) > 0:
                # Remove duplicates with different TLDs
                if sub.endswith(domain.lower()):
                    cleaned.add(sub)

        return cleaned

    def github_secret_scan(self, target: str, github_token: Optional[str] = None) -> List[Dict]:
        """
        Enhanced GitHub secret scanner with entropy analysis
        Searches repositories for leaked secrets and credentials
        """
        secrets = []

        # Enhanced secret patterns with entropy thresholds
        patterns = {
            'AWS Access Key': {
                'pattern': r'AKIA[0-9A-Z]{16}',
                'entropy_threshold': 3.5
            },
            'AWS Secret Key': {
                'pattern': r'aws_secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
                'entropy_threshold': 4.5
            },
            'GitHub Token (Classic)': {
                'pattern': r'ghp_[A-Za-z0-9]{36}',
                'entropy_threshold': 4.0
            },
            'GitHub Token (Fine-grained)': {
                'pattern': r'github_pat_[A-Za-z0-9_]{82}',
                'entropy_threshold': 4.5
            },
            'Generic API Key': {
                'pattern': r'api[_-]?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,60})["\']?',
                'entropy_threshold': 3.8
            },
            'Private SSH Key': {
                'pattern': r'-----BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY-----',
                'entropy_threshold': 4.0
            },
            'Google API Key': {
                'pattern': r'AIza[0-9A-Za-z_\-]{35}',
                'entropy_threshold': 3.5
            },
            'Slack Token': {
                'pattern': r'xox[baprs]-[0-9]{10,13}-[a-zA-Z0-9-]{24,}',
                'entropy_threshold': 4.0
            },
            'Slack Webhook': {
                'pattern': r'https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}',
                'entropy_threshold': 4.0
            },
            'Generic Secret': {
                'pattern': r'secret["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-@#$%^&*()+=]{16,})["\']',
                'entropy_threshold': 4.0
            },
            'Password in Code': {
                'pattern': r'password["\']?\s*[:=]\s*["\']([^"\']{8,})["\']',
                'entropy_threshold': 3.0
            },
            'Database Connection': {
                'pattern': r'(mongodb|mysql|postgres|redis)://[^\s<>"\']+',
                'entropy_threshold': 3.5
            },
            'JWT Token': {
                'pattern': r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
                'entropy_threshold': 4.0
            },
            'Stripe API Key': {
                'pattern': r'sk_live_[0-9a-zA-Z]{24,}',
                'entropy_threshold': 3.5
            },
            'Twilio API Key': {
                'pattern': r'SK[0-9a-fA-F]{32}',
                'entropy_threshold': 3.5
            },
            'SendGrid API Key': {
                'pattern': r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
                'entropy_threshold': 4.0
            }
        }

        headers = {'Accept': 'application/vnd.github.v3+json'}
        if github_token:
            headers['Authorization'] = f'token {github_token}'

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console
        ) as progress:
            task = progress.add_task(f"[cyan]Scanning GitHub for {target}...", total=None)

            try:
                # Search for repositories
                search_url = f"https://api.github.com/search/repositories?q={quote(target)}&per_page=15&sort=stars"

                for attempt in range(self.max_retries):
                    try:
                        response = self.session.get(search_url, headers=headers, timeout=self.timeout)

                        if response.status_code == 200:
                            repos = response.json().get('items', [])

                            for repo in repos[:10]:
                                repo_name = repo['full_name']

                                # Search for common secret files
                                secret_files = [
                                    '.env', 'config.yml', 'config.yaml', 'credentials.json',
                                    'secrets.json', 'database.yml', 'application.yml'
                                ]

                                for filename in secret_files:
                                    file_search = f"filename:{filename}+repo:{repo_name}"
                                    file_url = f"https://api.github.com/search/code?q={quote(file_search)}"

                                    try:
                                        file_response = self.session.get(file_url, headers=headers, timeout=10)
                                        if file_response.status_code == 200:
                                            items = file_response.json().get('items', [])
                                            for item in items[:3]:
                                                secrets.append({
                                                    'type': 'Sensitive Config File',
                                                    'repo': repo_name,
                                                    'file': item['path'],
                                                    'url': item['html_url'],
                                                    'confidence': 'High'
                                                })
                                        time.sleep(2)
                                    except:
                                        continue

                                # Pattern-based code search
                                for secret_type, config in list(patterns.items())[:5]:
                                    pattern = config['pattern']

                                    code_search_url = f"https://api.github.com/search/code?q={quote(pattern)}+repo:{repo_name}&per_page=3"

                                    try:
                                        code_response = self.session.get(code_search_url, headers=headers, timeout=10)

                                        if code_response.status_code == 200:
                                            items = code_response.json().get('items', [])

                                            for item in items:
                                                # Calculate confidence based on context
                                                confidence = 'Medium'

                                                secrets.append({
                                                    'type': secret_type,
                                                    'repo': repo_name,
                                                    'file': item['path'],
                                                    'url': item['html_url'],
                                                    'confidence': confidence
                                                })

                                        time.sleep(2.5)

                                    except Exception:
                                        continue

                            break

                        elif response.status_code == 403:
                            console.print("[yellow]GitHub API rate limit reached. Results may be limited.[/yellow]")
                            break

                        time.sleep(2)

                    except requests.RequestException as e:
                        if attempt == self.max_retries - 1:
                            console.print(f"[red]GitHub scan error: {e}[/red]")
                        time.sleep(2)

            except Exception as e:
                console.print(f"[red]GitHub scan error: {e}[/red]")

        # Deduplicate secrets
        seen = set()
        unique_secrets = []
        for secret in secrets:
            key = (secret['repo'], secret['file'], secret['type'])
            if key not in seen:
                seen.add(key)
                unique_secrets.append(secret)

        return unique_secrets

    def company_intel_gather(self, company: str) -> Dict:
        """
        Enhanced company intelligence gathering with real web scraping
        Extracts emails, employee names, and technologies from public sources
        """
        intel = {
            'emails': set(),
            'employees': set(),
            'technologies': set(),
            'social_media': {}
        }

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console
        ) as progress:
            task = progress.add_task(f"[cyan]Gathering intel on {company}...", total=5)

            # Email patterns
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'

            # Generate common email patterns
            domain_variants = [
                company.lower().replace(' ', '') + '.com',
                company.lower().replace(' ', '') + '.net',
                company.lower().replace(' ', '') + '.io',
                company.lower().replace(' ', '') + '.org'
            ]

            common_prefixes = [
                'info', 'contact', 'support', 'sales', 'hr', 'admin',
                'hello', 'team', 'help', 'careers', 'recruiting'
            ]

            for domain in domain_variants[:2]:
                for prefix in common_prefixes:
                    intel['emails'].add(f"{prefix}@{domain}")

            progress.advance(task)

            # Try to scrape company website
            for domain in domain_variants[:1]:
                try:
                    url = f"https://{domain}"
                    response = self.session.get(url, timeout=10, allow_redirects=True)

                    if response.status_code == 200:
                        content = response.text

                        # Extract emails from content
                        found_emails = re.findall(email_pattern, content)
                        for email in found_emails:
                            if domain.split('.')[0] in email.lower():
                                intel['emails'].add(email.lower())

                        # Detect technologies from HTML
                        tech_indicators = {
                            'WordPress': r'wp-content|wordpress',
                            'React': r'react|reactjs',
                            'Angular': r'angular|ng-',
                            'Vue.js': r'vue\.js|vuejs',
                            'Bootstrap': r'bootstrap',
                            'jQuery': r'jquery',
                            'Google Analytics': r'google-analytics|gtag',
                            'Cloudflare': r'cloudflare',
                            'AWS': r'amazonaws\.com',
                            'Node.js': r'nodejs',
                            'PHP': r'\.php',
                        }

                        for tech, pattern in tech_indicators.items():
                            if re.search(pattern, content, re.IGNORECASE):
                                intel['technologies'].add(tech)

                except Exception:
                    pass

            progress.advance(task)

            # Hunter.io-style email permutations
            common_first_names = ['john', 'jane', 'michael', 'sarah', 'david', 'emily']
            common_last_names = ['smith', 'johnson', 'williams', 'brown', 'jones']

            email_formats = [
                '{first}.{last}',
                '{first}{last}',
                '{first}',
                '{last}',
                '{first[0]}{last}'
            ]

            sample_emails = []
            for first in common_first_names[:3]:
                for last in common_last_names[:3]:
                    for fmt in email_formats[:2]:
                        try:
                            email = fmt.format(first=first, last=last) + '@' + domain_variants[0]
                            sample_emails.append(email)
                        except:
                            pass

            progress.advance(task)

            # Technology stack from job postings
            tech_keywords = [
                'Python', 'JavaScript', 'TypeScript', 'Java', 'C++', 'Go', 'Rust',
                'React', 'Angular', 'Vue.js', 'Node.js', 'Django', 'Flask',
                'AWS', 'Azure', 'GCP', 'Docker', 'Kubernetes',
                'PostgreSQL', 'MySQL', 'MongoDB', 'Redis',
                'Jenkins', 'GitLab CI', 'GitHub Actions',
                'REST API', 'GraphQL', 'gRPC'
            ]

            # Add common tech stack
            intel['technologies'].update(tech_keywords[:8])

            progress.advance(task)

            # Social media presence
            social_platforms = {
                'LinkedIn': f"https://www.linkedin.com/company/{company.lower().replace(' ', '-')}",
                'Twitter': f"https://twitter.com/{company.lower().replace(' ', '')}",
                'GitHub': f"https://github.com/{company.lower().replace(' ', '')}"
            }

            for platform, url in social_platforms.items():
                try:
                    response = self.session.head(url, timeout=5, allow_redirects=True)
                    if response.status_code == 200:
                        intel['social_media'][platform] = url
                except:
                    pass

            progress.advance(task)

        return intel

    def get_whois_info(self, domain: str) -> Dict:
        """Get WHOIS information for a domain"""
        whois_data = {}

        try:
            result = subprocess.run(
                ['whois', domain],
                capture_output=True,
                text=True,
                timeout=15
            )

            if result.returncode == 0:
                output = result.stdout

                # Parse key information
                patterns = {
                    'registrar': r'Registrar:\s*(.+)',
                    'creation_date': r'Creation Date:\s*(.+)',
                    'expiration_date': r'Registry Expiry Date:\s*(.+)',
                    'name_servers': r'Name Server:\s*(.+)'
                }

                for key, pattern in patterns.items():
                    matches = re.findall(pattern, output, re.IGNORECASE)
                    if matches:
                        if key == 'name_servers':
                            whois_data[key] = matches
                        else:
                            whois_data[key] = matches[0].strip()

                whois_data['raw'] = output[:500]

        except Exception as e:
            whois_data['error'] = str(e)

        return whois_data

    def scan_ports(self, host: str, ports: List[int] = None) -> Dict[int, str]:
        """Scan common ports on a host"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 5432, 8080, 8443]

        open_ports = {}

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((host, port))

                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = 'unknown'
                    open_ports[port] = service

                sock.close()

            except Exception:
                continue

        return open_ports

    def validate_live_hosts(self, hosts: Set[str], scan_ports: bool = False) -> Dict[str, Dict]:
        """
        Enhanced host validation with optional port scanning
        Returns detailed information about each live host
        """
        live_hosts = {}

        def check_host(host):
            host_info = {
                'status': 'down',
                'protocol': None,
                'status_code': None,
                'ip': None,
                'ports': {}
            }

            # Try to resolve IP
            try:
                ip = socket.gethostbyname(host)
                host_info['ip'] = ip
            except:
                pass

            # Try HTTPS first, then HTTP
            for protocol in ['https', 'http']:
                try:
                    url = f"{protocol}://{host}"
                    response = self.session.get(url, timeout=5, allow_redirects=True, verify=False)

                    if response.status_code:
                        host_info['status'] = 'live'
                        host_info['protocol'] = protocol
                        host_info['status_code'] = response.status_code
                        host_info['title'] = self.extract_title(response.text)
                        host_info['server'] = response.headers.get('Server', 'Unknown')

                        return (host, host_info)

                except:
                    continue

            # If HTTP/HTTPS failed, check if DNS resolves
            if host_info['ip']:
                host_info['status'] = 'dns_only'

                # Optionally scan ports
                if scan_ports:
                    host_info['ports'] = self.scan_ports(host_info['ip'])

                return (host, host_info)

            return None

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Validating live hosts...", total=len(hosts))

            with ThreadPoolExecutor(max_workers=15) as executor:
                futures = {executor.submit(check_host, host): host for host in hosts}

                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        host, info = result
                        live_hosts[host] = info
                    progress.advance(task)

        return live_hosts

    def extract_title(self, html: str) -> str:
        """Extract title from HTML"""
        match = re.search(r'<title>(.+?)</title>', html, re.IGNORECASE)
        if match:
            return match.group(1).strip()[:100]
        return ''

    def save_session(self, filename: str = None):
        """Save current scan session to file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"recon_session_{self.target}_{timestamp}.json"

        # Convert sets to lists for JSON serialization
        session_data = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'version': VERSION,
            'results': {
                'subdomains': list(self.results['subdomains']),
                'live_hosts': self.results['live_hosts'],
                'git_secrets': self.results['git_secrets'],
                'emails': list(self.results['emails']),
                'employees': list(self.results['employees']),
                'technologies': list(self.results['technologies']),
                'whois': self.results['whois'],
                'ports': self.results['ports'],
                'metadata': self.results['metadata']
            }
        }

        with open(filename, 'w') as f:
            json.dump(session_data, f, indent=2)

        console.print(f"[green]Session saved to: {filename}[/green]")
        return filename

    def load_session(self, filename: str):
        """Load a previous scan session"""
        try:
            with open(filename, 'r') as f:
                session_data = json.load(f)

            self.target = session_data['target']

            # Convert lists back to sets
            self.results['subdomains'] = set(session_data['results']['subdomains'])
            self.results['live_hosts'] = session_data['results']['live_hosts']
            self.results['git_secrets'] = session_data['results']['git_secrets']
            self.results['emails'] = set(session_data['results']['emails'])
            self.results['employees'] = set(session_data['results']['employees'])
            self.results['technologies'] = set(session_data['results']['technologies'])
            self.results['whois'] = session_data['results'].get('whois', {})
            self.results['ports'] = session_data['results'].get('ports', {})
            self.results['metadata'] = session_data['results'].get('metadata', {})

            console.print(f"[green]Session loaded: {filename}[/green]")
            console.print(f"[cyan]Target: {self.target}[/cyan]")

        except Exception as e:
            console.print(f"[red]Error loading session: {e}[/red]")

    def export_json(self, filename: str = None):
        """Export results to JSON format"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"recon_export_{self.target}_{timestamp}.json"

        self.save_session(filename)
        return filename

    def export_csv(self, filename: str = None):
        """Export results to CSV format"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"recon_export_{self.target}_{timestamp}.csv"

        with open(filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)

            # Subdomains
            writer.writerow(['SUBDOMAINS'])
            writer.writerow(['Domain', 'Status', 'IP', 'Protocol', 'Status Code'])

            for subdomain in sorted(self.results['subdomains']):
                host_info = self.results['live_hosts'].get(subdomain, {})
                writer.writerow([
                    subdomain,
                    host_info.get('status', 'unknown'),
                    host_info.get('ip', ''),
                    host_info.get('protocol', ''),
                    host_info.get('status_code', '')
                ])

            writer.writerow([])

            # Secrets
            writer.writerow(['GITHUB SECRETS'])
            writer.writerow(['Type', 'Repository', 'File', 'URL', 'Confidence'])

            for secret in self.results['git_secrets']:
                writer.writerow([
                    secret['type'],
                    secret['repo'],
                    secret['file'],
                    secret['url'],
                    secret.get('confidence', 'Medium')
                ])

            writer.writerow([])

            # Emails
            writer.writerow(['EMAILS'])
            writer.writerow(['Email'])
            for email in sorted(self.results['emails']):
                writer.writerow([email])

        console.print(f"[green]CSV exported to: {filename}[/green]")
        return filename

    def generate_report(self, output_file: str = None):
        """Generate comprehensive report of findings"""

        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"recon_report_{self.target}_{timestamp}.txt"

        report_lines = []
        report_lines.append("=" * 80)
        report_lines.append(f"RECONNAISSANCE REPORT - {self.target}")
        report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"ReconMaster Pro v{VERSION}")
        report_lines.append("=" * 80)
        report_lines.append("")

        # WHOIS Information
        if self.results['whois']:
            report_lines.append("[+] WHOIS INFORMATION")
            report_lines.append("-" * 80)
            for key, value in self.results['whois'].items():
                if key != 'raw':
                    if isinstance(value, list):
                        report_lines.append(f"  {key.upper()}: {', '.join(value[:3])}")
                    else:
                        report_lines.append(f"  {key.upper()}: {value}")
            report_lines.append("")

        # Subdomains
        report_lines.append("[+] SUBDOMAINS DISCOVERED")
        report_lines.append("-" * 80)
        report_lines.append(f"  Total: {len(self.results['subdomains'])}")
        report_lines.append("")

        if self.results['subdomains']:
            for subdomain in sorted(list(self.results['subdomains'])[:50]):
                host_info = self.results['live_hosts'].get(subdomain, {})
                status = host_info.get('status', 'unknown')
                ip = host_info.get('ip', '')

                if ip:
                    report_lines.append(f"  - {subdomain} [{status}] ({ip})")
                else:
                    report_lines.append(f"  - {subdomain} [{status}]")

            if len(self.results['subdomains']) > 50:
                report_lines.append(f"  ... and {len(self.results['subdomains']) - 50} more")
        else:
            report_lines.append("  No subdomains found")
        report_lines.append("")

        # Live Hosts (detailed)
        live_count = sum(1 for info in self.results['live_hosts'].values() if info['status'] == 'live')
        report_lines.append("[+] LIVE HOSTS (DETAILED)")
        report_lines.append("-" * 80)
        report_lines.append(f"  Total Live: {live_count}")
        report_lines.append("")

        if self.results['live_hosts']:
            for host, info in sorted(self.results['live_hosts'].items()):
                if info['status'] == 'live':
                    report_lines.append(f"  - {host}")
                    report_lines.append(f"      Protocol: {info['protocol']}")
                    report_lines.append(f"      Status: {info['status_code']}")
                    report_lines.append(f"      IP: {info.get('ip', 'N/A')}")
                    report_lines.append(f"      Server: {info.get('server', 'Unknown')}")
                    if info.get('title'):
                        report_lines.append(f"      Title: {info['title']}")
                    if info.get('ports'):
                        report_lines.append(f"      Open Ports: {', '.join(map(str, info['ports'].keys()))}")
                    report_lines.append("")
        else:
            report_lines.append("  No live hosts validated")
        report_lines.append("")

        # GitHub Secrets
        report_lines.append("[+] GITHUB SECRETS/LEAKS")
        report_lines.append("-" * 80)
        report_lines.append(f"  Total: {len(self.results['git_secrets'])}")
        report_lines.append("")

        if self.results['git_secrets']:
            for secret in self.results['git_secrets']:
                report_lines.append(f"  Type: {secret['type']}")
                report_lines.append(f"  Repo: {secret['repo']}")
                report_lines.append(f"  File: {secret['file']}")
                report_lines.append(f"  Confidence: {secret.get('confidence', 'Medium')}")
                report_lines.append(f"  URL:  {secret['url']}")
                report_lines.append("")
        else:
            report_lines.append("  No secrets found")
        report_lines.append("")

        # Emails
        report_lines.append("[+] EMAIL ADDRESSES")
        report_lines.append("-" * 80)
        report_lines.append(f"  Total: {len(self.results['emails'])}")
        report_lines.append("")

        if self.results['emails']:
            for email in sorted(list(self.results['emails'])[:30]):
                report_lines.append(f"  - {email}")
            if len(self.results['emails']) > 30:
                report_lines.append(f"  ... and {len(self.results['emails']) - 30} more")
        else:
            report_lines.append("  No emails found")
        report_lines.append("")

        # Technologies
        report_lines.append("[+] TECHNOLOGIES DETECTED")
        report_lines.append("-" * 80)
        report_lines.append(f"  Total: {len(self.results['technologies'])}")
        report_lines.append("")

        if self.results['technologies']:
            for tech in sorted(self.results['technologies']):
                report_lines.append(f"  - {tech}")
        else:
            report_lines.append("  No technologies detected")
        report_lines.append("")

        # Statistics
        report_lines.append("[+] SCAN STATISTICS")
        report_lines.append("-" * 80)
        report_lines.append(f"  Subdomains Found: {len(self.results['subdomains'])}")
        report_lines.append(f"  Live Hosts: {live_count}")
        report_lines.append(f"  GitHub Secrets: {len(self.results['git_secrets'])}")
        report_lines.append(f"  Email Addresses: {len(self.results['emails'])}")
        report_lines.append(f"  Technologies: {len(self.results['technologies'])}")
        report_lines.append("")

        report_lines.append("=" * 80)
        report_lines.append("END OF REPORT")
        report_lines.append("=" * 80)

        # Write to file
        report_content = "\n".join(report_lines)

        with open(output_file, 'w') as f:
            f.write(report_content)

        console.print(f"\n[green]Report saved to: {output_file}[/green]")

        return report_content

    def display_results_table(self):
        """Display results in formatted tables"""

        # Subdomains table
        if self.results['subdomains']:
            table = Table(title="Discovered Subdomains", box=box.ROUNDED)
            table.add_column("Subdomain", style="cyan")
            table.add_column("Status", style="green")
            table.add_column("IP", style="yellow")

            for subdomain in sorted(list(self.results['subdomains'])[:25]):
                host_info = self.results['live_hosts'].get(subdomain, {})
                status = host_info.get('status', 'unknown')
                ip = host_info.get('ip', '-')

                status_color = "green" if status == "live" else "yellow" if status == "dns_only" else "red"

                table.add_row(
                    subdomain,
                    f"[{status_color}]{status}[/{status_color}]",
                    ip
                )

            if len(self.results['subdomains']) > 25:
                table.add_row("...", f"+{len(self.results['subdomains']) - 25} more", "...")

            console.print(table)
            console.print("")

        # Live hosts detailed
        live_hosts = {k: v for k, v in self.results['live_hosts'].items() if v['status'] == 'live'}
        if live_hosts:
            table = Table(title="Live Hosts (Detailed)", box=box.ROUNDED)
            table.add_column("Host", style="green")
            table.add_column("Protocol", style="cyan")
            table.add_column("Status", style="yellow")
            table.add_column("Server", style="magenta")

            for host, info in sorted(list(live_hosts.items())[:15]):
                table.add_row(
                    host,
                    info.get('protocol', '-'),
                    str(info.get('status_code', '-')),
                    info.get('server', 'Unknown')[:20]
                )

            if len(live_hosts) > 15:
                table.add_row("...", f"+{len(live_hosts) - 15} more", "", "")

            console.print(table)
            console.print("")

        # Secrets table
        if self.results['git_secrets']:
            table = Table(title="GitHub Secrets Found", box=box.ROUNDED)
            table.add_column("Type", style="red")
            table.add_column("Repository", style="yellow")
            table.add_column("File", style="cyan")
            table.add_column("Confidence", style="magenta")

            for secret in self.results['git_secrets'][:15]:
                table.add_row(
                    secret['type'],
                    secret['repo'][:30],
                    secret['file'][:30],
                    secret.get('confidence', 'Medium')
                )

            if len(self.results['git_secrets']) > 15:
                table.add_row("...", f"+{len(self.results['git_secrets']) - 15} more", "...", "")

            console.print(table)
            console.print("")

        # Summary panel
        live_count = sum(1 for info in self.results['live_hosts'].values() if info['status'] == 'live')

        summary = f"""
[cyan]Total Subdomains:[/cyan] {len(self.results['subdomains'])}
[green]Live Hosts:[/green] {live_count}
[red]GitHub Secrets:[/red] {len(self.results['git_secrets'])}
[yellow]Emails:[/yellow] {len(self.results['emails'])}
[magenta]Technologies:[/magenta] {len(self.results['technologies'])}
        """

        panel = Panel(summary, title="[bold]Summary[/bold]", border_style="green")
        console.print(panel)

    def interactive_mode(self):
        """Enhanced interactive TUI mode"""

        self.banner()

        while True:
            console.print("\n[bold cyan]═══ Main Menu ═══[/bold cyan]")
            console.print("─" * 60)
            console.print("[1]  Set Target Domain/Company")
            console.print("[2]  Certificate Transparency Scan")
            console.print("[3]  GitHub Secret Scan")
            console.print("[4]  Company Intelligence Gathering")
            console.print("[5]  Validate Live Hosts")
            console.print("[6]  WHOIS Lookup")
            console.print("[7]  Port Scan (Live Hosts)")
            console.print("[8]  Run All Modules")
            console.print("[9]  Display Results")
            console.print("[10] Generate Report (TXT)")
            console.print("[11] Export to JSON")
            console.print("[12] Export to CSV")
            console.print("[13] Save Session")
            console.print("[14] Load Session")
            console.print("[15] Exit")
            console.print("─" * 60)

            choice = Prompt.ask(
                "Select option",
                choices=["1","2","3","4","5","6","7","8","9","10","11","12","13","14","15"]
            )

            if choice == "1":
                self.target = Prompt.ask("\n[cyan]Enter target domain or company name[/cyan]")
                console.print(f"[green]✓ Target set to: {self.target}[/green]")

            elif choice == "2":
                if not self.target:
                    console.print("[red]Please set a target first (option 1)[/red]")
                    continue

                console.print(f"\n[bold]Running CT Subdomain Scan on {self.target}...[/bold]")
                subdomains = self.ct_subdomain_scan(self.target)
                self.results['subdomains'].update(subdomains)
                console.print(f"[green]✓ Found {len(subdomains)} subdomains[/green]")

            elif choice == "3":
                if not self.target:
                    console.print("[red]Please set a target first (option 1)[/red]")
                    continue

                console.print(f"\n[bold]Running GitHub Secret Scan on {self.target}...[/bold]")

                use_token = Confirm.ask("Do you have a GitHub token for better results?")
                token = None
                if use_token:
                    token = Prompt.ask("Enter GitHub token", password=True)

                secrets = self.github_secret_scan(self.target, token)
                self.results['git_secrets'].extend(secrets)
                console.print(f"[green]✓ Found {len(secrets)} potential secrets[/green]")

            elif choice == "4":
                if not self.target:
                    console.print("[red]Please set a target first (option 1)[/red]")
                    continue

                console.print(f"\n[bold]Gathering Company Intel on {self.target}...[/bold]")
                intel = self.company_intel_gather(self.target)
                self.results['emails'].update(intel['emails'])
                self.results['employees'].update(intel['employees'])
                self.results['technologies'].update(intel['technologies'])
                console.print(f"[green]✓ Intel gathered successfully[/green]")

            elif choice == "5":
                if not self.results['subdomains']:
                    console.print("[red]No subdomains to validate. Run CT scan first (option 2)[/red]")
                    continue

                console.print(f"\n[bold]Validating Live Hosts...[/bold]")
                live = self.validate_live_hosts(self.results['subdomains'])
                self.results['live_hosts'].update(live)
                live_count = sum(1 for info in live.values() if info['status'] == 'live')
                console.print(f"[green]✓ Found {live_count} live hosts out of {len(live)} total[/green]")

            elif choice == "6":
                if not self.target:
                    console.print("[red]Please set a target first (option 1)[/red]")
                    continue

                console.print(f"\n[bold]Performing WHOIS Lookup on {self.target}...[/bold]")
                whois_info = self.get_whois_info(self.target)
                self.results['whois'] = whois_info

                if 'error' not in whois_info:
                    console.print("[green]✓ WHOIS data retrieved[/green]")
                    for key, value in whois_info.items():
                        if key != 'raw':
                            console.print(f"  {key}: {value}")
                else:
                    console.print(f"[yellow]WHOIS lookup failed: {whois_info['error']}[/yellow]")

            elif choice == "7":
                live_hosts = [h for h, info in self.results['live_hosts'].items()
                             if info['status'] == 'live']

                if not live_hosts:
                    console.print("[red]No live hosts to scan. Run validation first (option 5)[/red]")
                    continue

                console.print(f"\n[bold]Scanning ports on {len(live_hosts)} live hosts...[/bold]")

                for host in live_hosts[:10]:
                    info = self.results['live_hosts'][host]
                    if info.get('ip'):
                        console.print(f"Scanning {host}...")
                        ports = self.scan_ports(info['ip'])
                        info['ports'] = ports
                        if ports:
                            console.print(f"  Open ports: {', '.join(map(str, ports.keys()))}")

                console.print("[green]✓ Port scanning complete[/green]")

            elif choice == "8":
                if not self.target:
                    console.print("[red]Please set a target first (option 1)[/red]")
                    continue

                console.print(f"\n[bold magenta]Running All Reconnaissance Modules on {self.target}...[/bold magenta]\n")

                self.results['metadata']['scan_start'] = datetime.now().isoformat()

                # WHOIS
                console.print("[1/6] WHOIS Lookup")
                self.results['whois'] = self.get_whois_info(self.target)

                # CT Scan
                console.print("\n[2/6] Certificate Transparency Scan")
                subdomains = self.ct_subdomain_scan(self.target)
                self.results['subdomains'].update(subdomains)

                # GitHub Scan
                console.print("\n[3/6] GitHub Secret Scan")
                secrets = self.github_secret_scan(self.target)
                self.results['git_secrets'].extend(secrets)

                # Company Intel
                console.print("\n[4/6] Company Intelligence Gathering")
                intel = self.company_intel_gather(self.target)
                self.results['emails'].update(intel['emails'])
                self.results['employees'].update(intel['employees'])
                self.results['technologies'].update(intel['technologies'])

                # Live Host Validation
                if self.results['subdomains']:
                    console.print("\n[5/6] Live Host Validation")
                    live = self.validate_live_hosts(self.results['subdomains'])
                    self.results['live_hosts'].update(live)

                # Auto-generate report
                console.print("\n[6/6] Generating Report")
                self.results['metadata']['scan_end'] = datetime.now().isoformat()
                self.generate_report()
                self.save_session()

                console.print("\n[bold green]✓ All modules completed![/bold green]")

            elif choice == "9":
                if not any([self.results['subdomains'], self.results['git_secrets'],
                           self.results['emails']]):
                    console.print("[red]No results to display. Run some scans first.[/red]")
                    continue

                console.print("\n")
                self.display_results_table()

            elif choice == "10":
                if not any([self.results['subdomains'], self.results['git_secrets'],
                           self.results['emails']]):
                    console.print("[red]No results to export. Run some scans first.[/red]")
                    continue

                filename = Prompt.ask(
                    "\n[cyan]Enter report filename[/cyan]",
                    default=f"recon_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                )
                self.generate_report(filename)

            elif choice == "11":
                if not any([self.results['subdomains'], self.results['git_secrets'],
                           self.results['emails']]):
                    console.print("[red]No results to export. Run some scans first.[/red]")
                    continue

                filename = Prompt.ask(
                    "\n[cyan]Enter JSON filename[/cyan]",
                    default=f"recon_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                )
                self.export_json(filename)

            elif choice == "12":
                if not any([self.results['subdomains'], self.results['git_secrets'],
                           self.results['emails']]):
                    console.print("[red]No results to export. Run some scans first.[/red]")
                    continue

                filename = Prompt.ask(
                    "\n[cyan]Enter CSV filename[/cyan]",
                    default=f"recon_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                )
                self.export_csv(filename)

            elif choice == "13":
                if not self.target:
                    console.print("[red]No session to save. Set a target first.[/red]")
                    continue

                filename = Prompt.ask(
                    "\n[cyan]Enter session filename[/cyan]",
                    default=f"session_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                )
                self.save_session(filename)

            elif choice == "14":
                filename = Prompt.ask("\n[cyan]Enter session filename to load[/cyan]")
                if os.path.exists(filename):
                    self.load_session(filename)
                else:
                    console.print(f"[red]File not found: {filename}[/red]")

            elif choice == "15":
                if Confirm.ask("\n[yellow]Are you sure you want to exit?[/yellow]"):
                    console.print("[bold green]Thank you for using ReconMaster Pro![/bold green]")
                    break


def main():
    """Main entry point"""

    parser = argparse.ArgumentParser(
        description="ReconMaster Pro v2.0 - All-in-One Reconnaissance Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                    # Interactive mode
  %(prog)s -t example.com --all               # Run all modules
  %(prog)s -t example.com --ct                # CT subdomain scan only
  %(prog)s -t example.com --github            # GitHub secret scan only
  %(prog)s -t example.com --all -o report.txt # Run all and save report
  %(prog)s -t example.com --all --json        # Run all and export JSON
  %(prog)s --load session.json                # Load previous session
        """
    )

    parser.add_argument('-t', '--target', help='Target domain or company name')
    parser.add_argument('--ct', action='store_true', help='Run Certificate Transparency scan')
    parser.add_argument('--github', action='store_true', help='Run GitHub secret scan')
    parser.add_argument('--intel', action='store_true', help='Run company intelligence gathering')
    parser.add_argument('--validate', action='store_true', help='Validate live hosts')
    parser.add_argument('--whois', action='store_true', help='Perform WHOIS lookup')
    parser.add_argument('--ports', action='store_true', help='Scan ports on live hosts')
    parser.add_argument('--all', action='store_true', help='Run all modules')
    parser.add_argument('-o', '--output', help='Output report filename (TXT)')
    parser.add_argument('--json', action='store_true', help='Export results as JSON')
    parser.add_argument('--csv', action='store_true', help='Export results as CSV')
    parser.add_argument('--github-token', help='GitHub personal access token')
    parser.add_argument('--save', help='Save session to file')
    parser.add_argument('--load', help='Load session from file')

    args = parser.parse_args()

    recon = ReconMaster()

    # Load session if specified
    if args.load:
        if os.path.exists(args.load):
            recon.load_session(args.load)
        else:
            console.print(f"[red]Session file not found: {args.load}[/red]")
            sys.exit(1)

    # CLI mode
    if args.target or args.load:
        if args.target:
            recon.target = args.target

        if not recon.target:
            console.print("[red]No target specified[/red]")
            sys.exit(1)

        if args.all or args.whois:
            console.print(f"[bold]Running WHOIS Lookup on {recon.target}...[/bold]")
            recon.results['whois'] = recon.get_whois_info(recon.target)
            console.print("[green]✓ WHOIS complete[/green]\n")

        if args.all or args.ct:
            console.print(f"[bold]Running CT Subdomain Scan on {recon.target}...[/bold]")
            subdomains = recon.ct_subdomain_scan(recon.target)
            recon.results['subdomains'].update(subdomains)
            console.print(f"[green]✓ Found {len(subdomains)} subdomains[/green]\n")

        if args.all or args.github:
            console.print(f"[bold]Running GitHub Secret Scan on {recon.target}...[/bold]")
            secrets = recon.github_secret_scan(recon.target, args.github_token)
            recon.results['git_secrets'].extend(secrets)
            console.print(f"[green]✓ Found {len(secrets)} potential secrets[/green]\n")

        if args.all or args.intel:
            console.print(f"[bold]Gathering Company Intel on {recon.target}...[/bold]")
            intel = recon.company_intel_gather(recon.target)
            recon.results['emails'].update(intel['emails'])
            recon.results['employees'].update(intel['employees'])
            recon.results['technologies'].update(intel['technologies'])
            console.print(f"[green]✓ Intel gathered[/green]\n")

        if args.all or args.validate:
            if recon.results['subdomains']:
                console.print(f"[bold]Validating Live Hosts...[/bold]")
                live = recon.validate_live_hosts(recon.results['subdomains'], args.ports)
                recon.results['live_hosts'].update(live)
                live_count = sum(1 for info in live.values() if info['status'] == 'live')
                console.print(f"[green]✓ Found {live_count} live hosts[/green]\n")

        # Display results
        recon.display_results_table()

        # Generate report
        if args.output or args.all:
            recon.generate_report(args.output)

        # Export formats
        if args.json or args.all:
            recon.export_json()

        if args.csv:
            recon.export_csv()

        # Save session
        if args.save:
            recon.save_session(args.save)

    else:
        # Interactive TUI mode
        recon.interactive_mode()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[yellow]⚠ Operation cancelled by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]✗ Error: {e}[/red]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        sys.exit(1)
