#!/usr/bin/env python3
"""
Analyze-CLI: IOC Analysis Tool
Copyright (c) 2026 byFranke - Security Solutions
GitHub: https://github.com/byfranke/analyze-cli

A robust command-line interface for analyzing Indicators of Compromise (IOCs)
including IPs, domains, hashes, URLs, and CVEs using multiple threat intelligence sources.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.json import JSON
from rich.progress import Progress, SpinnerColumn, TextColumn
import configparser
from urllib.parse import urlparse
import re
from getpass import getpass
import base64

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import keyring
    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False

VERSION = "1.1.0"
DEFAULT_API_URL = "https://sheep.byfranke.com/api/ai/analyze"
DEFAULT_CONFIG_FILE = "~/.analyze-cli/config.ini"
DEFAULT_TIMEOUT = 30
GITHUB_REPO = "https://github.com/byfranke/analyze-cli"
PRIVACY_POLICY = "https://sheep.byfranke.com/pages/privacy.html"
SUPPORT_EMAIL = "support@byfranke.com"

console = Console()


class IOCAnalyzer:
    """Client for the IOC analysis API"""

    def __init__(self, api_token: Optional[str] = None, api_url: Optional[str] = None):
        """
        Initialize the IOC Analyzer client.

        Args:
            api_token: API authentication token
            api_url: Base URL for the API endpoint
        """
        config = self._load_config()
        self.api_token = self._normalize_token(api_token) or self._load_token(config)
        self.api_url = api_url or os.environ.get("ANALYZE_API_URL") or self._load_api_url(config)

        if not self.api_token:
            raise ValueError(
                "API token is required. Configure it via:\n"
                "  1. Run: python3 setup.py to configure encrypted token\n"
                "  2. Use --token argument for one-time use\n\n"
                f"Support: {SUPPORT_EMAIL}\n"
                f"Documentation: {GITHUB_REPO}"
            )

    def _session_cache_path(self) -> Optional[Path]:
        """Path for the per-terminal-session decrypted token cache."""
        try:
            sid = os.getsid(os.getpid())
        except (AttributeError, OSError):
            return None
        uid = os.getuid() if hasattr(os, "getuid") else 0
        return Path(f"/tmp/analyze-cli-sess-{uid}-{sid}")

    def _read_session_cache(self) -> Optional[str]:
        """Read cached token for current terminal session, if valid."""
        cache = self._session_cache_path()
        if cache is None or not cache.exists():
            return None
        try:
            st = cache.stat()
            if hasattr(os, "getuid") and st.st_uid != os.getuid():
                return None
            if st.st_mode & 0o077:
                return None
            token = cache.read_text().strip()
            return token or None
        except Exception:
            return None

    def _write_session_cache(self, token: str) -> None:
        """Store decrypted token in a per-session cache file."""
        cache = self._session_cache_path()
        if cache is None:
            return
        try:
            fd = os.open(str(cache), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(token)
        except Exception:
            pass

    def _normalize_token(self, token: Optional[str]) -> Optional[str]:
        """Normalize token values loaded from CLI, env, config, or keyring."""
        if token is None:
            return None
        token = token.strip()
        return token or None

    def _load_config(self) -> configparser.ConfigParser:
        """Load CLI configuration file if present."""
        config = configparser.ConfigParser()
        config_path = Path(DEFAULT_CONFIG_FILE).expanduser()
        if config_path.exists():
            config.read(config_path)
        return config

    def _load_api_url(self, config: configparser.ConfigParser) -> str:
        """Load API URL from config when available."""
        return config.get("api", "url", fallback=DEFAULT_API_URL).strip() or DEFAULT_API_URL

    def _decrypt_token(self, encrypted_token: str, password: str) -> Optional[str]:
        """Decrypt token with password"""
        if not ENCRYPTION_AVAILABLE:
            console.print("[yellow]Warning: Encryption libraries not available[/yellow]")
            return None

        try:
            salt = b'analyze-cli-salt-2026'
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            f = Fernet(key)
            encrypted = base64.b64decode(encrypted_token.encode())
            decrypted = f.decrypt(encrypted)
            return decrypted.decode()
        except Exception:
            return None

    def _load_token(self, config: configparser.ConfigParser) -> Optional[str]:
        """Load API token from various sources"""
        token = self._normalize_token(os.environ.get("ANALYZE_API_TOKEN"))
        if token:
            return token

        if "api" in config:
            if config["api"].get("encryption_enabled") == "true" and "encrypted_token" in config["api"]:
                cached = self._read_session_cache()
                if cached:
                    return self._normalize_token(cached)

                encrypted_token = config["api"]["encrypted_token"]
                console.print("[yellow]Token is encrypted. Enter your master password:[/yellow]")

                for attempt in range(3):
                    password = getpass("Master Password: ")
                    token = self._normalize_token(self._decrypt_token(encrypted_token, password))
                    if token:
                        self._write_session_cache(token)
                        return token
                    console.print(f"[red]Invalid password. {2-attempt} attempts remaining.[/red]")

                console.print("[red]Failed to decrypt token after 3 attempts[/red]")
                return None

            token = self._normalize_token(config["api"].get("token"))
            if token:
                return token

        if ENCRYPTION_AVAILABLE:
            try:
                token = self._normalize_token(keyring.get_password("analyze-cli", "api_token"))
                if token:
                    return token
            except Exception:
                pass

        return None

    def detect_ioc_type(self, target: str) -> str:
        """
        Automatically detect the type of IOC.

        Args:
            target: The IOC to analyze

        Returns:
            The detected IOC type
        """
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        md5_pattern = r'^[a-fA-F0-9]{32}$'
        sha1_pattern = r'^[a-fA-F0-9]{40}$'
        sha256_pattern = r'^[a-fA-F0-9]{64}$'
        cve_pattern = r'^CVE-\d{4}-\d{4,}$'

        if target.startswith(('http://', 'https://')):
            return 'url'

        if re.match(ip_pattern, target):
            return 'ip'

        if re.match(md5_pattern, target):
            return 'hash'
        if re.match(sha1_pattern, target):
            return 'hash'
        if re.match(sha256_pattern, target):
            return 'hash'

        if re.match(cve_pattern, target.upper()):
            return 'cve'

        if '.' in target and not ' ' in target and len(target) < 255:
            domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
            if re.match(domain_pattern, target):
                return 'domain'

        return 'domain'

    def analyze(self, target: str, ioc_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze an IOC using the API.

        Args:
            target: The IOC to analyze
            ioc_type: Type of IOC (auto-detected if not provided)

        Returns:
            Analysis results from the API
        """
        if not ioc_type:
            ioc_type = self.detect_ioc_type(target)
            console.print(f"[cyan]Auto-detected IOC type: {ioc_type}[/cyan]")

        headers = {
            "X-API-Token": self.api_token,
            "Content-Type": "application/json"
        }

        payload = {
            "target": target,
            "type": ioc_type
        }

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True
            ) as progress:
                task = progress.add_task(f"Analyzing {ioc_type}: {target}", total=None)

                response = requests.post(
                    self.api_url,
                    headers=headers,
                    json=payload,
                    timeout=DEFAULT_TIMEOUT
                )

                progress.update(task, completed=True)

            response.raise_for_status()
            return response.json()

        except requests.exceptions.Timeout:
            console.print("[red]Error: Request timed out[/red]")
            sys.exit(1)
        except requests.exceptions.ConnectionError:
            console.print("[red]Error: Failed to connect to API server[/red]")
            sys.exit(1)
        except requests.exceptions.HTTPError as e:
            if response.status_code == 401:
                console.print("[red]Error: Invalid API token[/red]")
            elif response.status_code == 400:
                error_detail = response.text.strip()
                if not error_detail:
                    try:
                        payload = response.json()
                    except ValueError:
                        payload = {}

                    error_detail = (
                        str(payload.get("detail") or payload.get("error") or payload.get("message") or "")
                    ).strip()

                if not error_detail:
                    error_detail = "the saved token or API URL may be invalid; try --token or re-run setup.py"

                console.print(f"[red]Error: Invalid request - {error_detail}[/red]")
            else:
                console.print(f"[red]Error: HTTP {response.status_code} - {response.text}[/red]")
            sys.exit(1)
        except requests.exceptions.RequestException as e:
            console.print(f"[red]Error: {str(e)}[/red]")
            sys.exit(1)


def display_results(results: Dict[str, Any], output_format: str = "pretty"):
    """
    Display analysis results in the specified format.

    Args:
        results: Analysis results from the API
        output_format: Output format (pretty, json, table)
    """
    if output_format == "json":
        console.print_json(json.dumps(results, indent=2))
    elif output_format == "pretty":
        if "error" in results and results["error"] is not None:
            console.print(Panel(f"[red]{results['error']}[/red]", title="Error", border_style="red"))
            return

        title = f"IOC Analysis Results"
        if "target" in results:
            title = f"Analysis: {results['target']}"

        if "analysis" in results:
            console.print(Panel(results["analysis"], title=title, border_style="green"))
        elif "summary" in results:
            console.print(Panel(results["summary"], title=title, border_style="green"))

        if "sources" in results:
            table = Table(title="Threat Intelligence Sources", show_header=True, header_style="bold cyan")
            table.add_column("Source", style="cyan", width=20)
            table.add_column("Status", width=15)
            table.add_column("Details", style="white")

            for source, data in results["sources"].items():
                if isinstance(data, dict):
                    status = data.get("status", "Unknown")
                    details = data.get("details", "N/A")

                    if "malicious" in str(status).lower():
                        status = f"[red]{status}[/red]"
                    elif "clean" in str(status).lower():
                        status = f"[green]{status}[/green]"
                    else:
                        status = f"[yellow]{status}[/yellow]"

                    table.add_row(source, status, str(details)[:80])

            console.print(table)

        if "raw_data" in results:
            console.print("\n[bold cyan]Raw Data:[/bold cyan]")
            console.print(JSON(json.dumps(results["raw_data"], indent=2)))

    elif output_format == "table":
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Field", style="cyan")
        table.add_column("Value")

        def flatten_dict(d, parent_key=''):
            items = []
            for k, v in d.items():
                new_key = f"{parent_key}.{k}" if parent_key else k
                if isinstance(v, dict):
                    items.extend(flatten_dict(v, new_key))
                else:
                    items.append((new_key, str(v)))
            return items

        for key, value in flatten_dict(results):
            table.add_row(key, value[:100])  # Truncate long values

        console.print(table)


def init_config():
    """Initialize configuration file with example settings"""
    config_dir = Path(DEFAULT_CONFIG_FILE).expanduser().parent
    config_dir.mkdir(parents=True, exist_ok=True)

    config_path = Path(DEFAULT_CONFIG_FILE).expanduser()

    if config_path.exists():
        console.print(f"[yellow]Configuration file already exists at {config_path}[/yellow]")
        overwrite = console.input("Do you want to overwrite it? (y/N): ")
        if overwrite.lower() != 'y':
            return

    config = configparser.ConfigParser()
    config['api'] = {
        'token': 'YOUR_API_TOKEN_HERE',
        'url': DEFAULT_API_URL
    }

    config['defaults'] = {
        'output_format': 'pretty',
        'auto_detect_type': 'true'
    }

    with open(config_path, 'w') as f:
        config.write(f)

    console.print(f"[green]Configuration file created at {config_path}[/green]")
    console.print("[yellow]Please edit the file and add your API token[/yellow]")


def check_for_updates():
    """Check for updates from GitHub"""
    console.print("[bold cyan]Checking for updates...[/bold cyan]")
    console.print(f"Current version: {VERSION}")
    console.print(f"\nFor updates, visit: {GITHUB_REPO}")
    console.print("To update, run: [cyan]python3 setup.py --update[/cyan]")


def main():
    """Main entry point for the CLI"""
    parser = argparse.ArgumentParser(
        description="Analyze IOCs (IPs, domains, hashes, URLs, CVEs) using multiple threat intelligence sources",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  %(prog)s 185.220.101.45                    # Auto-detect and analyze IP
  %(prog)s malware.exe --type hash           # Analyze file hash
  %(prog)s example.com --type domain         # Analyze domain
  %(prog)s CVE-2021-44228                    # Analyze CVE
  %(prog)s https://suspicious.site/page      # Analyze URL

Setup & Configuration:
  python3 setup.py                           # Run interactive setup wizard
  %(prog)s --init                            # Quick config file creation
  %(prog)s --update                          # Check for updates

Support:
  Documentation: {GITHUB_REPO}
  Privacy Policy: {PRIVACY_POLICY}
  Email: {SUPPORT_EMAIL}

Copyright (c) 2026 byFranke - Security Solutions
        """
    )

    parser.add_argument(
        "target",
        nargs="?",
        help="The IOC to analyze (IP, domain, hash, URL, or CVE)"
    )

    parser.add_argument(
        "-t", "--type",
        choices=["ip", "domain", "hash", "url", "cve"],
        help="Specify the IOC type (auto-detected if not provided)"
    )

    parser.add_argument(
        "--token",
        help="API authentication token"
    )

    parser.add_argument(
        "--api-url",
        help=f"API endpoint URL (default: {DEFAULT_API_URL})"
    )

    parser.add_argument(
        "-o", "--output",
        choices=["pretty", "json", "table"],
        default="pretty",
        help="Output format (default: pretty)"
    )

    parser.add_argument(
        "--init",
        action="store_true",
        help="Initialize configuration file"
    )

    parser.add_argument(
        "--update",
        action="store_true",
        help="Check for updates from GitHub"
    )

    parser.add_argument(
        "--setup",
        action="store_true",
        help="Run interactive setup wizard"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}"
    )

    parser.add_argument(
        "--about",
        action="store_true",
        help="Show about information and legal notices"
    )

    parser.add_argument(
        "--logout",
        action="store_true",
        help="Clear the cached decrypted token for the current terminal session"
    )

    args = parser.parse_args()

    if args.about:
        about_info = f"""
[bold cyan]Analyze-CLI v{VERSION}[/bold cyan]
IOC Analysis & Threat Intelligence Tool

[bold]Copyright:[/bold] © 2026 byFranke - Security Solutions
[bold]License:[/bold] byFranke License
[bold]GitHub:[/bold] {GITHUB_REPO}
[bold]Privacy Policy:[/bold] {PRIVACY_POLICY}
[bold]Support:[/bold] {SUPPORT_EMAIL}

[bold]Credits:[/bold]
Integrates with multiple threat intelligence sources:
• VirusTotal
• AbuseIPDB
• Shodan
• URLScan
• And more...
        """
        console.print(Panel(about_info, title="About Analyze-CLI", style="cyan"))
        return

    if args.logout:
        try:
            analyzer = IOCAnalyzer.__new__(IOCAnalyzer)
            cache = analyzer._session_cache_path()
            if cache and cache.exists():
                cache.unlink()
                console.print("[green]Session token cache cleared[/green]")
            else:
                console.print("[yellow]No cached session token to clear[/yellow]")
        except Exception as e:
            console.print(f"[red]Failed to clear session cache: {e}[/red]")
        return

    if args.setup:
        console.print("[cyan]Launching setup wizard...[/cyan]")
        os.system("python3 setup.py")
        return

    if args.update:
        check_for_updates()
        return

    if args.init:
        init_config()
        return

    if not args.target:
        parser.error("Target IOC is required (use --help for options)")

    try:
        analyzer = IOCAnalyzer(api_token=args.token, api_url=args.api_url)
        results = analyzer.analyze(args.target, args.type)
        display_results(results, args.output)

    except ValueError as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Analysis cancelled by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        if args.verbose:
            console.print_exception()
        else:
            console.print(f"[red]Unexpected error: {str(e)}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
