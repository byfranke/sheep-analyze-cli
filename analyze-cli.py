#!/usr/bin/env python3
"""
Sheep Analyze CLI: IOC analysis tool for the Sheep platform.

Copyright (c) 2026 byFranke - Security Solutions
GitHub: https://github.com/byfranke/sheep-analyze-cli

A command-line interface for analyzing Indicators of Compromise (IPs,
domains, hashes, URLs, CVEs) through the Sheep API, with built-in
threat intelligence enrichment and structured (SOAR-friendly) output.
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, Any, Optional
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.json import JSON
from rich.markdown import Markdown
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text
from rich.markup import escape as rich_escape
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

_VERSION_FILE = Path(__file__).resolve().parent / "VERSION"
VERSION = _VERSION_FILE.read_text().strip() if _VERSION_FILE.exists() else "2.2.0"

DEFAULT_API_BASE = "https://sheep.byfranke.com"
ANALYZE_PATH = "/api/ai/analyze"
PROFILE_PATH = "/api/profile"
DEFAULT_API_URL = DEFAULT_API_BASE + ANALYZE_PATH
DEFAULT_CONFIG_FILE = "~/.analyze/config.ini"
LEGACY_CONFIG_FILE = "~/.analyze-cli/config.ini"
DEFAULT_TIMEOUT = 30
GITHUB_REPO = "https://github.com/byfranke/sheep-analyze-cli"
PRIVACY_POLICY = "https://sheep.byfranke.com/pages/privacy.html"
SUPPORT_EMAIL = "support@byfranke.com"
STORE_URL = "https://sheep.byfranke.com/pages/store"


def _normalize_api_base(value: Optional[str]) -> str:
    """Accept either a base URL or a full /api/ai/analyze URL and return the base.

    Older configs stored ``api.url=https://sheep.byfranke.com/api/ai/analyze``
    in the ini file. Newer code wants the bare base so we can derive /analyze
    AND /api/profile. Strip the legacy suffix transparently so an upgraded
    CLI doesn't force the user to re-edit their config.
    """
    if not value:
        return DEFAULT_API_BASE
    v = value.rstrip("/")
    if v.endswith(ANALYZE_PATH):
        v = v[: -len(ANALYZE_PATH)]
    return v or DEFAULT_API_BASE

PBKDF2_DEFAULT_ITERATIONS = 600000
LEGACY_FIXED_SALT = b'analyze-cli-salt-2026'
LEGACY_ITERATIONS = 100000
KEYRING_SERVICE = "sheep-analyze"
LEGACY_KEYRING_SERVICE = "analyze-cli"
MIN_PBKDF2_ITERATIONS = 100000
MAX_PBKDF2_ITERATIONS = 10000000
MIN_SALT_BYTES = 16

console = Console()
err_console = Console(stderr=True)


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
        env_url = (
            os.environ.get("SHEEP_API_URL")
            or os.environ.get("ANALYZE_API_URL")
        )
        if (
            os.environ.get("ANALYZE_API_URL")
            and not os.environ.get("SHEEP_API_URL")
        ):
            err_console.print(
                "[yellow]Warning: ANALYZE_API_URL is deprecated. "
                "Use SHEEP_API_URL instead (will be removed in v1.5).[/yellow]"
            )
        raw_url = api_url or env_url or self._load_api_url(config)
        self.api_base = _normalize_api_base(raw_url)
        self.api_url = self.api_base + ANALYZE_PATH
        self.profile_url = self.api_base + PROFILE_PATH
        self._validate_api_url(self.api_base)
        if self.api_base != DEFAULT_API_BASE:
            err_console.print(
                f"[yellow]Warning: using non-default API base "
                f"({self.api_base}). Your X-Sheep-Token will be sent to "
                f"that host. Make sure you trust it.[/yellow]"
            )

        if not self.api_token:
            raise ValueError(
                "API token is required. Configure it via:\n"
                "  1. Run: python3 setup.py to configure encrypted token\n"
                "  2. Use --token argument for one-time use\n\n"
                f"Support: {SUPPORT_EMAIL}\n"
                f"Documentation: {GITHUB_REPO}"
            )

    @staticmethod
    def _is_local_host(host: str) -> bool:
        """True for hosts that resolve to the local machine.

        Uses Python's stdlib ipaddress module to check whether the
        supplied host is an address bound to the local machine, with a
        special case for the conventional name 'localhost'.
        """
        if not host:
            return False
        if host == "localhost":
            return True
        try:
            import ipaddress
            return ipaddress.ip_address(host).is_loopback
        except (ValueError, ImportError):
            return False

    @staticmethod
    def _validate_api_url(url: str) -> None:
        """Reject api_url values that would leak the token in clear-text.

        The CLI sends the X-Sheep-Token on every request. If a caller
        configures ``--api-url=http://attacker.example.com`` (or is
        socially engineered into it), the token would be transmitted
        unencrypted. This helper enforces:

        - https:// for any non-local host (including IP addresses)
        - http:// only for the user's own machine (localhost names or
          IP addresses bound to the local machine)
        - rejects any non-http(s) scheme (file://, ftp://, javascript:, ...)

        Raises ValueError on rejection so the caller can surface a
        clear, non-fatal CLI error rather than silently leaking.
        """
        try:
            parsed = urlparse(url)
        except (TypeError, ValueError):
            raise ValueError(f"Invalid API URL: {url!r}")
        scheme = (parsed.scheme or "").lower()
        host = (parsed.hostname or "").lower()
        if scheme not in ("http", "https"):
            raise ValueError(
                f"Unsupported URL scheme {scheme!r}; use https:// "
                "(or http:// for the local machine only)."
            )
        if not host:
            raise ValueError(f"API URL has no host: {url!r}")
        if scheme == "http" and not IOCAnalyzer._is_local_host(host):
            raise ValueError(
                f"Refusing http:// for non-local host {host!r}; "
                "use https:// to avoid sending the API token in clear-text."
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
        """Read cached token for current terminal session, if valid.

        Hardened against TOCTOU and symlink attacks: opens the path with
        O_NOFOLLOW (no symlink traversal) and validates uid/mode via fstat
        on the OPEN file descriptor — never re-resolving the path.
        """
        cache = self._session_cache_path()
        if cache is None:
            return None
        try:
            fd = os.open(str(cache), os.O_RDONLY | os.O_NOFOLLOW)
        except (FileNotFoundError, OSError):
            return None
        try:
            st = os.fstat(fd)
            if hasattr(os, "getuid") and st.st_uid != os.getuid():
                return None
            if st.st_mode & 0o077:
                return None
            with os.fdopen(fd, "r") as f:
                fd = -1
                token = f.read().strip()
            return token or None
        except Exception:
            return None
        finally:
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass

    def _write_session_cache(self, token: str) -> None:
        """Store decrypted token in a per-session cache file.

        Hardened against symlink attacks: opens with O_NOFOLLOW so a
        pre-planted symlink at the cache path cannot redirect the write
        to an attacker-chosen file. Stale non-symlink files are
        overwritten via O_TRUNC.
        """
        cache = self._session_cache_path()
        if cache is None:
            return
        try:
            fd = os.open(
                str(cache),
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                0o600,
            )
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
        """Load CLI configuration file if present.

        Looks at ``~/.analyze/config.ini`` first; falls back to the
        legacy ``~/.analyze-cli/config.ini`` (with a deprecation warning)
        so users upgrading from v1.2 keep working without rerunning the
        setup wizard. Both paths apply the same permission gate.

        Refuses to load configs that are world/group-readable: an attacker
        with read access to a config holding the encrypted token, salt
        and KDF iterations could mount an offline brute-force attack
        against the master password. Fail-closed (warn + ignore) so the
        caller is forced to fix permissions before the token leaves the
        local trust boundary again.
        """
        config = configparser.ConfigParser()
        primary = Path(DEFAULT_CONFIG_FILE).expanduser()
        legacy = Path(LEGACY_CONFIG_FILE).expanduser()
        if primary.exists():
            config_path = primary
        elif legacy.exists():
            config_path = legacy
            err_console.print(
                f"[yellow]Warning: reading legacy config at {legacy}. "
                f"Re-run `python3 setup.py` to migrate to {primary}.[/yellow]"
            )
        else:
            return config
        try:
            st = config_path.stat()
        except OSError:
            return config
        if hasattr(os, "getuid") and st.st_uid != os.getuid():
            err_console.print(
                f"[yellow]Warning: {config_path} is owned by another user; "
                "ignoring it. Re-run setup.py to recreate.[/yellow]"
            )
            return config
        if st.st_mode & 0o077:
            err_console.print(
                f"[yellow]Warning: {config_path} has loose permissions "
                f"({oct(st.st_mode & 0o777)}); refusing to load. "
                f"Run: chmod 600 {config_path}[/yellow]"
            )
            return config
        config.read(config_path)
        return config

    def _load_api_url(self, config: configparser.ConfigParser) -> str:
        """Load API URL from config when available."""
        return config.get("api", "url", fallback=DEFAULT_API_URL).strip() or DEFAULT_API_URL

    def _decrypt_token(
        self,
        encrypted_token: str,
        password: str,
        salt: bytes,
        iterations: int,
    ) -> Optional[str]:
        """Decrypt token with password using the supplied KDF parameters."""
        if not ENCRYPTION_AVAILABLE:
            console.print("[yellow]Warning: Encryption libraries not available[/yellow]")
            return None

        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=iterations,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            f = Fernet(key)
            encrypted = base64.b64decode(encrypted_token.encode())
            decrypted = f.decrypt(encrypted)
            return decrypted.decode()
        except Exception:
            return None

    def _load_token(self, config: configparser.ConfigParser) -> Optional[str]:
        """Load API token from environment, config or system keyring."""
        sheep_token = self._normalize_token(os.environ.get("SHEEP_API_TOKEN"))
        legacy_token = self._normalize_token(os.environ.get("ANALYZE_API_TOKEN"))
        if sheep_token:
            return sheep_token
        if legacy_token:
            err_console.print(
                "[yellow]Warning: ANALYZE_API_TOKEN is deprecated. "
                "Use SHEEP_API_TOKEN instead (will be removed in v1.5).[/yellow]"
            )
            return legacy_token

        if "api" in config:
            if config["api"].get("encryption_enabled") == "true" and "encrypted_token" in config["api"]:
                cached = self._read_session_cache()
                if cached:
                    return self._normalize_token(cached)

                encrypted_token = config["api"]["encrypted_token"]
                salt_b64 = config["api"].get("salt")
                if salt_b64:
                    try:
                        salt = base64.b64decode(salt_b64)
                    except Exception:
                        salt = LEGACY_FIXED_SALT
                else:
                    salt = LEGACY_FIXED_SALT
                if len(salt) < MIN_SALT_BYTES:
                    salt = LEGACY_FIXED_SALT
                try:
                    iterations = int(config["api"].get(
                        "kdf_iterations", LEGACY_ITERATIONS
                    ))
                except (TypeError, ValueError):
                    iterations = LEGACY_ITERATIONS
                if iterations < MIN_PBKDF2_ITERATIONS or iterations > MAX_PBKDF2_ITERATIONS:
                    iterations = LEGACY_ITERATIONS

                err_console.print("[yellow]Token is encrypted. Enter your master password:[/yellow]")

                for attempt in range(3):
                    try:
                        password = getpass("Master Password: ")
                    except (KeyboardInterrupt, EOFError):
                        err_console.print("\n[yellow]Cancelled[/yellow]")
                        return None
                    token = self._normalize_token(
                        self._decrypt_token(encrypted_token, password, salt, iterations)
                    )
                    if token:
                        self._write_session_cache(token)
                        return token
                    err_console.print(f"[red]Invalid password. {2-attempt} attempts remaining.[/red]")

                err_console.print("[red]Failed to decrypt token after 3 attempts[/red]")
                return None

            token = self._normalize_token(config["api"].get("token"))
            if token:
                return token

        if ENCRYPTION_AVAILABLE:
            for service in (KEYRING_SERVICE, LEGACY_KEYRING_SERVICE):
                try:
                    token = self._normalize_token(
                        keyring.get_password(service, "api_token")
                    )
                    if token:
                        return token
                except Exception:
                    continue

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

    def analyze(
        self,
        target: str,
        ioc_type: Optional[str] = None,
        api_format: str = "markdown",
    ) -> Dict[str, Any]:
        """
        Analyze an IOC using the API.

        Args:
            target: The IOC to analyze.
            ioc_type: Type of IOC (auto-detected if not provided).
            api_format: Wire response format the server should produce.
                'markdown' (default) — full AnalysisResult with the
                markdown narrative + structured_analysis. Backwards
                compatible with older API deployments that don't know
                the format parameter.
                'json' — same shape minus the markdown ``analysis``
                field. Lighter for SIEM/SOAR pipelines.
                'stix' — replaces the body with a STIX 2.1 Bundle
                served by the API at ``Content-Type:
                application/stix+json;version=2.1``. The CLI returns
                the parsed bundle dict.

        Returns:
            Analysis results from the API. The /analyze endpoint runs
            every request on the Hunter model — there is no per-call
            model selector.
        """
        if not ioc_type:
            ioc_type = self.detect_ioc_type(target)
            err_console.print(f"[cyan]Auto-detected IOC type: {_safe(ioc_type, max_len=40)}[/cyan]")

        headers = {
            "X-Sheep-Token": self.api_token,
            "Content-Type": "application/json",
            "User-Agent": f"sheep-analyze/{VERSION}",
        }

        payload: Dict[str, Any] = {
            "target": target,
            "type": ioc_type,
        }

        fmt = (api_format or "markdown").strip().lower()
        if fmt not in ("markdown", "json", "stix"):
            fmt = "markdown"
        request_url = self.api_url
        if fmt != "markdown":
            sep = "&" if "?" in request_url else "?"
            request_url = f"{request_url}{sep}format={fmt}"

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=err_console,
                transient=True
            ) as progress:
                task = progress.add_task(
                    f"Analyzing {_safe(ioc_type, max_len=20)}: {_safe(target, max_len=120)}",
                    total=None,
                )

                response = requests.post(
                    request_url,
                    headers=headers,
                    json=payload,
                    timeout=DEFAULT_TIMEOUT
                )

                progress.update(task, completed=True)

            response.raise_for_status()
            return response.json()

        except requests.exceptions.Timeout:
            err_console.print("[red]Error: Request timed out[/red]")
            sys.exit(1)
        except requests.exceptions.ConnectionError:
            err_console.print("[red]Error: Failed to connect to API server[/red]")
            sys.exit(1)
        except requests.exceptions.HTTPError as e:
            if response.status_code == 401:
                err_console.print(Panel(
                    "[red]Invalid API token.[/red]\n\n"
                    "Your token is missing, expired, or no longer valid.\n\n"
                    f"Get a token or upgrade your plan: [blue]{STORE_URL}[/blue]\n"
                    f"Support: {SUPPORT_EMAIL}",
                    title="Authentication failed",
                    border_style="red",
                ))
            elif response.status_code == 403:
                err_console.print(Panel(
                    "[red]Forbidden — your plan doesn't cover this "
                    "request.[/red]\n\n"
                    f"Upgrade your plan: [blue]{STORE_URL}[/blue]\n"
                    f"Support: {SUPPORT_EMAIL}",
                    title="Plan does not cover this request",
                    border_style="red",
                ))
            elif response.status_code == 429:
                err_console.print(Panel(
                    "[red]Rate limit exceeded.[/red]\n\n"
                    "Please wait a minute before trying again. If you hit this often, "
                    "consider upgrading your plan.\n\n"
                    f"Plans and quotas: [blue]{STORE_URL}[/blue]\n"
                    f"Support: {SUPPORT_EMAIL}",
                    title="Too many requests",
                    border_style="red",
                ))
            elif response.status_code == 400:
                error_detail = (response.text or "").strip()
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

                err_console.print(f"[red]Error: Invalid request - {_safe(error_detail, max_len=600)}[/red]")
            else:
                raw = response.text or ""
                truncated = len(raw) > 500
                snippet = _safe(raw[:500], max_len=600)
                if truncated:
                    snippet += "…[truncated]"
                err_console.print(f"[red]Error: HTTP {response.status_code}[/red]")
                if snippet:
                    err_console.print(f"[dim]{snippet}[/dim]")
            sys.exit(1)
        except requests.exceptions.RequestException as e:
            err_console.print(f"[red]Error: {_safe(str(e), max_len=400)}[/red]")
            sys.exit(1)

    def profile(self) -> Dict[str, Any]:
        """Fetch the authenticated caller's plan + quota from /api/profile."""
        headers = {"X-Sheep-Token": self.api_token, "User-Agent": f"sheep-analyze/{VERSION}"}
        try:
            response = requests.get(self.profile_url, headers=headers, timeout=DEFAULT_TIMEOUT)
        except requests.exceptions.Timeout:
            err_console.print("[red]Error: Profile request timed out[/red]")
            sys.exit(1)
        except requests.exceptions.ConnectionError:
            err_console.print("[red]Error: Failed to connect to API server[/red]")
            sys.exit(1)
        except requests.exceptions.RequestException as e:
            err_console.print(f"[red]Error: {_safe(str(e), max_len=400)}[/red]")
            sys.exit(1)

        if response.status_code == 401:
            err_console.print(Panel(
                "[red]Invalid API token.[/red]\n\n"
                f"Get a token or upgrade your plan: [blue]{STORE_URL}[/blue]",
                title="Authentication failed",
                border_style="red",
            ))
            sys.exit(1)
        if response.status_code != 200:
            try:
                detail = response.json()
            except ValueError:
                detail = {}
            msg = detail.get("detail") or detail.get("message") or f"API returned status {response.status_code}"
            err_console.print(f"[red]Error: {_safe(str(msg), max_len=600)}[/red]")
            sys.exit(1)

        try:
            return response.json()
        except ValueError:
            err_console.print("[red]Error: Invalid profile response[/red]")
            sys.exit(1)


_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_MAX_FIELD_LEN = 600
_MAX_LIST_ITEMS = 30


def _safe(value: Any, max_len: int = _MAX_FIELD_LEN) -> str:
    """Return a string safe to interpolate into Rich markup or terminal output.

    Defends against three classes of injection from server-controlled fields:

    1. Rich markup injection (``[red]EVIL[/red]`` → forged colors / clickable
       phishing links) — escaped via ``rich.markup.escape``.
    2. ANSI escape sequences (``\\x1b[...m``) and other control characters
       that could rewrite the terminal beyond the rendered region.
    3. Unbounded length leading to render-time DoS — truncated to
       ``max_len`` with an ellipsis.

    Always coerces to ``str`` first; ``None`` becomes ``''``. Use this on
    any value that originates from the API, threat-intel sources, or any
    non-local trust boundary before placing it into an f-string with
    Rich markup brackets.
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    value = _CONTROL_CHAR_RE.sub("", value)
    if len(value) > max_len:
        value = value[: max_len - 1] + "…"
    return rich_escape(value)


def _safe_url(value: Any) -> Optional[str]:
    """Return ``value`` if it parses as http/https with a host, else ``None``.

    Defends against ``[link=file:///etc/passwd]click[/link]``-style phishing
    where the server places an attacker-chosen URL into a field the CLI
    would otherwise render as a clickable hyperlink. Only ``http`` and
    ``https`` schemes survive; ``file``, ``javascript``, ``data``, ``ftp``,
    etc. are rejected.
    """
    if not value or not isinstance(value, str):
        return None
    cleaned = _CONTROL_CHAR_RE.sub("", value).strip()
    if len(cleaned) > 500:
        return None
    try:
        parsed = urlparse(cleaned)
    except (TypeError, ValueError):
        return None
    if parsed.scheme.lower() not in ("http", "https"):
        return None
    if not parsed.hostname:
        return None
    return cleaned


VERDICT_STYLES = {
    "malicious": ("red", "MALICIOUS"),
    "suspicious": ("yellow", "SUSPICIOUS"),
    "benign": ("green", "BENIGN"),
    "inconclusive": ("dim", "INCONCLUSIVE"),
}


def _verdict_style(verdict: str) -> tuple:
    return VERDICT_STYLES.get((verdict or "").lower(), ("dim", verdict.upper() if verdict else "UNKNOWN"))


def _confidence_bar(confidence: int) -> str:
    confidence = max(0, min(100, int(confidence or 0)))
    filled = confidence // 10
    bar = "█" * filled + "░" * (10 - filled)
    if confidence >= 70:
        color = "green"
    elif confidence >= 40:
        color = "yellow"
    else:
        color = "red"
    return f"[{color}]{bar}[/{color}] {confidence}%"


_VALID_ENGINE_NAMES = {"scout", "hunter", "sage"}


def _format_engine_line(results: Dict[str, Any]) -> str:
    """Render the "Engine: Sheep Hunter" sub-header.

    Two surfaces:
    - ``served_by`` (the engine that actually ran) → "Engine: Sheep Hunter".
    - ``requested_model`` (only present when the server downgraded from
      the asked tier) → appended downgrade notice in yellow.

    Returns an empty string when the response carries no engine info
    (older server / cached path) so the header stays clean.
    """
    served_by_raw = (results.get("served_by") or "").strip().lower()
    if served_by_raw not in _VALID_ENGINE_NAMES:
        return ""
    label = served_by_raw.capitalize()
    line = f"[bold]Engine:[/bold] Sheep {label}"
    requested_raw = (results.get("requested_model") or "").strip().lower()
    if (
        requested_raw
        and requested_raw in _VALID_ENGINE_NAMES
        and requested_raw != served_by_raw
    ):
        line += (
            f"  [yellow](requested {requested_raw.capitalize()}, "
            f"downgraded to {label})[/yellow]"
        )
    return line


def _render_structured(results: Dict[str, Any], structured: Dict[str, Any]) -> None:
    target = _safe(results.get("target", ""), max_len=200)
    ioc_type = _safe(results.get("type", ""), max_len=40)

    verdict_color, verdict_label = _verdict_style(structured.get("verdict", ""))
    confidence = structured.get("confidence", 0)

    header_lines = [
        f"[bold {verdict_color}]Verdict:[/bold {verdict_color}] [{verdict_color}]{verdict_label}[/{verdict_color}]",
        f"[bold]Confidence:[/bold] {_confidence_bar(confidence)}",
    ]
    served_line = _format_engine_line(results)
    if served_line:
        header_lines.append(served_line)
    summary = _safe((structured.get("summary") or "").strip(), max_len=600)
    if summary:
        header_lines.append("")
        header_lines.append(summary)

    title = f"Analysis: {target}" if target else "IOC Analysis"
    if ioc_type:
        title += f"  [dim]({ioc_type})[/dim]"

    console.print(Panel("\n".join(header_lines), title=title, border_style=verdict_color, expand=True))

    findings = [_safe(f, max_len=300) for f in (structured.get("key_findings") or [])[:_MAX_LIST_ITEMS] if f]
    findings = [f for f in findings if f]
    if findings:
        body = "\n".join(f"  • {f}" for f in findings)
        console.print(Panel(body, title="Key Findings", border_style="cyan", expand=True))

    iocs = [i for i in (structured.get("iocs_extracted") or [])[:_MAX_LIST_ITEMS]
            if isinstance(i, dict) and i.get("value")]
    if iocs:
        ioc_table = Table(title="Extracted IoCs", show_header=True, header_style="bold cyan", expand=True)
        ioc_table.add_column("Type", style="cyan", width=10)
        ioc_table.add_column("Value", style="white", overflow="fold")
        for item in iocs:
            ioc_table.add_row(
                Text(_CONTROL_CHAR_RE.sub("", str(item.get("type", "?")))[:40]),
                Text(_CONTROL_CHAR_RE.sub("", str(item.get("value", "")))[:200]),
            )
        console.print(ioc_table)

    techniques = [_safe(t, max_len=40) for t in (structured.get("mitre_techniques") or [])[:_MAX_LIST_ITEMS] if t]
    techniques = [t for t in techniques if t]
    if techniques:
        body = "  " + "  ".join(f"[bold magenta]{t}[/bold magenta]" for t in techniques)
        console.print(Panel(body, title="MITRE ATT&CK Techniques", border_style="magenta", expand=True))

    recs = [_safe(r, max_len=300) for r in (structured.get("recommendations") or [])[:_MAX_LIST_ITEMS] if r]
    recs = [r for r in recs if r]
    if recs:
        body = "\n".join(f"  • {r}" for r in recs)
        console.print(Panel(body, title="Recommendations", border_style="green", expand=True))

    refs_safe = []
    for r in (structured.get("references") or [])[:_MAX_LIST_ITEMS]:
        url = _safe_url(r)
        if url:
            refs_safe.append(url)
    if refs_safe:
        escaped = [rich_escape(u) for u in refs_safe]
        body = "\n".join(f"  • [link={u}]{u}[/link]" for u in escaped)
        console.print(Panel(body, title="References", border_style="blue", expand=True))

    threat_intel = results.get("threat_intel") or {}
    sources = threat_intel.get("sources") or {}
    if sources:
        ti_table = Table(title="Threat Intelligence Sources", show_header=True, header_style="bold cyan", expand=True)
        ti_table.add_column("Source", style="cyan", width=14)
        ti_table.add_column("Signal", style="white", overflow="fold")
        for src_name, data in list(sources.items())[:_MAX_LIST_ITEMS]:
            if not isinstance(data, dict):
                continue
            signal = _summarize_source(str(src_name), data)
            if signal:
                ti_table.add_row(_safe(src_name, max_len=40), signal)
        if ti_table.row_count:
            console.print(ti_table)

        risk = threat_intel.get("risk_score")
        tags = [_safe(t, max_len=80) for t in (threat_intel.get("tags") or [])[:_MAX_LIST_ITEMS] if t]
        tags = [t for t in tags if t]
        if (isinstance(risk, (int, float)) and risk is not None) or tags:
            footer_parts = []
            if isinstance(risk, (int, float)):
                clamped = max(0, min(100, int(risk)))
                if clamped >= 70:
                    color = "red"
                elif clamped >= 40:
                    color = "yellow"
                else:
                    color = "green"
                footer_parts.append(f"[bold]Risk Score:[/bold] [{color}]{clamped}/100[/{color}]")
            if tags:
                footer_parts.append("[bold]Tags:[/bold] " + ", ".join(f"[yellow]{t}[/yellow]" for t in tags))
            console.print("  " + "    ".join(footer_parts))


def _int_or_none(v: Any) -> Optional[int]:
    """Coerce ``v`` to int when feasible; return ``None`` otherwise.

    Used to harden the threat-intel summarizer against API responses that
    place strings (or worse, Rich-markup strings) in fields the schema
    declares as integers.
    """
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        try:
            return int(v)
        except (ValueError, OverflowError):
            return None
    return None


def _summarize_source(name: str, data: Dict[str, Any]) -> str:
    name = (name or "").lower()
    if name == "virustotal":
        m = _int_or_none(data.get("malicious"))
        s = _int_or_none(data.get("suspicious"))
        h = _int_or_none(data.get("harmless"))
        u = _int_or_none(data.get("undetected"))
        rep = _int_or_none(data.get("reputation"))
        parts = []
        if m is not None or s is not None:
            mal_color = "red" if (m or 0) > 0 else "green"
            parts.append(f"malicious=[{mal_color}]{m or 0}[/{mal_color}]")
            if s:
                parts.append(f"suspicious=[yellow]{s}[/yellow]")
        if h is not None:
            parts.append(f"harmless={h}")
        if u is not None:
            parts.append(f"undetected={u}")
        if rep is not None:
            parts.append(f"reputation={rep}")
        return ", ".join(parts)
    if name == "abuseipdb":
        score = _int_or_none(data.get("abuse_score"))
        reports = _int_or_none(data.get("total_reports"))
        country = _safe(data.get("country"), max_len=80)
        isp = _safe(data.get("isp"), max_len=120)
        parts = []
        if score is not None:
            color = "red" if score >= 50 else ("yellow" if score >= 25 else "green")
            parts.append(f"abuse=[{color}]{score}%[/{color}]")
        if reports is not None:
            parts.append(f"reports={reports}")
        if country:
            parts.append(f"country={country}")
        if isp:
            parts.append(f"ISP={isp}")
        return ", ".join(parts)
    if name == "shodan":
        ports_raw = data.get("ports") or []
        vulns_raw = data.get("vulns") or []
        org = _safe(data.get("org"), max_len=120)
        asn = _safe(data.get("asn"), max_len=40)
        parts = []
        if isinstance(ports_raw, list) and ports_raw:
            ports_safe = [str(p) for p in ports_raw[:8] if _int_or_none(p) is not None]
            if ports_safe:
                parts.append(f"ports={','.join(ports_safe)}")
        if isinstance(vulns_raw, list) and vulns_raw:
            parts.append(f"[red]vulns={len(vulns_raw)}[/red]")
        if asn:
            parts.append(f"ASN={asn}")
        if org:
            parts.append(f"org={org}")
        return ", ".join(parts)
    if name == "otx":
        pulses = _int_or_none(data.get("pulse_count"))
        families_raw = data.get("malware_families") or []
        parts = []
        if pulses is not None:
            color = "red" if pulses > 5 else ("yellow" if pulses > 0 else "green")
            parts.append(f"pulses=[{color}]{pulses}[/{color}]")
        if isinstance(families_raw, list) and families_raw:
            fams = [_safe(f, max_len=60) for f in families_raw[:5] if f]
            fams = [f for f in fams if f]
            if fams:
                parts.append(f"families={','.join(fams)}")
        return ", ".join(parts)
    if name == "whois":
        country = _safe(data.get("country"), max_len=80)
        isp = _safe(data.get("isp"), max_len=120)
        org = _safe(data.get("org"), max_len=120)
        parts = []
        if country:
            parts.append(f"country={country}")
        if isp:
            parts.append(f"ISP={isp}")
        if org and org != isp:
            parts.append(f"org={org}")
        return ", ".join(parts)
    items = []
    for k, v in data.items():
        if k == "source" or v in (None, "", [], {}):
            continue
        if isinstance(v, list):
            v = ",".join(_safe(x, max_len=40) for x in v[:5])
        else:
            v = _safe(v, max_len=120)
        items.append(f"{_safe(k, max_len=40)}={v}")
        if len(items) >= 4:
            break
    return ", ".join(items)



def display_results(results: Dict[str, Any], output_format: str = "pretty"):
    """
    Display analysis results in the specified format.

    Args:
        results: Analysis results from the API
        output_format: Output format (pretty, json, table, stix)
    """
    if output_format == "json":
        console.print_json(json.dumps(results, indent=2))
        return

    if output_format == "stix":
        if results.get("error"):
            err_console.print(Panel(
                f"[red]{_safe(results['error'], max_len=600)}[/red]",
                title="Error",
                border_style="red",
            ))
            sys.exit(1)
        if results.get("type") == "bundle" and "objects" in results:
            sys.stdout.write(json.dumps(results, indent=2, ensure_ascii=False))
            sys.stdout.write("\n")
            return
        err_console.print(Panel(
            "[red]The Sheep API did not return a STIX 2.1 Bundle for "
            "this request.[/red]\n\n"
            "This usually means the API endpoint is older than "
            "expected and does not understand the [cyan]?format=stix[/cyan] "
            "query parameter. Make sure your [cyan]--api-url[/cyan] points "
            "to a current Sheep API deployment, or fall back to "
            "[cyan]--output json[/cyan] / [cyan]pretty[/cyan].\n\n"
            f"Support: {SUPPORT_EMAIL}",
            title="STIX response unavailable",
            border_style="red",
        ))
        sys.exit(1)

    if results.get("error"):
        err_console.print(Panel(
            f"[red]{_safe(results['error'], max_len=600)}[/red]",
            title="Error",
            border_style="red",
        ))
        return

    structured = results.get("structured_analysis")
    if output_format == "pretty":
        if isinstance(structured, dict) and structured:
            _render_structured(results, structured)
            return

        target_safe = _safe(results.get("target", ""), max_len=200)
        title = f"Analysis: {target_safe}" if target_safe else "IOC Analysis"
        engine_line = _format_engine_line(results)
        if engine_line:
            console.print(engine_line)
        analysis_md = results.get("analysis") or results.get("summary") or ""
        if analysis_md:
            if not isinstance(analysis_md, str):
                analysis_md = str(analysis_md)
            analysis_md = _CONTROL_CHAR_RE.sub("", analysis_md)
            if len(analysis_md) > 20000:
                analysis_md = analysis_md[:20000] + "\n\n…[truncated]"
            console.print(Panel(
                Markdown(analysis_md, hyperlinks=False),
                title=title,
                border_style="green",
                expand=True,
            ))
        else:
            console.print(Panel("[yellow]No analysis content returned.[/yellow]", title=title, border_style="yellow"))
        return

    if output_format == "table":
        if isinstance(structured, dict) and structured:
            payload = {
                "target": results.get("target"),
                "type": results.get("type"),
                "verdict": structured.get("verdict"),
                "confidence": structured.get("confidence"),
                "summary": structured.get("summary"),
                "key_findings": structured.get("key_findings"),
                "iocs_extracted": structured.get("iocs_extracted"),
                "mitre_techniques": structured.get("mitre_techniques"),
                "recommendations": structured.get("recommendations"),
                "references": structured.get("references"),
            }
        else:
            payload = {k: v for k, v in results.items() if k not in ("analysis", "threat_intel", "structured")}

        table = Table(show_header=True, header_style="bold cyan", expand=True)
        table.add_column("Field", style="cyan", width=24)
        table.add_column("Value", overflow="fold")

        def flatten(d, parent=""):
            for k, v in d.items():
                key = f"{parent}.{k}" if parent else k
                if isinstance(v, dict):
                    yield from flatten(v, key)
                elif isinstance(v, list):
                    if not v:
                        yield key, "(empty)"
                    else:
                        for i, item in enumerate(v):
                            sub = f"{key}[{i}]"
                            if isinstance(item, dict):
                                yield from flatten(item, sub)
                            else:
                                yield sub, str(item)
                else:
                    yield key, "" if v is None else str(v)

        for key, value in flatten(payload):
            table.add_row(Text(key[:80]), Text(_CONTROL_CHAR_RE.sub("", value)[:600]))

        console.print(table)


def display_profile(profile: Dict[str, Any]) -> None:
    """Render the /api/profile payload as a human-readable summary."""
    plan = profile.get("plan") or {}
    sub = profile.get("subscription") or {}
    usage = profile.get("usage") or {}
    addons = profile.get("addons") or []

    plan_name = _safe(plan.get("name") or plan.get("id") or "unknown", max_len=80)
    allowed = [_safe(m, max_len=40) for m in (plan.get("allowed_models") or [])[:_MAX_LIST_ITEMS] if m]
    allowed_str = ", ".join(allowed) if allowed else "auto"

    consumed = max(0, _int_or_none(usage.get("current_period_tokens")) or 0)
    budget = max(0, _int_or_none(usage.get("current_period_budget")) or 0)
    remaining = max(0, _int_or_none(usage.get("tokens_remaining")) or 0)
    status_safe = _safe(sub.get("status", "unknown"), max_len=40)
    period_end_safe = _safe(sub.get("current_period_end", "—"), max_len=80)
    if budget > 0:
        pct = min(100, int(consumed * 100 / budget))
        bar_len = 20
        filled = int(pct * bar_len / 100)
        bar = "█" * filled + "░" * (bar_len - filled)
        if pct >= 90:
            bar_color = "red"
        elif pct >= 70:
            bar_color = "yellow"
        else:
            bar_color = "cyan"
        usage_line = f"[{bar_color}]{bar}[/{bar_color}]  {consumed:,} / {budget:,} tokens ({pct}%)"
    else:
        usage_line = f"{consumed:,} tokens consumed (budget unknown)"

    body_lines = [
        f"[bold]Plan:[/bold] {plan_name}",
        f"[bold]Status:[/bold] {status_safe}",
        f"[bold]Period ends:[/bold] {period_end_safe}",
        "",
        f"[bold]Allowed models:[/bold] [cyan]{allowed_str}[/cyan]",
        "",
        f"[bold]Period usage[/bold]",
        usage_line,
        f"[bold]Remaining:[/bold] {remaining:,} tokens",
    ]
    if addons:
        addon_lines = []
        for a in addons[:_MAX_LIST_ITEMS]:
            if not isinstance(a, dict):
                continue
            name = _safe(a.get("name") or a.get("id") or "?", max_len=80)
            extra = max(0, _int_or_none(a.get("extra_tokens_period")) or 0)
            addon_lines.append(f"  • {name}: +{extra:,} tokens")
        if addon_lines:
            body_lines.append("")
            body_lines.append("[bold]Active add-ons:[/bold]")
            body_lines.extend(addon_lines)

    console.print(Panel(
        "\n".join(body_lines),
        title=f"Sheep Profile · {plan_name}",
        border_style="green",
    ))


def init_config():
    """Initialize configuration file with example settings.

    Writes the file with mode 0600 atomically (open with O_CREAT | O_TRUNC
    | O_NOFOLLOW + mode argument). The user is expected to paste a real
    token here later, so the file must already be unreadable to other
    users from creation — never write a placeholder with 0644 then chmod.
    """
    config_dir = Path(DEFAULT_CONFIG_FILE).expanduser().parent
    config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(config_dir, 0o700)
    except OSError:
        pass

    config_path = Path(DEFAULT_CONFIG_FILE).expanduser()

    if config_path.exists():
        console.print(f"[yellow]Configuration file already exists at {config_path}[/yellow]")
        try:
            overwrite = console.input("Do you want to overwrite it? (y/N): ")
        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]Cancelled[/yellow]")
            return
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

    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    fd = os.open(str(config_path), flags, 0o600)
    try:
        with os.fdopen(fd, 'w') as f:
            config.write(f)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    try:
        os.chmod(config_path, 0o600)
    except OSError:
        pass

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
  %(prog)s plan                              # Show plan, quota and allowed models

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
        help=(
            "API authentication token. Convenient for one-shot calls; "
            "for daily use prefer `python3 setup.py` (encrypted at rest) "
            "or the SHEEP_API_TOKEN env var, since command-line flags "
            "are visible in process listings (ps, /proc/<pid>/cmdline)."
        ),
    )

    parser.add_argument(
        "--api-url",
        help=f"API endpoint URL (default: {DEFAULT_API_URL})"
    )

    parser.add_argument(
        "-o", "--output",
        choices=["pretty", "json", "table", "stix"],
        default="pretty",
        help=(
            "Output format. pretty (default) renders a colored summary; "
            "json emits the raw Sheep schema; table emits a tabular view; "
            "stix emits a STIX 2.1 Bundle (Indicator / Vulnerability / "
            "AttackPattern / Note SDOs) ready to import in MISP, OpenCTI, "
            "TheHive or any TAXII-aware tool."
        ),
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
[bold cyan]Sheep Analyze v{VERSION}[/bold cyan]
IOC analysis client for the Sheep API

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
        console.print(Panel(about_info, title="About Sheep Analyze", style="cyan"))
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
        script_dir = Path(__file__).resolve().parent
        subprocess.call([sys.executable, str(script_dir / "setup.py")])
        return

    if args.update:
        check_for_updates()
        return

    if args.init:
        init_config()
        return

    if not args.target:
        parser.error("Target IOC is required (use --help for options)")

    if args.target.strip().lower() == "plan":
        try:
            analyzer = IOCAnalyzer(api_token=args.token, api_url=args.api_url)
            profile = analyzer.profile()
            if args.output == "json":
                console.print_json(json.dumps(profile, indent=2))
            else:
                display_profile(profile)
            return
        except ValueError as e:
            console.print(f"[red]Error: {str(e)}[/red]")
            sys.exit(1)
        except KeyboardInterrupt:
            console.print("\n[yellow]Cancelled by user[/yellow]")
            sys.exit(0)

    try:
        analyzer = IOCAnalyzer(api_token=args.token, api_url=args.api_url)
        wire_format = "stix" if args.output == "stix" else "markdown"
        results = analyzer.analyze(args.target, args.type, api_format=wire_format)
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
