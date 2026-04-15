#!/usr/bin/env python3
"""
Analyze-CLI Interactive Setup Wizard
Copyright (c) 2026 byFranke - Security Solutions
"""

import os
import sys
import subprocess
import platform
from pathlib import Path
from getpass import getpass
import base64
import configparser

def check_dependencies():
    """Check if required packages are installed"""
    required = ['rich', 'cryptography', 'keyring', 'GitPython']
    missing = []

    for package in required:
        try:
            __import__(package.replace('GitPython', 'git'))
        except ImportError:
            missing.append(package)

    if missing:
        print("Installing missing dependencies...")
        print(f"Missing packages: {', '.join(missing)}")

        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install"] + missing + ["--user"],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                if "externally-managed-environment" in result.stderr:
                    print("\nYour system uses externally managed Python.")
                    print("Options:")
                    print("1. Use --break-system-packages (may affect system):")
                    print(f"   {sys.executable} -m pip install -r requirements.txt --break-system-packages")
                    print("\n2. Use a virtual environment (recommended):")
                    print("   python3 -m venv venv")
                    print("   source venv/bin/activate")
                    print("   pip install -r requirements.txt")
                    print("   python setup.py")
                    print("\n3. Use system packages:")
                    print("   sudo apt install python3-rich python3-cryptography python3-keyring python3-git")
                    sys.exit(1)
                else:
                    raise subprocess.CalledProcessError(result.returncode, result.args, result.stderr)

            print("Dependencies installed successfully!")
            print("\nPlease restart the setup:")
            print(f"  {sys.executable} setup.py")
            sys.exit(0)
        except subprocess.CalledProcessError as e:
            print(f"Error installing dependencies")
            print("\nPlease install manually:")
            print(f"  pip install -r requirements.txt")
            sys.exit(1)

check_dependencies()

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

try:
    import keyring
    KEYRING_AVAILABLE = True
except ImportError:
    KEYRING_AVAILABLE = False

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False

try:
    import git
    GIT_AVAILABLE = True
except ImportError:
    GIT_AVAILABLE = False

console = Console()

GITHUB_REPO = "https://github.com/byfranke/analyze-cli"
CONFIG_DIR = Path.home() / ".analyze-cli"
CONFIG_FILE = CONFIG_DIR / "config.ini"
KEY_FILE = CONFIG_DIR / ".key"
VERSION_FILE = Path(__file__).parent / "VERSION"
PRIVACY_POLICY = "https://sheep.byfranke.com/pages/privacy.html"
TERMS_OF_SERVICE = "https://sheep.byfranke.com/pages/terms.html"
SUPPORT_EMAIL = "support@byfranke.com"


class SecureTokenManager:
    """Manages encrypted token storage"""

    def __init__(self):
        self.config_dir = CONFIG_DIR
        self.key_file = KEY_FILE
        self.config_dir.mkdir(exist_ok=True)

    def _get_or_create_key(self, password: str) -> bytes:
        """Get or create encryption key from password"""
        if not ENCRYPTION_AVAILABLE:
            raise ImportError("Cryptography library not available")

        salt = b'analyze-cli-salt-2026'  # Static salt for this app
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def encrypt_token(self, token: str, password: str) -> str:
        """Encrypt token with password"""
        if not ENCRYPTION_AVAILABLE:
            raise ImportError("Cryptography library not available")

        key = self._get_or_create_key(password)
        f = Fernet(key)
        encrypted = f.encrypt(token.encode())
        return base64.b64encode(encrypted).decode()

    def decrypt_token(self, encrypted_token: str, password: str) -> str:
        """Decrypt token with password"""
        if not ENCRYPTION_AVAILABLE:
            return None

        try:
            key = self._get_or_create_key(password)
            f = Fernet(key)
            encrypted = base64.b64decode(encrypted_token.encode())
            decrypted = f.decrypt(encrypted)
            return decrypted.decode()
        except Exception:
            return None

    def save_encrypted_token(self, token: str, password: str):
        """Save encrypted token to config"""
        encrypted = self.encrypt_token(token, password)

        config = configparser.ConfigParser()
        if CONFIG_FILE.exists():
            config.read(CONFIG_FILE)

        if 'api' not in config:
            config['api'] = {}

        config['api']['encrypted_token'] = encrypted
        config['api']['encryption_enabled'] = 'true'

        with open(CONFIG_FILE, 'w') as f:
            config.write(f)

        os.chmod(CONFIG_FILE, 0o600)

    def use_system_keyring(self, token: str):
        """Store token in system keyring"""
        if not KEYRING_AVAILABLE:
            console.print("[yellow]Warning: Keyring module not available[/yellow]")
            return False

        try:
            keyring.set_password("analyze-cli", "api_token", token)
            return True
        except Exception as e:
            console.print(f"[yellow]Warning: Could not use system keyring: {e}[/yellow]")
            return False


class AnalyzeSetup:
    """Interactive setup wizard for Analyze-CLI"""

    def __init__(self):
        self.token_manager = SecureTokenManager()
        self.current_version = self.get_current_version()

    def get_current_version(self) -> str:
        """Get current installed version"""
        if VERSION_FILE.exists():
            return VERSION_FILE.read_text().strip()
        return "1.1.0"

    def display_welcome(self):
        """Display welcome message with privacy notice"""
        console.clear()

        header = "ANALYZE-CLI SETUP WIZARD v1.0\nIOC Analysis & Threat Intelligence"
        console.print(Panel(header, style="bold cyan"))

        privacy_notice = f"""
[bold]Privacy & Legal Notice:[/bold]
• Privacy Policy: {PRIVACY_POLICY}
• Terms of Service: {TERMS_OF_SERVICE}
• Support: {SUPPORT_EMAIL}
• License: byFranke License (see LICENSE file)

By continuing, you agree to our terms and privacy policy.
        """
        console.print(Panel(privacy_notice, title="Legal Information", style="yellow"))

        if not Confirm.ask("\n[bold]Do you accept the terms and want to continue?[/bold]"):
            console.print("[red]Setup cancelled.[/red]")
            sys.exit(0)

    def check_python_version(self):
        """Check if Python version is compatible"""
        version = sys.version_info
        if version.major < 3 or (version.major == 3 and version.minor < 7):
            console.print("[red]Error: Python 3.7 or higher is required[/red]")
            sys.exit(1)
        console.print(f"[green][OK][/green] Python {version.major}.{version.minor}.{version.micro} detected")

    def check_if_dependencies_installed(self):
        """Check if all required dependencies are installed"""
        required = ['rich', 'cryptography', 'keyring', 'git']

        for package in required:
            try:
                __import__(package)
            except ImportError:
                return False

        console.print("[green][OK][/green] Dependencies already installed")
        return True

    def install_dependencies(self):
        """Install Python dependencies"""
        console.print("\n[bold cyan]Installing Dependencies[/bold cyan]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Installing packages...", total=None)

            try:
                result = subprocess.run(
                    [sys.executable, "-m", "pip", "install", "-r", "requirements.txt", "--user"],
                    capture_output=True,
                    text=True
                )

                if result.returncode == 0:
                    progress.update(task, completed=True)
                    console.print("[green][OK][/green] Dependencies installed successfully")
                    return

                if "externally-managed-environment" in result.stderr:
                    progress.stop()
                    console.print("\n[yellow]System uses externally managed Python (PEP 668)[/yellow]")

                    if Confirm.ask("\nWould you like to install with --break-system-packages?"):
                        progress.start()
                        result2 = subprocess.run(
                            [sys.executable, "-m", "pip", "install", "-r", "requirements.txt", "--break-system-packages"],
                            capture_output=True,
                            text=True
                        )

                        if result2.returncode == 0:
                            progress.update(task, completed=True)
                            console.print("[green][OK][/green] Dependencies installed successfully")
                            return
                        else:
                            progress.stop()
                            console.print(f"[red]Installation failed: {result2.stderr}[/red]")

                    console.print("\n[yellow]Alternative installation methods:[/yellow]")
                    console.print("\n1. Use a virtual environment (recommended):")
                    console.print("   python3 -m venv venv")
                    console.print("   source venv/bin/activate")
                    console.print("   pip install -r requirements.txt")
                    console.print("   python setup.py")
                    console.print("\n2. Install system packages:")
                    console.print("   sudo apt install python3-rich python3-cryptography python3-keyring python3-git")
                    console.print("\n3. Force install (may affect system):")
                    console.print("   pip3 install -r requirements.txt --break-system-packages")
                    sys.exit(1)
                else:
                    progress.stop()
                    console.print(f"[red]Error installing dependencies: {result.stderr}[/red]")
                    sys.exit(1)

            except Exception as e:
                progress.stop()
                console.print(f"[red]Unexpected error: {e}[/red]")
                sys.exit(1)

    def configure_token(self):
        """Configure API token with encrypted storage"""
        console.print("\n[bold cyan]API Token Configuration[/bold cyan]")
        console.print("Your API token will be encrypted and password-protected.\n")

        if not ENCRYPTION_AVAILABLE:
            console.print("[red]Error: Encryption libraries not available.[/red]")
            console.print("Please install: pip3 install cryptography --break-system-packages")
            return False

        console.print("[yellow]Enter your API token (hidden for security):[/yellow]")
        token = getpass("Token: ").strip()

        if not token:
            console.print("[red]Error: Token cannot be empty[/red]")
            return False

        console.print("\n[bold]Set a master password for token encryption[/bold]")
        console.print("[dim]This password will be required to decrypt your token[/dim]")

        while True:
            password = getpass("Master Password (min 8 chars): ")
            confirm = getpass("Confirm Password: ")

            if password != confirm:
                console.print("[red]Passwords don't match. Try again.[/red]")
                continue

            if len(password) < 8:
                console.print("[red]Password must be at least 8 characters[/red]")
                continue

            break

        self.token_manager.save_encrypted_token(token, password)
        console.print("[green][OK][/green] Token encrypted and saved securely")
        console.print("[yellow]Note: You'll need to enter your master password when using the CLI[/yellow]")

        return True

    def check_for_updates(self):
        """Check for updates from GitHub"""
        console.print("\n[bold cyan]Checking for Updates[/bold cyan]")

        if not GIT_AVAILABLE:
            console.print("[yellow]Git module not available - using alternative method[/yellow]")
            console.print(f"Please check for updates manually at: {GITHUB_REPO}")
            return

        try:
            install_dir = Path.home() / ".analyze-cli"

            if (install_dir / ".git").exists():
                console.print("Pulling latest updates...")
                repo = git.Repo(install_dir)
                origin = repo.remotes.origin
                origin.pull()
                console.print("[green][OK][/green] Updated successfully!")
            else:
                console.print(f"[yellow]Repository not found at {install_dir}[/yellow]")
                console.print(f"To reinstall, run:")
                console.print(f"  curl -fsSL https://raw.githubusercontent.com/byfranke/analyze-cli/main/install.sh | bash")
                return

            version_file = install_dir / "VERSION"
            if version_file.exists():
                new_version = version_file.read_text().strip()
                if new_version != self.current_version:
                    console.print(f"[green]Updated to version {new_version}[/green]")
                else:
                    console.print(f"[green][OK][/green] Already at latest version ({self.current_version})")

        except Exception as e:
            console.print(f"[yellow]Could not check for updates: {e}[/yellow]")

    def check_system_installation(self):
        """Check if analyze-cli is accessible from PATH"""
        console.print("\n[bold cyan]Checking Installation[/bold cyan]")
        
        try:
            result = subprocess.run(
                ["which", "analyze-cli"],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                console.print(f"[green][OK][/green] analyze-cli is available at: {result.stdout.strip()}")
                return True
            else:
                console.print("[yellow]analyze-cli not found in PATH[/yellow]")
                console.print("To reinstall, run:")
                console.print("  curl -fsSL https://raw.githubusercontent.com/byfranke/analyze-cli/main/install.sh | bash")
                return False
        except Exception:
            return False

    def display_summary(self):
        """Display setup summary and next steps"""
        console.print("\n" + "="*50)
        console.print(Panel("[bold green]Setup Completed Successfully![/bold green]", style="green"))

        guide = f"""
[bold]Quick Start Guide:[/bold]

1. Test your installation:
   [cyan]analyze-cli --version[/cyan]

2. Analyze an IOC:
   [cyan]analyze-cli 8.8.8.8[/cyan]
   [cyan]analyze-cli example.com[/cyan]
   [cyan]analyze-cli CVE-2021-44228[/cyan]

3. Get help:
   [cyan]analyze-cli --help[/cyan]

4. Check for updates:
   [cyan]python3 setup.py --update[/cyan]

[bold]Support:[/bold]
- Documentation: {GITHUB_REPO}
- Email: {SUPPORT_EMAIL}
- Privacy: {PRIVACY_POLICY}
"""
        console.print(guide)

    def run(self):
        """Run the complete setup wizard"""
        self.display_welcome()

        console.print("\n[bold]Starting Setup Process...[/bold]\n")

        self.check_python_version()

        if not self.check_if_dependencies_installed():
            self.install_dependencies()

        self.configure_token()

        if Confirm.ask("\n[bold]Check for updates from GitHub?[/bold]"):
            self.check_for_updates()

        self.check_system_installation()

        self.display_summary()


def main():
    """Main entry point for setup"""
    import argparse

    parser = argparse.ArgumentParser(description="Analyze-CLI Setup Wizard")
    parser.add_argument("--update", action="store_true", help="Check and install updates")
    parser.add_argument("--configure-token", action="store_true", help="Reconfigure API token")
    parser.add_argument("--version", action="store_true", help="Show version")

    args = parser.parse_args()

    setup = AnalyzeSetup()

    if args.version:
        console.print(f"Analyze-CLI Setup v{setup.current_version}")
        return

    if args.update:
        setup.check_for_updates()
        return

    if args.configure_token:
        setup.configure_token()
        return

    try:
        setup.run()
    except KeyboardInterrupt:
        console.print("\n[yellow]Setup cancelled by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]Setup failed: {e}[/red]")
        console.print("[yellow]Please check the error and try again[/yellow]")
        sys.exit(1)


if __name__ == "__main__":
    main()
