# Analyze-CLI

A robust command-line interface for analyzing Indicators of Compromise (IOCs) including IPs, domains, hashes, URLs, and CVEs using multiple threat intelligence sources.

<p align="center">
  <a href="https://www.youtube.com/watch?v=-NZARpdcJKk">
    <img src="https://img.youtube.com/vi/-NZARpdcJKk/maxresdefault.jpg" alt="Analyze-CLI — Quick Summary" width="600">
  </a>
</p>

<p align="center">
  <strong>A robust command-line interface for analyzing Indicators of Compromise</strong><br>
  Version 1.2 | byFranke 2026
</p>

---


<img width="2127" height="723" alt="image" src="https://github.com/user-attachments/assets/fd784e35-ada8-41e7-95ae-66363ed2515b" />

---

**About more:** [Analyze Web](https://byfranke.com/pages/analyze.html) | [Sheep Manual](https://github.com/byfranke/sheep)

## Installation

### Prerequisites

- Python 3.7 or higher
- pip package manager

### Get Analyze CLI

```bash
# Run the interactive setup wizard (recommended)
curl -fsSL https://byfranke.com/analyze-cli-install | bash
```

### Install from Source

```bash
# Or install manually
git clone https://github.com/byfranke/analyze-cli
cd analyze-cli
chmod +x analyze-cli.py setup.py install.sh
bash install.sh
python3 setup.py
```

## Configuration

### Secure Token Setup

Run the interactive setup wizard to configure your encrypted token:

```bash
python3 setup.py
```

The setup will:
- Ask for your [API token](https://sheep.byfranke.com/pages/store)
- Set a master password for encryption
- Store your token encrypted in `~/.analyze-cli/config.ini`
- Require the master password **only once per terminal session** (cached in `/tmp` with mode `0600`, scoped to your shell's Session ID)

### Alternative: One-time Use

For single-use or testing, you can pass the token directly:

```bash
./analyze-cli.py --token "your_api_token_here" 185.220.101.45
```

Or via environment variable:

```bash
export SHEEP_API_TOKEN="your_api_token_here"
./analyze-cli.py 185.220.101.45
```

> The legacy variable `ANALYZE_API_TOKEN` is still accepted but prints a deprecation warning. It will be removed in v1.5. The same `SHEEP_API_TOKEN` works across every Sheep CLI.

**Security**: Your token is always encrypted and password-protected when stored. Encryption uses PBKDF2-SHA256 (600,000 iterations) with a per-install random salt and Fernet (AES-128 + HMAC-SHA256).

## Usage

### Basic Usage

```bash
# Analyze an IP address (auto-detect type)
./analyze-cli.py 185.220.101.45

# Analyze a domain
./analyze-cli.py example.com

# Analyze a file hash
./analyze-cli.py d41d8cd98f00b204e9800998ecf8427e

# Analyze a URL
./analyze-cli.py https://suspicious-site.com/malware

# Analyze a CVE
./analyze-cli.py CVE-2021-44228
```

### Output Formats

```bash
# Pretty output (default) - colored terminal output
./analyze-cli.py 8.8.8.8

# JSON output - for parsing and automation
./analyze-cli.py 8.8.8.8 --output json

# Table output - simple tabular format
./analyze-cli.py 8.8.8.8 --output table
```

### Session Management

```bash
# Clear the cached decrypted token for the current terminal only
./analyze-cli.py --logout
```

After logout the next call will prompt for the master password again.

### Maintenance

```bash
# Show help
./analyze-cli.py --help

# Show version
./analyze-cli.py --version

# Re-run the setup wizard
./analyze-cli.py --setup

# Check for updates from GitHub
./analyze-cli.py --update
```

### Common Issues

1. **API Token Error**
   ```
   Error: API token is required
   ```
   Solution: Configure your API token using one of the methods described above, or upgrade your plan at https://sheep.byfranke.com/pages/store.

2. **Authentication failed (HTTP 401)**
   ```
   Invalid API token. Your token is missing, expired, or no longer valid.
   ```
   Solution: Re-run `python3 setup.py` with a fresh token, or get/upgrade one at https://sheep.byfranke.com/pages/store.

3. **Plan does not cover this request (HTTP 403)**
   ```
   Forbidden — your plan doesn't cover this request.
   ```
   Solution: Upgrade your plan at https://sheep.byfranke.com/pages/store.

4. **Too many requests (HTTP 429)**
   ```
   Rate limit exceeded.
   ```
   Solution: Wait a minute. If it happens often, upgrade your plan at https://sheep.byfranke.com/pages/store.

5. **Connection Error**
   ```
   Error: Failed to connect to API server
   ```
   Solution: Check your internet connection and verify the API URL is correct.

6. **Invalid IOC Type**
   ```
   Error: Invalid request
   ```
   Solution: Ensure the IOC format is correct or let the tool auto-detect the type.

7. **Timeout Error**
   ```
   Error: Request timed out
   ```
   Solution: The analysis is taking longer than expected. Try again or check if the service is available.

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

## Security Considerations

- **Never commit your API token** to version control
- Store tokens securely using the setup wizard (encrypted) or `SHEEP_API_TOKEN`
- Use restrictive permissions for config files:
  ```bash
  chmod 600 ~/.analyze-cli/config.ini
  ```
- Session token cache lives in `/tmp/analyze-cli-sess-<uid>-<sid>` with mode `0600` and is bound to your current shell's Session ID. Run `--logout` to clear it early.

  
## Donation Support

This tool is maintained through community support. Help keep it active:

[![Donate](https://img.shields.io/badge/Support-Development-blue?style=for-the-badge&logo=github)](https://buy.byfranke.com/b/8wM03kb3u7THeIgaEE)
