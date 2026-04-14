# Analyze-CLI

A robust command-line interface for analyzing Indicators of Compromise (IOCs) including IPs, domains, hashes, URLs, and CVEs using multiple threat intelligence sources.

<p align="center">
  <a href="https://www.youtube.com/watch?v=-NZARpdcJKk">
    <img src="https://img.youtube.com/vi/-NZARpdcJKk/maxresdefault.jpg" alt="Analyze-CLI — Quick Summary" width="600">
  </a>
</p>

<p align="center">
  <strong>A robust command-line interface for analyzing Indicators of Compromise</strong><br>
  Version 1.0 | byFranke 2026
</p>

---


<img width="2127" height="723" alt="image" src="https://github.com/user-attachments/assets/fd784e35-ada8-41e7-95ae-66363ed2515b" />

---

**About more:** [Analyze Web](https://byfranke.com/pages/analyze.html) | [Sheep Manual](https://github.com/byfranke/sheep)

## Installation

### Prerequisites

- Python 3.7 or higher
- pip package manager

### Install from Source

```bash
# Clone the repository
git clone https://github.com/byfranke/analyze-cli
cd analyze-cli

# Run the interactive setup wizard (recommended)
chmod +x analyze-cli.py setup.py install.sh
bash install.sh
python3 setup.py
```
```
# Or install manually
pip install -r requirements.txt

```

### Install System-wide (Optional)

```bash
# Install to /usr/local/bin for system-wide access
sudo cp analyze-cli.py /usr/local/bin/analyze-cli
sudo chmod +x /usr/local/bin/analyze-cli
```

## Configuration

### Secure Token Setup

Run the interactive setup wizard to configure your encrypted token:

```bash
python3 setup.py
```

The setup will:
- Ask for your [API token](https://sheep.byfranke.com/discord)
- Set a master password for encryption
- Store your token encrypted in `~/.analyze-cli/config.ini`
- Require the master password each time you use the CLI

### Alternative: One-time Use

For single-use or testing, you can pass the token directly:

```bash
./analyze-cli.py --token "your_api_token_here" 185.220.101.45
```

**Security**: Your token is always encrypted and password-protected when stored.

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

### Advanced Options

```bash
# Show help
./analyze-cli.py --help

# Show version
./analyze-cli.py --version
```

### Common Issues

1. **API Token Error**
   ```
   Error: API token is required
   ```
   Solution: Configure your API token using one of the methods described above.

2. **Connection Error**
   ```
   Error: Failed to connect to API server
   ```
   Solution: Check your internet connection and verify the API URL is correct.

3. **Invalid IOC Type**
   ```
   Error: Invalid request
   ```
   Solution: Ensure the IOC format is correct or let the tool auto-detect the type.

4. **Timeout Error**
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
- Store tokens securely using environment variables or protected config files
- Use read-only permissions (400) for config files containing tokens:
  ```bash
  chmod 400 ~/.analyze-cli/config.ini
  ```

  
## Donation Support

This tool is maintained through community support. Help keep it active:

[![Donate](https://img.shields.io/badge/Support-Development-blue?style=for-the-badge&logo=github)](https://buy.byfranke.com/b/8wM03kb3u7THeIgaEE)
