# Sheep Analyze CLI

Command-line client for the Sheep API focused on Indicator of Compromise (IOC) analysis: IPs, domains, file hashes, URLs and CVEs. Each request is enriched with threat intelligence and answered by a Sheep AI model with both a human-readable narrative and a SOAR-friendly structured payload.

<p align="center">
  <a href="https://www.youtube.com/watch?v=-NZARpdcJKk">
    <img src="https://img.youtube.com/vi/-NZARpdcJKk/maxresdefault.jpg" alt="Sheep Analyze CLI — quick summary" width="600">
  </a>
</p>

<p align="center">
  <strong>IOC analysis from your terminal, powered by the Sheep API.</strong><br>
  Version 1.3 | byFranke 2026
</p>

---

<img width="2127" height="723" alt="image" src="https://github.com/user-attachments/assets/fd784e35-ada8-41e7-95ae-66363ed2515b" />

---

**More:** [Analyze Web](https://byfranke.com/pages/analyze.html) | [Sheep Docs](https://github.com/byfranke/sheep)

## Installation

### Prerequisites

- Python 3.7 or higher
- pip

### Quick install

```bash
curl -fsSL https://raw.githubusercontent.com/byfranke/sheep-analyze-cli/main/install.sh | bash
```

### Install from source

```bash
git clone https://github.com/byfranke/sheep-analyze-cli
cd sheep-analyze-cli
chmod +x analyze-cli.py setup.py install.sh
bash install.sh
python3 setup.py
```

The installer creates two symlinks: `analyze` (canonical) and `analyze-cli` (legacy alias kept for backwards compatibility). Use whichever you prefer — every example below uses `analyze`.

## Configuration

### Encrypted setup (recommended)

```bash
python3 setup.py
```

The wizard will:
- Ask for your [API token](https://sheep.byfranke.com/pages/store)
- Set a master password for encryption
- Store the encrypted token at `~/.analyze/config.ini`
- Cache the decrypted token in `/tmp` (mode `0600`, scoped to the current shell session) so you only type the master password once per terminal

### One-shot

```bash
analyze --token "YOUR_TOKEN" 185.220.101.45
```

Or via environment variable:

```bash
export SHEEP_API_TOKEN="YOUR_TOKEN"
analyze 185.220.101.45
```

The legacy variable `ANALYZE_API_TOKEN` is still accepted with a deprecation warning and will be removed in v1.5. `SHEEP_API_TOKEN` is the same variable used by every other Sheep CLI.

**Storage:** the token is encrypted using PBKDF2-SHA256 (600,000 iterations) with a per-install random salt and Fernet (AES-128 + HMAC-SHA256).

**Upgrading from analyze-cli 1.2:** the new config dir is `~/.analyze/`. The CLI keeps reading `~/.analyze-cli/config.ini` if it exists, so you can upgrade without re-running setup. Re-run `python3 setup.py` whenever you want to migrate.

## Usage

### Basic

```bash
analyze 185.220.101.45                  # IP (auto-detected)
analyze example.com                     # Domain
analyze d41d8cd98f00b204e9800998ecf8427e  # MD5 hash
analyze https://suspicious-site.com/m   # URL
analyze CVE-2021-44228                  # CVE
```

### Which Sheep model is used

Every `/analyze` call is served by the **Sheep Hunter** model. The CLI does not expose a model selector here — analysis is opinionated by design so latency, depth and billing stay consistent across calls. If you need the lighter Scout model or the heavier Sage model, use the `/ask` surface (see [Sheep Ask CLI](https://github.com/byfranke/sheep-ask-cli)) where the model selector is exposed.

### Output formats

```bash
analyze 8.8.8.8                  # Pretty (default)
analyze 8.8.8.8 --output json    # JSON, for automation / SOAR
analyze 8.8.8.8 --output table   # Tabular summary
analyze 8.8.8.8 --output stix    # STIX 2.1 Bundle (MISP / OpenCTI / TheHive)
```

The pretty output shows the verdict, confidence, the Sheep model that served the request, an executive summary, key findings, extracted IoCs, MITRE ATT&CK techniques, recommendations and references.

### STIX 2.1 interop

`--output stix` emits a STIX 2.1 Bundle (OASIS spec) on stdout, ready to feed into any tool that speaks STIX: MISP, OpenCTI, TheHive, Cortex Analyzers, ThreatConnect, Anomali, or your own TAXII collection. The mapping is:

- **Identity** SDO — names the producer ("Sheep AI").
- **Indicator** SDO — one per IOC, with a real STIX pattern (`[ipv4-addr:value = '…']`, `[domain-name:value = '…']`, `[file:hashes.'SHA-256' = '…']`, `[url:value = '…']`).
- **Vulnerability** SDO — for CVE targets, with `external_references` to NVD.
- **AttackPattern** SDO — one per MITRE ATT&CK technique, with `external_references` to the ATT&CK registry.
- **Relationship** SDO — wires secondary IOCs and ATT&CK techniques back to the primary indicator (`related-to`).
- **Note** SDO — recommended actions, attached to the primary indicator.
- Verdict (`malicious` / `suspicious` / `benign` / `inconclusive`) is rendered as the STIX `indicator-type-ov` label.
- Confidence (0–100) propagates to the Indicator / Vulnerability `confidence` field.

Quick pipe-to-file example:

```bash
analyze 8.8.8.8 --output stix > ioc.json
# Push to MISP via misp-stix-converter, OpenCTI via its STIX2 connector,
# TheHive 5 via Cortex, or any TAXII 2.1 server with curl.
```

The exporter requires the [`stix2`](https://stix2.readthedocs.io/) library (already in `requirements.txt`). If it is missing, `--output stix` exits with a clear "Missing dependency" message and the pip command to install it.

### Plan and quota

```bash
analyze plan
```

Shows your plan name, status, period end, the models your plan allows, and the current token usage / remaining budget.

### Session management

```bash
analyze --logout
```

Clears the cached decrypted token for the current terminal only. The next call will prompt for the master password again.

### Maintenance

```bash
analyze --help        # Show help
analyze --version     # Show version
analyze --setup       # Re-run the interactive setup wizard
analyze --update      # Pull the latest version from GitHub
```

## Common errors

1. **API token missing** — Configure your token with `python3 setup.py`, the `--token` flag or the `SHEEP_API_TOKEN` env var. New tokens at https://sheep.byfranke.com/pages/store.

2. **HTTP 401 — Authentication failed** — Token missing, expired or revoked. Re-run `python3 setup.py` with a fresh token.

3. **HTTP 403 — Plan does not cover this request** — Upgrade at https://sheep.byfranke.com/pages/store.

4. **HTTP 429 — Rate limit exceeded** — Wait a minute. If it happens often, upgrade your plan.

5. **Connection error** — Check your internet connection.

6. **Invalid IOC type** — Make sure the IOC format is correct, or let the auto-detector handle it.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

## Security considerations

- **Never commit your API token** to version control.
- Store tokens securely with the setup wizard (encrypted) or `SHEEP_API_TOKEN`.
- Keep restrictive permissions on the config file:
  ```bash
  chmod 600 ~/.analyze/config.ini
  ```
- The session token cache lives at `/tmp/analyze-cli-sess-<uid>-<sid>` with mode `0600`, scoped to your current shell session. Run `analyze --logout` to clear it early.

## Donation support

This tool is maintained through community support. Help keep it active:

[![Donate](https://img.shields.io/badge/Support-Development-blue?style=for-the-badge&logo=github)](https://buy.byfranke.com/b/8wM03kb3u7THeIgaEE)
