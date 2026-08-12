<p align="center"><pre>
   ██████╗ ██████╗ ██╗   ██╗███████╗██████╗ ████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔════╝██╔═══██╗██║   ██║██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██║     ██║   ██║██║   ██║█████╗  ██████╔╝   ██║   ███████╗██║     ███████║██╔██╗ ██║
  ██║     ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗   ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
  ╚██████╗╚██████╔╝ ╚████╔╝ ███████╗██║  ██║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
   ╚═════╝ ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
</pre></p>

<h1 align="center">CovertScan 👻</h1>
<p align="center">Scan your codebase for hardcoded secrets before attackers do.</p>
<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-blue?style=flat-square&logo=python">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20Any%20Distro-informational?style=flat-square">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square">
  <img src="https://img.shields.io/badge/rules-66%2B-red?style=flat-square">
  <img src="https://img.shields.io/badge/version-2.0.0-orange?style=flat-square">
</p>

---

```
  ╔════════════════════════════════════════════════════════════╗
  ║  files/folders  ──▶  pattern match  ──▶  entropy analysis ║
  ║  git history    ──▶  .env parser    ──▶  false pos filter ║
  ║                            ↓                               ║
  ║          CRITICAL  /  HIGH  /  MEDIUM  /  LOW              ║
  ╚════════════════════════════════════════════════════════════╝
```

## What is CovertScan?

CovertScan scans your source code, folders, and git history for **hardcoded secrets** —
API keys, tokens, passwords, private keys, and database credentials that were accidentally
left in code and could be exploited if pushed to a public repository.

## Features

| Feature | Description |
|---------|-------------|
| 🔍 Pattern Matching | 66+ rules — AWS, OpenAI, GitHub, Stripe, Cloudflare, Anthropic, dll |
| 🎲 Entropy Analysis | Detect unknown secrets by randomness level (Shannon entropy) |
| 📜 Git History Scan | Scan old commits — even deleted secrets are traceable |
| 🌿 .env File Parser | Dedicated parser for `KEY=VALUE` format |
| 🚫 False Positive Filter | Skip `changeme`, `example`, `${VAR}`, `{{VAR}}`, `<KEY>`, dll |
| 📊 Severity Rating | CRITICAL / HIGH / MEDIUM / LOW |
| 🔎 Context Lines | Show surrounding lines around each finding |
| 📁 Export | JSON / CSV |

## Supported Secret Types

```
  AWS · Google · OpenAI · Anthropic · GitHub · GitLab
  Slack · Stripe · Twilio · SendGrid · Mailgun · Cloudflare
  DigitalOcean · HuggingFace · Firebase · Heroku · NPM
  Shopify · JWT · RSA/EC/DSA/OpenSSH Private Keys
  PostgreSQL · MySQL · MongoDB · Redis · MSSQL
  Generic: password · api_key · secret · token · bearer
```

## Install

```bash
git clone https://github.com/hehe986/covertscan.git
cd covertscan
bash install.sh
```

> **Kali Linux / Ubuntu / Debian:**
> ```bash
> pip install -r requirements.txt --break-system-packages
> ```

> **Arch Linux / Manjaro:**
> ```bash
> pip install -r requirements.txt --break-system-packages
> ```

> **Fedora / RHEL / CentOS:**
> ```bash
> pip3 install -r requirements.txt
> ```

> **openSUSE:**
> ```bash
> pip3 install -r requirements.txt
> ```

> **Universal (semua distro) — via venv:**
> ```bash
> python3 -m venv venv
> source venv/bin/activate
> pip install -r requirements.txt
> ```

## Usage

```bash
# Scan folder
python covertscan.py --path /project/myapp

# Scan single file
python covertscan.py --path config.py

# Scan + entropy analysis
python covertscan.py --path /project/myapp --entropy

# Scan + git history
python covertscan.py --path /project/myapp --git-history

# Show context lines around findings
python covertscan.py --path /project/myapp --context

# Filter only CRITICAL findings
python covertscan.py --path /project/myapp --severity CRITICAL

# Export to JSON
python covertscan.py --path /project/myapp --output json

# Full scan
python covertscan.py --path /project/myapp --entropy --git-history --context --output json
```

## Output Example

```
   ██████╗ ██████╗ ██╗   ██╗███████╗██████╗ ████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
  ...

  CovertScan - Hardcoded Secrets & Credential Scanner
  Author  : H1lm1.exe
  Version : 2.0.0
  ────────────────────────────────────────────────────────────

  [*] Loaded 66 detection rules
  [*] Scanning  : /project/myapp

  [CRITICAL]   /src/config.py  line 12
               Rule  : AWS Access Key ID
               Value : AKIA****XXXX

  [CRITICAL]   /src/db.py  line 34
               Rule  : PostgreSQL Connection String
               Value : post****st

  [HIGH]       /src/auth.py  line 8
               Rule  : Generic API Key in Code
               Value : API_****key"

  ────────────────────────────────────────────────────────────
  SUMMARY
  ────────────────────────────────────────────────────────────
  CRITICAL : 2
  HIGH     : 1
  MEDIUM   : 0
  LOW      : 0
  TOTAL    : 3
  TIME     : 0.42s
  ────────────────────────────────────────────────────────────
```

## Author

```
  ╔══════════════════════════════════╗
  ║  H1lm1.exe                       ║
  ║  Informatics Engineering         ║
  ║  Universitas Amikom Yogyakarta   ║
  ╚══════════════════════════════════╝
```

> ⚠️ For educational and authorized security testing purposes only.
