# CovertScan 👻
> Hardcoded Secrets & Credential Scanner

CovertScan scans files, folders, and git history for hardcoded secrets, credentials, and sensitive data left in source code.

## Features
- Pattern matching (30+ rules): AWS, GitHub, JWT, DB URLs, API keys, dll
- Entropy analysis — detect unknown secrets by randomness level
- Git history scan — cek commit lama yang sudah dihapus sekalipun
- Severity rating: CRITICAL / HIGH / MEDIUM / LOW
- Export: JSON / CSV

## Install

```bash
git clone https://github.com/H1lm1exe/covertscan
cd covertscan
pip install -r requirements.txt
```

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

# Export hasil ke JSON
python covertscan.py --path /project/myapp --output json

# Export hasil ke CSV
python covertscan.py --path /project/myapp --output csv

# Full scan
python covertscan.py --path /project/myapp --entropy --git-history --output json
```

## Output Example

```
  [CRITICAL]   /src/config.py  line 12
               Rule  : AWS Access Key
               Value : AKIA****XXXX

  [HIGH]       /src/db.py  line 34
               Rule  : Database URL (PostgreSQL)
               Value : post****st

  ────────────────────────────────────────────────────────────
  SUMMARY
  ────────────────────────────────────────────────────────────
  CRITICAL : 2
  HIGH     : 1
  MEDIUM   : 0
  LOW      : 0
  TOTAL    : 3
  TIME     : 0.42s
```

## Author
- **H1lm1.exe**
- Informatics Engineering — Universitas Amikom Yogyakarta
