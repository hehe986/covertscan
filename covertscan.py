#!/usr/bin/env python3

import os
import re
import sys
import math
import json
import argparse
import subprocess
from datetime import datetime
from pathlib import Path

try:
    import yaml
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    print("Missing dependencies. Run: pip install pyyaml colorama")
    sys.exit(1)

# ─────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────

BANNER = r"""
   ██████╗ ██████╗ ██╗   ██╗███████╗██████╗ ████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔════╝██╔═══██╗██║   ██║██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██║     ██║   ██║██║   ██║█████╗  ██████╔╝   ██║   ███████╗██║     ███████║██╔██╗ ██║
  ██║     ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗   ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
  ╚██████╗╚██████╔╝ ╚████╔╝ ███████╗██║  ██║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
   ╚═════╝ ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
"""

def print_banner():
    print(Fore.CYAN + BANNER)
    print(Fore.CYAN + "  CovertScan - Hardcoded Secrets & Credential Scanner")
    print(Fore.CYAN + "  Author  : H1lm1.exe")
    print(Fore.CYAN + "  Version : 1.0.0")
    print(Fore.CYAN + "  Target  : Files · Folders · Git History · .env")
    print(Fore.CYAN + "  " + "─" * 60)
    print()

# ─────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────

SKIP_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg',
    '.mp4', '.mp3', '.avi', '.mov', '.zip', '.tar', '.gz',
    '.pdf', '.exe', '.bin', '.dll', '.so', '.pyc', '.class',
    '.lock', '.sum', '.woff', '.woff2', '.ttf', '.eot',
}

SKIP_DIRS = {
    'node_modules', '.git', '__pycache__', '.idea', '.vscode',
    'venv', 'env', 'dist', 'build', 'vendor', 'target',
    'coverage', '.pytest_cache', '.mypy_cache',
}

ENTROPY_THRESHOLD = 4.2
MIN_ENTROPY_LENGTH = 16
CONTEXT_LINES = 2  # lines to show around a finding

# Known false positive values — skip these even if pattern matches
FALSE_POSITIVE_VALUES = {
    'changeme', 'password', 'secret', 'example', 'placeholder',
    'your_api_key', 'your-api-key', 'xxxxxxxxxxxx', 'xxxxxxxxxxxxxxxx',
    'insert_your', 'insert-your', 'replace_me', 'replace-me',
    'api_key_here', 'token_here', 'sk-xxxxxxxx', 'dummy', 'test',
    'sample', 'demo', 'fake', 'none', 'null', 'undefined', 'todo',
    '1234567890', 'abcdefghij', 'aaaaaaaaaa', '0000000000',
    'your_secret', 'my_secret', 'my_password', 'my_api_key',
}

FALSE_POSITIVE_PATTERNS = [
    re.compile(r'^(.)\1{7,}$'),           # repeating single char: aaaaaaaa
    re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I),  # UUID
    re.compile(r'^\$\{.+\}$'),            # shell/template variable: ${VAR}
    re.compile(r'^\{\{.+\}\}$'),          # template variable: {{VAR}}
    re.compile(r'^<.+>$'),               # placeholder: <YOUR_KEY>
    re.compile(r'^%\w+%$'),              # Windows env var: %VAR%
]

SEVERITY_COLOR = {
    'CRITICAL': Fore.RED,
    'HIGH':     Fore.YELLOW,
    'MEDIUM':   Fore.MAGENTA,
    'LOW':      Fore.BLUE,
}

SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}

# ─────────────────────────────────────────────
#  LOAD RULES
# ─────────────────────────────────────────────

def load_rules(rules_path: str) -> list:
    with open(rules_path, 'r') as f:
        data = yaml.safe_load(f)
    rules = []
    for rule in data.get('rules', []):
        rules.append({
            'name': rule['name'],
            'severity': rule['severity'],
            'pattern': re.compile(rule['pattern'])
        })
    return rules

# ─────────────────────────────────────────────
#  FALSE POSITIVE FILTER
# ─────────────────────────────────────────────

def is_false_positive(value: str) -> bool:
    v = value.strip().strip('"\'').lower()
    if v in FALSE_POSITIVE_VALUES:
        return True
    if len(v) < 6:
        return True
    for pat in FALSE_POSITIVE_PATTERNS:
        if pat.match(v):
            return True
    return False

# ─────────────────────────────────────────────
#  ENTROPY
# ─────────────────────────────────────────────

def shannon_entropy(string: str) -> float:
    if not string:
        return 0.0
    freq = {}
    for ch in string:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(string)
    entropy = 0.0
    for count in freq.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return entropy

def find_high_entropy_strings(line: str) -> list:
    found = []
    patterns = [
        r'["\']([A-Za-z0-9+/=_\-\.]{%d,})["\']' % MIN_ENTROPY_LENGTH,
        r'(?<![A-Za-z0-9])([A-Za-z0-9+/=_\-\.]{%d,})(?![A-Za-z0-9])' % MIN_ENTROPY_LENGTH,
    ]
    seen = set()
    for pat in patterns:
        for match in re.finditer(pat, line):
            candidate = match.group(1) if match.lastindex else match.group(0)
            if len(candidate) >= MIN_ENTROPY_LENGTH and candidate not in seen:
                seen.add(candidate)
                if is_false_positive(candidate):
                    continue
                entropy = shannon_entropy(candidate)
                if entropy >= ENTROPY_THRESHOLD:
                    found.append((candidate, round(entropy, 2)))
    return found

# ─────────────────────────────────────────────
#  MASK VALUE
# ─────────────────────────────────────────────

def mask_value(value: str) -> str:
    v = value.strip()
    if len(v) <= 6:
        return '*' * len(v)
    return v[:4] + '*' * (len(v) - 6) + v[-2:]

# ─────────────────────────────────────────────
#  DEDUPLICATION KEY
# ─────────────────────────────────────────────

def dedup_key(finding: dict) -> tuple:
    return (finding['file'], finding['line'], finding['rule'])

# ─────────────────────────────────────────────
#  SCAN FILE
# ─────────────────────────────────────────────

def scan_file(filepath: str, rules: list, entropy: bool) -> list:
    findings = []
    seen_keys = set()

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            all_lines = f.readlines()
    except Exception:
        return findings

    is_env_file = Path(filepath).suffix == '' and Path(filepath).name.startswith('.env') \
                  or Path(filepath).suffix in {'.env'}

    for lineno, line in enumerate(all_lines, start=1):
        line_stripped = line.strip()
        if not line_stripped:
            continue
        # Skip comment lines (but not in .env files — comments there are #KEY=val)
        if not is_env_file and line_stripped.startswith('#'):
            continue

        # Context lines (lines around the finding)
        ctx_start = max(0, lineno - 1 - CONTEXT_LINES)
        ctx_end   = min(len(all_lines), lineno - 1 + CONTEXT_LINES + 1)
        context   = [l.rstrip() for l in all_lines[ctx_start:ctx_end]]

        # .env file: parse KEY=VALUE
        if is_env_file and '=' in line_stripped and not line_stripped.startswith('#'):
            parts = line_stripped.split('=', 1)
            if len(parts) == 2:
                val = parts[1].strip().strip('"\'')
                if val and not is_false_positive(val) and shannon_entropy(val) >= 3.5:
                    key = (filepath, lineno, '.env Key')
                    if key not in seen_keys:
                        seen_keys.add(key)
                        findings.append({
                            'type': 'env_file',
                            'file': filepath,
                            'line': lineno,
                            'rule': f'.env Credential ({parts[0].strip()})',
                            'severity': 'HIGH',
                            'value': mask_value(val),
                            'raw': val,
                            'context': context,
                        })

        # Pattern matching
        for rule in rules:
            match = rule['pattern'].search(line)
            if match:
                value = match.group(0)
                if is_false_positive(value):
                    continue
                key = dedup_key({'file': filepath, 'line': lineno, 'rule': rule['name']})
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append({
                    'type': 'pattern',
                    'file': filepath,
                    'line': lineno,
                    'rule': rule['name'],
                    'severity': rule['severity'],
                    'value': mask_value(value),
                    'raw': value,
                    'context': context,
                })

        # Entropy analysis
        if entropy:
            for candidate, ent in find_high_entropy_strings(line):
                already = any(candidate in f.get('raw', '') for f in findings if f['line'] == lineno)
                if already:
                    continue
                key = (filepath, lineno, f'entropy:{candidate[:8]}')
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append({
                    'type': 'entropy',
                    'file': filepath,
                    'line': lineno,
                    'rule': f'High Entropy String (entropy={ent})',
                    'severity': 'MEDIUM',
                    'value': mask_value(candidate),
                    'raw': candidate,
                    'context': context,
                })

    return findings

# ─────────────────────────────────────────────
#  CRAWL PATH
# ─────────────────────────────────────────────

def crawl_path(root: str, rules: list, entropy: bool) -> list:
    all_findings = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            ext = Path(filename).suffix.lower()
            if ext in SKIP_EXTENSIONS:
                continue
            filepath = os.path.join(dirpath, filename)
            findings = scan_file(filepath, rules, entropy)
            all_findings.extend(findings)
    return all_findings

# ─────────────────────────────────────────────
#  GIT HISTORY SCAN
# ─────────────────────────────────────────────

def scan_git_history(repo_path: str, rules: list, entropy: bool) -> list:
    all_findings = []
    seen_keys = set()

    try:
        result = subprocess.run(
            ['git', '-C', repo_path, 'log', '--all', '--oneline'],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print(Fore.RED + "  [!] Not a git repository or git not found.")
            return []

        commits = [line.split()[0] for line in result.stdout.strip().splitlines()]
        print(Fore.CYAN + f"  [*] Scanning {len(commits)} commits in git history...")

        for commit in commits:
            diff_result = subprocess.run(
                ['git', '-C', repo_path, 'show', '--unified=0', commit],
                capture_output=True, text=True, errors='ignore'
            )
            lines = diff_result.stdout.splitlines()
            for lineno, line in enumerate(lines, start=1):
                if not line.startswith('+') or line.startswith('+++'):
                    continue
                clean_line = line[1:]

                for rule in rules:
                    match = rule['pattern'].search(clean_line)
                    if match:
                        value = match.group(0)
                        if is_false_positive(value):
                            continue
                        key = (commit, lineno, rule['name'])
                        if key in seen_keys:
                            continue
                        seen_keys.add(key)
                        all_findings.append({
                            'type': 'git_history',
                            'file': f'[commit:{commit}]',
                            'line': lineno,
                            'rule': rule['name'],
                            'severity': rule['severity'],
                            'value': mask_value(value),
                            'raw': value,
                            'context': [clean_line],
                        })

                if entropy:
                    for candidate, ent in find_high_entropy_strings(clean_line):
                        key = (commit, lineno, f'entropy:{candidate[:8]}')
                        if key in seen_keys:
                            continue
                        seen_keys.add(key)
                        all_findings.append({
                            'type': 'git_history_entropy',
                            'file': f'[commit:{commit}]',
                            'line': lineno,
                            'rule': f'High Entropy String (entropy={ent})',
                            'severity': 'MEDIUM',
                            'value': mask_value(candidate),
                            'raw': candidate,
                            'context': [clean_line],
                        })

    except FileNotFoundError:
        print(Fore.RED + "  [!] git not found. Install git to use --git-history.")
    return all_findings

# ─────────────────────────────────────────────
#  PRINT RESULTS
# ─────────────────────────────────────────────

def print_results(findings: list, show_context: bool):
    if not findings:
        print(Fore.GREEN + "\n  [✓] No secrets found.\n")
        return

    findings.sort(key=lambda x: SEVERITY_ORDER.get(x['severity'], 99))

    print()
    for f in findings:
        color = SEVERITY_COLOR.get(f['severity'], Fore.WHITE)
        badge = f"[{f['severity']}]"
        print(color + f"  {badge:<12} {f['file']}  line {f['line']}")
        print(color + f"  {'':12} Rule  : {f['rule']}")
        print(color + f"  {'':12} Value : {f['value']}")
        if show_context and f.get('context'):
            print(Fore.WHITE + Style.DIM + f"  {'':12} Context:")
            for ctx_line in f['context']:
                print(Fore.WHITE + Style.DIM + f"  {'':14} {ctx_line}")
        print()

def print_summary(findings: list, elapsed: float):
    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    type_counts = {}
    for f in findings:
        sev = f['severity']
        if sev in counts:
            counts[sev] += 1
        t = f['type']
        type_counts[t] = type_counts.get(t, 0) + 1

    print(Fore.CYAN + "  " + "─" * 60)
    print(Fore.CYAN + "  SUMMARY")
    print(Fore.CYAN + "  " + "─" * 60)
    print(Fore.RED    + f"  CRITICAL : {counts['CRITICAL']}")
    print(Fore.YELLOW + f"  HIGH     : {counts['HIGH']}")
    print(Fore.MAGENTA+ f"  MEDIUM   : {counts['MEDIUM']}")
    print(Fore.BLUE   + f"  LOW      : {counts['LOW']}")
    print(Fore.WHITE  + f"  TOTAL    : {len(findings)}")
    print(Fore.WHITE  + f"  TYPES    : " + " | ".join(f"{k}:{v}" for k, v in type_counts.items()))
    print(Fore.CYAN   + f"  TIME     : {elapsed:.2f}s")
    print(Fore.CYAN + "  " + "─" * 60)
    print()

# ─────────────────────────────────────────────
#  EXPORT
# ─────────────────────────────────────────────

def export_json(findings: list, path: str):
    output = []
    for f in findings:
        output.append({
            'severity': f['severity'],
            'rule': f['rule'],
            'file': f['file'],
            'line': f['line'],
            'value': f['value'],
            'type': f['type'],
        })
    with open(path, 'w') as out:
        json.dump({'timestamp': datetime.now().isoformat(), 'findings': output}, out, indent=2)
    print(Fore.GREEN + f"  [✓] JSON exported: {path}")

def export_csv(findings: list, path: str):
    with open(path, 'w') as out:
        out.write("severity,rule,file,line,value,type\n")
        for f in findings:
            val = f['value'].replace(',', ';')
            rule = f['rule'].replace(',', ';')
            out.write(f"{f['severity']},{rule},{f['file']},{f['line']},{val},{f['type']}\n")
    print(Fore.GREEN + f"  [✓] CSV exported: {path}")

# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description='CovertScan - Hardcoded Secrets & Credential Scanner',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('--path',        required=True,  help='Target file or directory to scan')
    parser.add_argument('--git-history', action='store_true', help='Also scan git commit history')
    parser.add_argument('--entropy',     action='store_true', help='Enable entropy analysis for unknown secrets')
    parser.add_argument('--context',     action='store_true', help='Show context lines around findings')
    parser.add_argument('--output',      choices=['json', 'csv'], help='Export results (json or csv)')
    parser.add_argument('--rules',       default=os.path.join(os.path.dirname(__file__), 'patterns', 'rules.yaml'),
                        help='Path to custom rules.yaml')
    parser.add_argument('--severity',    choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                        help='Filter output by minimum severity')
    args = parser.parse_args()

    # Load rules
    if not os.path.exists(args.rules):
        print(Fore.RED + f"  [!] Rules file not found: {args.rules}")
        sys.exit(1)
    rules = load_rules(args.rules)
    print(Fore.CYAN + f"  [*] Loaded {len(rules)} detection rules")

    # Validate path
    if not os.path.exists(args.path):
        print(Fore.RED + f"  [!] Path not found: {args.path}")
        sys.exit(1)

    print(Fore.CYAN + f"  [*] Scanning  : {args.path}")
    if args.entropy:
        print(Fore.CYAN + f"  [*] Entropy   : ON (threshold={ENTROPY_THRESHOLD})")
    if args.git_history:
        print(Fore.CYAN + f"  [*] Git scan  : ON")
    if args.context:
        print(Fore.CYAN + f"  [*] Context   : ON ({CONTEXT_LINES} lines)")
    if args.severity:
        print(Fore.CYAN + f"  [*] Filter    : {args.severity}+")
    print()

    start = datetime.now()

    # Scan
    findings = []
    if os.path.isfile(args.path):
        findings = scan_file(args.path, rules, args.entropy)
    else:
        findings = crawl_path(args.path, rules, args.entropy)

    # Git history
    if args.git_history:
        git_findings = scan_git_history(args.path, rules, args.entropy)
        findings.extend(git_findings)

    # Severity filter
    if args.severity:
        order = SEVERITY_ORDER
        min_order = order.get(args.severity, 99)
        findings = [f for f in findings if order.get(f['severity'], 99) <= min_order]

    elapsed = (datetime.now() - start).total_seconds()

    # Print
    print_results(findings, show_context=args.context)
    print_summary(findings, elapsed)

    # Export
    if args.output and findings:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        outfile = f"covertscan_{timestamp}.{args.output}"
        if args.output == 'json':
            export_json(findings, outfile)
        elif args.output == 'csv':
            export_csv(findings, outfile)

if __name__ == '__main__':
    main()
