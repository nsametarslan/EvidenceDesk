"""Small pre-publication heuristic scan; never prints matched secret values."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = {'.git', '.venv', '__pycache__', '.pytest_cache', 'build', 'dist'}
PATTERNS = {
    'private key': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    'GitHub token': re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,})\b'),
    'AWS access key': re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
    'literal credential': re.compile(r'''(?im)^\s*(?:password|api_key|access_token|secret_key)\s*[:=]\s*["'][^"'\n]{8,}["']'''),
}


def main():
    problems = []
    scanned = 0
    for path in sorted(ROOT.rglob('*')):
        if not path.is_file() or any(p in EXCLUDED or p.endswith('.egg-info') for p in path.relative_to(ROOT).parts):
            continue
        if path.suffix.lower() in {'.sqlite3', '.db', '.pem', '.key', '.env'} or path.name.startswith('.env'):
            problems.append((str(path.relative_to(ROOT)), 'sensitive file type'))
            continue
        if path.suffix.lower() in {'.png', '.jpg', '.jpeg'}:
            continue
        scanned += 1
        try:
            text = path.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            problems.append((str(path.relative_to(ROOT)), 'unreviewed binary'))
            continue
        for name, expression in PATTERNS.items():
            if expression.search(text):
                problems.append((str(path.relative_to(ROOT)), name))
    for filename, kind in problems:
        print(f'REVIEW {filename}: {kind}')
    print(f'{scanned} text files scanned; {len(problems)} items require review. Heuristic scan, not a security guarantee.')
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
