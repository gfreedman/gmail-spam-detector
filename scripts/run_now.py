#!/usr/bin/env python3
"""
Run the deployed script NOW, on the latest pushed code, and prove it (v6.115.0).

    python3 scripts/run_now.py

1. Calls scriptVersion() through the Apps Script API (`clasp run`, devMode = the latest pushed code,
   owner only; appsscript.json executionApi MYSELF) and compares it with SCRIPT_VERSION in the local
   versionFile. A mismatch, or "function not found", means the API is NOT running the latest code:
   it stops without running anything. (v6.111.0's web-app path silently ran a frozen version.)
2. Runs processInbox() the same way and reports errors.

Needs the `runner` clasp login: `clasp login --user runner --use-project-scopes --creds <client>.json`
with the OAuth client of the script's Cloud project (spam-detector-486300). Exit 0 = ran on the
expected version; 1 = refused or failed.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'scripts'))
import sources  # noqa: E402

CLASP = ['npx', '-y', '@google/clasp@3.3.0', 'run-function', '--user', 'runner', '--json']


def run(fn, timeout):
    p = subprocess.run(CLASP + [fn], cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    out = p.stdout.strip()
    try:
        data = json.loads(out[out.index('{'):]) if '{' in out else {}
    except ValueError:
        data = {}
    return p.returncode, data, (out + '\n' + p.stderr).strip()


def main():
    text = Path(sources.version_file_path()).read_text(encoding='utf-8')
    local = re.search(r"const SCRIPT_VERSION = '([0-9.]+)';", text).group(1)

    code, data, raw = run('scriptVersion', 120)
    live = data.get('response')
    if code != 0 or data.get('error') or live != local:
        print(f'REFUSED: the API is not running the latest code (live={live!r}, local={local!r}).')
        print(raw[-600:])
        return 1
    print(f'live code is {live} - running processInbox')

    code, data, raw = run('processInbox', 400)
    if code != 0 or data.get('error'):
        print('processInbox FAILED:')
        print(raw[-800:])
        return 1
    print(f'processInbox ran on {live}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
