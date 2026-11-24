#!/usr/bin/env python3
"""
Warn (never fail) when the IANA_TLDS snapshot behind Signal 18 needs refreshing.

Signal 18 (fakeTldSender, Text.gs) treats a TLD missing from IANA_TLDS as fake. Two ways the
snapshot goes wrong, and this prints a GitHub ::warning:: for each:

  - IANA DELEGATED a TLD after the snapshot. The dangerous direction: mail from it looks fake.
    (A TLD IANA retired only costs a miss, so it is reported as a note, not a warning.)
  - The snapshot is close to TLD_SNAPSHOT_MAX_AGE_DAYS old, after which the signal abstains and
    the Spam-folder fast path for this mill goes silent - with every test still green, because the
    suites freeze the clock.

Always exits 0: a network blip or an IANA change must never block a deploy. CI runs it in the
test job. To refresh: replace IANA_TLDS in Domains.gs from the IANA file and bump TLD_SNAPSHOT_DATE.
"""
import datetime
import re
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import sources  # noqa: E402

IANA_URL = 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt'
WARN_DAYS_BEFORE_EXPIRY = 35


def main():
    src = sources.concat_source()
    block = re.search(r'const IANA_TLDS = Object\.freeze\(\[(.*?)\]\);', src, re.S)
    date = re.search(r"const TLD_SNAPSHOT_DATE = '([0-9-]+)';", src)
    max_age = re.search(r'const TLD_SNAPSHOT_MAX_AGE_DAYS = (\d+);', src)
    if not (block and date and max_age):
        print('::warning::check_tld_snapshot: could not find IANA_TLDS / TLD_SNAPSHOT_DATE in the source')
        return
    ours = set(re.findall(r"'([^']+)'", block.group(1)))

    snap = datetime.date.fromisoformat(date.group(1))
    expires = snap + datetime.timedelta(days=int(max_age.group(1)))
    left = (expires - datetime.date.today()).days
    if left <= WARN_DAYS_BEFORE_EXPIRY:
        print(f'::warning::IANA_TLDS snapshot ({snap}) expires {expires} ({left} days): Signal 18 then '
              'stops firing. Refresh it from ' + IANA_URL)
    else:
        print(f'TLD snapshot {snap}: Signal 18 active until {expires} ({left} days)')

    try:
        with urllib.request.urlopen(IANA_URL, timeout=20) as r:
            text = r.read().decode('ascii', 'replace')
    except Exception as e:  # never block a deploy on the network
        print(f'::notice::check_tld_snapshot: could not fetch the IANA list ({e}); skipped the diff')
        return
    live = {l.strip().lower() for l in text.splitlines() if l.strip() and not l.startswith('#')}
    if len(live) < 1000:
        print(f'::notice::check_tld_snapshot: IANA list looked truncated ({len(live)} entries); skipped')
        return
    added, removed = sorted(live - ours), sorted(ours - live)
    if added:
        print(f'::warning::IANA delegated {len(added)} TLD(s) not in IANA_TLDS, which Signal 18 would treat '
              f'as fake: {", ".join(added[:20])}. Refresh the snapshot in Domains.gs.')
    if removed:
        print(f'::notice::IANA retired {len(removed)} TLD(s) still in IANA_TLDS (harmless): {", ".join(removed[:20])}')
    if not added and not removed:
        print(f'IANA_TLDS matches the live root zone ({len(live)} TLDs)')


if __name__ == '__main__':
    main()
