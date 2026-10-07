#!/usr/bin/env python3
"""
Follow a "Deploy to Google Apps Script" run and print one progress line per
change, with an ETA:

    v6.71.0  [███░░] 3/5 · validate ✓ · verify-prod running (waiting for 10-min trigger) · ~4m left

Usage:
    python3 scripts/watch_deploy.py            # newest deploy.yml run
    python3 scripts/watch_deploy.py <run-id>

Why the ETA is not just "median job time": verify-prod polls until the
10-minute Apps Script trigger runs the new version, so its length depends on
WHEN in the trigger cycle the deploy landed. The health marker in Drive
(the same one prod_health.py reads) carries the last run's timestamp; the next
run is due 10 minutes after it. Every other job uses the median of recent
successful runs.

Prints a heartbeat at most every HEARTBEAT_S even when nothing changed, so a
watcher never goes silent for minutes. Exits 0 on success, 1 on failure.
Needs `gh` (authenticated) and, for the trigger estimate only, `rclone`.
"""
import json
import re
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone

WORKFLOW = 'deploy.yml'
JOB_ORDER = ['test', 'deploy', 'validate', 'verify-prod', 'tag']
TRIGGER_PERIOD_S = 600          # the Apps Script trigger runs every 10 minutes
TRIGGER_GRACE_S = 180          # a due run's marker can land this long after the due time
POLL_S = 15
HEARTBEAT_S = 120
HISTORY_RUNS = 6


def gh_json(*args):
    out = subprocess.run(['gh', *args], capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip() or 'gh failed')
    return json.loads(out.stdout)


def parse_ts(s):
    if not s or s.startswith('0001-'):
        return None
    return datetime.fromisoformat(s.replace('Z', '+00:00'))


def median_job_seconds(exclude_id):
    """Median duration per job over recent successful runs."""
    runs = gh_json('run', 'list', '--workflow', WORKFLOW, '--status', 'success',
                   '--limit', str(HISTORY_RUNS + 1), '--json', 'databaseId')
    samples = {}
    for r in runs:
        if r['databaseId'] == exclude_id:
            continue
        for j in gh_json('run', 'view', str(r['databaseId']), '--json', 'jobs')['jobs']:
            a, b = parse_ts(j.get('startedAt')), parse_ts(j.get('completedAt'))
            if a and b:
                samples.setdefault(j['name'], []).append((b - a).total_seconds())
    return {k: statistics.median(v) for k, v in samples.items()}


def next_trigger_at():
    """Due time of the next Apps Script run, from the health marker's name."""
    try:
        out = subprocess.run(['rclone', 'lsf', 'gdrive:Spam Intelligence'],
                             capture_output=True, text=True, timeout=60).stdout
        m = re.search(r'SpamDetector_health_\w+_v[\d.]+_(\S+Z)', out)
        if not m:
            return None
        last = parse_ts(m.group(1))
        now = datetime.now(timezone.utc)
        due = last.timestamp() + TRIGGER_PERIOD_S
        # The run starts AT the due time and its marker lands a minute or two
        # later, so a due time just passed means "any moment", not "next slot".
        # Rolling forward immediately showed "~11m left" seconds before the
        # run finished. Only past the grace window is it a missed beat.
        while due + TRIGGER_GRACE_S < now.timestamp():
            due += TRIGGER_PERIOD_S
        return due
    except Exception:
        return None


def fmt_dur(s):
    s = max(0, int(s))
    return f'{-(-s // 60)}m' if s >= 60 else '<1m'


def main():
    if len(sys.argv) > 1:
        run_id = int(sys.argv[1])
    else:
        run_id = gh_json('run', 'list', '--workflow', WORKFLOW, '--limit', '1',
                         '--json', 'databaseId')[0]['databaseId']

    medians = median_job_seconds(run_id)
    last_line, last_print = None, 0.0
    trigger_due, trigger_checked = None, 0.0

    while True:
        run = gh_json('run', 'view', str(run_id), '--json',
                      'status,conclusion,displayTitle,jobs')
        title = run['displayTitle']
        version = re.match(r'(v\d+\.\d+\.\d+)', title)
        label = version.group(1) if version else title[:40]
        jobs = {j['name']: j for j in run['jobs']}
        now = time.time()

        done = [n for n in JOB_ORDER if jobs.get(n, {}).get('status') == 'completed']
        failed = [n for n in done if jobs[n].get('conclusion') not in ('success', 'skipped')]
        running = [n for n in JOB_ORDER if jobs.get(n, {}).get('status') == 'in_progress']

        # ETA: remaining median time per unfinished job; verify-prod uses the
        # trigger clock (refreshed at most once a minute — it is an rclone call).
        remaining = 0.0
        for n in JOB_ORDER:
            if n in done:
                continue
            j = jobs.get(n, {})
            elapsed = now - parse_ts(j['startedAt']).timestamp() if parse_ts(j.get('startedAt')) else 0
            if n == 'verify-prod':
                if now - trigger_checked > 60:
                    trigger_due, trigger_checked = next_trigger_at(), now
                # the run after the deploy, plus ~1 min for the marker to land
                est = (trigger_due - now + 60) if trigger_due else medians.get(n, 600) - elapsed
            else:
                est = medians.get(n, 30) - elapsed
            remaining = max(remaining, est) if n in running else remaining + max(est, 0)

        bar = '█' * len(done) + '░' * (len(JOB_ORDER) - len(done))   # fills left to right
        head = f'{label}  [{bar}] {len(done)}/{len(JOB_ORDER)}'
        parts = []
        finished = [n for n in done if n not in failed]
        if finished:                       # the most recently completed job
            last = max(finished, key=lambda n: jobs[n].get('completedAt') or '')
            parts.append(f'{last} ✓')
        parts += [f'{n} ✗' for n in failed]
        parts += [n + ' running' + (' (waiting for 10-min trigger)' if n == 'verify-prod' else '')
                  for n in running]
        if run['status'] != 'completed':
            # remaining <= 0 only when the trigger is due or overdue (within
            # the grace window) and nothing else is left to run.
            parts.append(f'~{fmt_dur(remaining)} left' if remaining > 0 else 'any moment')
        line = ' · '.join([head] + parts)

        if line.split('~')[0] != (last_line or '').split('~')[0] or now - last_print >= HEARTBEAT_S:
            print(line, flush=True)
            last_line, last_print = line, now

        if run['status'] == 'completed':
            ok = run['conclusion'] == 'success'
            bar = '█' * len(JOB_ORDER) if ok else bar
            print(f'{label}  [{bar}] ' + ('done · all jobs passed ✓' if ok
                                          else f'FAILED ({run["conclusion"]}) ✗'), flush=True)
            sys.exit(0 if ok else 1)
        time.sleep(POLL_S)


if __name__ == '__main__':
    main()
