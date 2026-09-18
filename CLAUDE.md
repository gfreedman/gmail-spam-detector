# Gmail Spam Detector — working notes for Claude

This script **permanently deletes the user's email**. Every rule below exists
because something went wrong once. Read the whole file before changing anything
in the deploy path.

## Layout

- Source is **21 `.gs` files under `src/`**, listed in `sources.json`. There is
  no `SpamDetector.gs` — it was split in v6.63.0.
- **Never hardcode a source filename.** Read the manifest via
  `scripts/sources.js` (Node) or `scripts/sources.py` (Python).
- Apps Script has **no module system**: every `.gs` is concatenated into one
  global scope. Nothing imports anything; every function is a global.
- `sources.json` owns `rootDir` (`src`), the file list, and `versionFile`
  (`src/Config.gs`, which carries both version markers).

## The two path conventions — get these backwards and you delete production

| Consumer | Base | Example |
|---|---|---|
| `.claspignore` | **rootDir**-relative | `!Config.gs` |
| `filePushOrder` | **repo**-relative | `src/Config.gs` |

clasp crawls `rootDir` with `fdir().withRelativePaths()` and filters ignore
patterns against the crawl's relative names **before** it builds any repo path
(`files.js:43-56, 228`). `filePushOrder` is compared against `localPath`, which
is repo-relative (`files.js:232, 390`). `clasp push --watch` uses a **third**
base, the repo root (`files.js:275`) — unused here, but do not assume two.

**Which failure is dangerous:** whitelisting *nothing* is a silent no-op (clasp
reports "already up to date" and returns early). A **partial** whitelist is
destructive — `updateContent` deletes every source it did not receive. A typo in
one line is worse than deleting all of them.

Deny patterns cannot secure `rootDir`: clasp lowercases extensions before
matching types (`files.js:97`), so `Config.GS` is SERVER_JS and `page.HTML` is
HTML, while micromatch is case-sensitive. That is why a test asserts `rootDir`
holds *only* the manifest files plus `appsscript.json`.

## Commit and release rules

- A release subject is **`v6.X.0: description`**. The version must be at the
  **start**; the deploy anchors on `^v`.
- **Never put a version string anywhere else in a subject.** Before anchoring,
  "Delete the tombstone comment for two functions removed in v6.47.0" made the
  deploy stamp the script 6.47.0. It ran mislabelled for three hours and every
  check agreed with itself.
- A version bump needs three edits: the commit subject, `@version` +
  `SCRIPT_VERSION` in `src/Config.gs`, and a `## vX.Y.Z` entry in
  `CHANGELOG.md` (newest first — CI checks all three).
- **The version commit must be HEAD when pushing.** The tag job reads
  `git log -1`.
- A change with no behaviour change needs no bump — but then `validate` has
  nothing falsifiable to assert, so say so explicitly rather than assuming the
  deploy worked.

## Before changing anything in the deploy path

Run `/deploy-change` (`.claude/skills/deploy-change/`). Short version:

1. **Read the dependency, do not reason about it.** Both near-misses in the
   v6.63.0 work came from inferring clasp's behaviour instead of reading
   `node_modules/@google/clasp/build/src/core/files.js`.
2. **Simulate before pushing.** The skill has the exact fdir + micromatch
   recipe that reproduces clasp's file resolution offline.
3. **Prove the guard fails.** A check that has never gone red proves nothing.
   Inject the fault, watch it fail, restore, verify with `cmp`.

## Testing

Five suites, all must pass:

```
python3 tests/test_spam_detector.py     # parser, detection corpus, JS/Python parity
node    tests/test_disposition.js       # quarantine-vs-delete routing
node    tests/test_link_graph.js        # URL parsing + Signal 7
node    tests/test_patch_version.js     # version patch + manifest/clasp hygiene
python3 scripts/validate.py             # README stats + version consistency
```

The Python suite parses the **concatenation** of every manifest file at import
time — patterns are never duplicated. Phase 7 runs all 81 fixtures through the
shipped JS *and* the Python mirror and fails on any disagreement.

## Local environment

- Use `python3`, not `python`. The `venv/` in the repo is broken (stale path).
- **zsh does not word-split unquoted variables.** `cat $FILES` passes one
  argument; `cat` with no valid arg reads stdin and hangs. Pass lists literally.
- `grep -oP` is GNU-only — fine in CI (Ubuntu), not on macOS. Use `grep -oE`.
- `.clasp.json` and `BLOG.md` are gitignored. Do not assume an edit to either is
  tracked.

## Never

- Run destructive experiments against tracked or gitignored working files.
  Copy to the scratchpad first. (I clobbered `sources.json` and deleted the
  user's `.clasp.json` this way.)
- Report local `git branch -r` as the remote's state without
  `git fetch --prune` — stale tracking refs look like live branches.
- Delete comments that carry measured evidence. "The 11,500-reads/day leak
  v6.50.1 closed" is the cost of a change someone already tried, not history.
