---
name: deploy-change
description: Verification procedure for any change touching the Apps Script deploy path — sources.json, .claspignore, .clasp.json, rootDir, the deploy workflow, or adding/moving/removing a .gs file. Use BEFORE pushing, because clasp push --force replaces the remote wholesale and this script permanently deletes mail.
---

# Changing the deploy path

`clasp push --force` calls `projects.updateContent`, which **replaces every file
in the project**. Any source it does not receive is deleted from the deployed
script. There is no undo.

Two changes came within one step of wiping the deployment in v6.63.0. Both came
from *reasoning about* clasp instead of *reading* it. Do not repeat that.

## 1. Read clasp's source. Do not infer.

```bash
SCRATCH="${TMPDIR:-/tmp}/clasp-verify"
mkdir -p "$SCRATCH" && cd "$SCRATCH"
npm install --silent --no-fund --no-audit @google/clasp@3.3.0 micromatch
```

The file that decides everything is
`node_modules/@google/clasp/build/src/core/files.js`:

| Line | What it settles |
|---|---|
| `43-56` | `getLocalFiles` — fdir crawl of rootDir, then `micromatch.not`. **`.claspignore` is matched against rootDir-relative names.** |
| `97` | `getFileType` **lowercases the extension** — `Config.GS` is SERVER_JS. |
| `232` | `localPath = relative(cwd, join(contentDir, filename))` — repo-relative. |
| `233-235` | `remotePath` = rootDir-relative path minus extension. This is the deployed name. |
| `241-243` | `appsscript.json` is force-renamed to `appsscript`. |
| `390` | `filePushOrder` is compared against **`localPath`** — repo-relative. |
| `275` | `clasp push --watch` filters against a **third** base, the repo root. |

Pin the version you read against what CI installs
(`grep 'npm install -g @google/clasp' .github/workflows/deploy.yml`).

## 2. Simulate the push offline, before you commit

Run from the repo root. This reproduces clasp's resolution exactly — note it
does **not** strip comments or trim, because `loadIgnoreFileOrDefaults` doesn't
(`clasp.js:288`).

```bash
node -e "
const {fdir}=require('$SCRATCH/node_modules/fdir');
const micromatch=require('$SCRATCH/node_modules/micromatch');
const path=require('path'),fs=require('fs');
const man=require('./scripts/sources.js');
(async()=>{
  const root=man.rootDir();
  const files=await new fdir().withBasePath().withRelativePaths().crawl(root).withPromise();
  const pats=fs.readFileSync('.claspignore','utf8').split('\n').filter(n=>n.length>0);
  const kept=micromatch.not(files,pats,{dot:true});
  const remote=kept.map(f=>{
    const localPath=path.relative(process.cwd(),path.join(root,f));
    const p=path.parse(path.relative(root,localPath));
    let r=path.format({dir:p.dir,name:p.name}).split(path.sep).join('/');
    if(path.basename(localPath)==='appsscript.json') r='appsscript';
    return {localPath,r};
  });
  console.log('files pushed :',kept.length);
  console.log('remote names :',remote.map(x=>x.r).sort().join(', '));
  const order=[root+'/appsscript.json'].concat(man.sourceNames()).map(p=>path.normalize(p));
  console.log('filePushOrder unmatched:',remote.filter(x=>order.indexOf(path.normalize(x.localPath))===-1).length);
})();"
```

**Expected:** file count = manifest length + 1, remote names carry no directory
prefix and no extension, unmatched = 0.

**If the count is 0** — clasp pushes nothing and reports "already up to date".
Harmless, but your change is a no-op.
**If the count is between 1 and N-1** — this is the destructive case. Do not
push. `updateContent` would delete every source that is missing.

## 3. Prove each guard can fail

A guard that has never gone red proves nothing. For every check you add or rely
on, inject the fault, confirm the failure message names the right thing, then
restore and verify with `cmp`.

```bash
cp <file> "$SCRATCH/x.bak"          # ALWAYS back up outside the repo first
# ...break it, run the suite, see red...
cp "$SCRATCH/x.bak" <file> && cmp "$SCRATCH/x.bak" <file>
```

Never inject faults into a tracked *or* gitignored working file without a
backup — `git checkout` cannot restore what git does not track.

## 4. Run everything

```bash
python3 tests/test_spam_detector.py && \
node tests/test_disposition.js && node tests/test_link_graph.js && \
node tests/test_patch_version.js && python3 scripts/validate.py && \
node -e "new (require('vm').Script)(require('./scripts/sources.js').concatSource())"
```

`tests/test_patch_version.js` carries the manifest/clasp hygiene checks: every
`.gs` listed, every manifest file whitelisted rootDir-relative, no `!` line
repo-relative or trailing-whitespaced, `rootDir` free of strays, LF endings,
trailing newline, no duplicate top-level `function`/`var`.

## 5. Commit subject

`v6.X.0: description` for a release; **no version string anywhere else in a
subject**, ever — the deploy anchors on `^v` but prose versions have already
caused one mislabelled production deploy.

For a release also update `@version` and `SCRIPT_VERSION` in `src/Config.gs`
and add a `## vX.Y.Z` entry to `CHANGELOG.md`, and make it the HEAD commit.

## 6. After the deploy

CI's own guards are the backstop, in order: the pre-push `clasp status --json`
check (fail-open), the deployed-file assertion (names **and** order, hard
failure), then `verify-prod`.

Then confirm it actually **ran**, not just deployed:

```bash
python3 scripts/prod_health.py
```

The marker timestamp must be **later than the deploy**. A green `verify-prod`
moments after a push can still be the *previous* version reporting healthy.
`prod_health.py` is the only check that compares the live marker against local
source rather than against the commit — it is how the 6.47.0 mislabel was found.
