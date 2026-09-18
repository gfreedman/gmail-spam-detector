/**
 * Tests for scripts/patch_version.js.
 *
 * The deploy step this replaces failed only in CI (GNU sed vs BSD sed quoting),
 * after tests had already passed — the worst place to discover a bug. These
 * assertions run in the same job as everything else.
 *
 * Run: node tests/test_patch_version.js
 */
'use strict';
const fs = require('fs');
const path = require('path');
const { patchVersion } = require(path.join(__dirname, '..', 'scripts', 'patch_version.js'));
const srcManifest = require(path.join(__dirname, '..', 'scripts', 'sources.js'));

let failures = 0, passed = 0;
const check = (d, c, detail) => {
  if (c) { passed++; console.log('  ✅ ' + d); }
  else { failures++; console.log('  ❌ ' + d + (detail ? ' — ' + detail : '')); }
};

// The manifest's versionFile, not a hardcoded name: patch_version.js targets
// that file, so this must test the same one.
const real = fs.readFileSync(srcManifest.versionFilePath(), 'utf8');

console.log('\n=== patch_version against the real ' +
            path.basename(srcManifest.versionFilePath()) + ' ===');
const out = patchVersion(real, '9.9.9');
check('header tag patched', /^ \* @version 9\.9\.9$/m.test(out));
check('runtime constant patched', /^const SCRIPT_VERSION = '9\.9\.9';$/m.test(out));
check('exactly one header @version line',
      (out.match(/^ \* @version /gm) || []).length === 1);
check('exactly one SCRIPT_VERSION declaration',
      (out.match(/^const SCRIPT_VERSION = /gm) || []).length === 1);

// The bug the anchoring fixed: a changelog line mentioning the tag must survive.
const changelogLine = real.split('\n').find(l => / @version /.test(l) && !/^ \* @version /.test(l));
if (changelogLine) {
  check('changelog line mentioning the tag is untouched',
        out.indexOf(changelogLine) !== -1,
        JSON.stringify(changelogLine.trim()));
} else {
  console.log('  ℹ no changelog line mentions the tag — anchoring untested here');
}

check('output still parses as JS', (() => {
  try { new (require('vm').Script)(out); return true; } catch (e) { return false; }
})());

console.log('\n=== the two checked-in version markers must agree ===');
// CI patches both from the commit subject, which masks drift at deploy time but
// leaves it in the repo — and a commit subject with no version deploys whatever
// was hand-edited. SCRIPT_VERSION going stale silently disables the
// new-deploy maintenance trigger, so the two must match in source.
{
  const tag = (real.match(/^ \* @version (\S+)$/m) || [])[1];
  const konst = (real.match(/^const SCRIPT_VERSION = '([^']*)';$/m) || [])[1];
  check('@version (' + tag + ') agrees with SCRIPT_VERSION (' + konst + ')',
        !!tag && tag === konst);
}

console.log('\n=== failure modes must throw, not silently no-op ===');
const mustThrow = (desc, fn) => {
  try { fn(); check(desc, false, 'did not throw'); }
  catch (e) { check(desc, true); }
};
mustThrow('missing header line throws',
          () => patchVersion("const SCRIPT_VERSION = '1.0.0';", '6.45.0'));
mustThrow('missing SCRIPT_VERSION throws',
          () => patchVersion(' * @version 1.0.0\n', '6.45.0'));
mustThrow('malformed version throws', () => patchVersion(real, 'v6.45.0'));
mustThrow('empty version throws', () => patchVersion(real, ''));

console.log('\n=== the manifest must describe the repo as it really is ===');
// Phase 0 of the source split. These three assertions are what make a later
// split safe: they fail the build the moment the manifest and the filesystem
// disagree, rather than letting a forgotten file reach clasp — or not reach it.
{
  const root = path.join(__dirname, '..');
  const listed = srcManifest.sourceNames();

  const missing = listed.filter(f => !fs.existsSync(path.join(root, f)));
  check('every file in sources.json exists', missing.length === 0, missing.join(', '));

  // The dangerous direction. A new .gs file that nobody added to the manifest
  // is invisible to every test suite here AND to the deploy's syntax lint,
  // while clasp still happily pushes it — untested code, live.
  // Recursive: a split that puts sources in src/ would otherwise make this
  // guard blind to every file it exists to police.
  const onDisk = fs.readdirSync(root, { recursive: true })
    .map(f => String(f).split(path.sep).join('/'))
    .filter(f => f.endsWith('.gs') &&
                 !/^(venv|archive|node_modules|\.git|__pycache__)\//.test(f))
    .sort();
  const unlisted = onDisk.filter(f => listed.indexOf(f) === -1);
  check('every .gs file in the repo is listed in sources.json (' + onDisk.length + ' found)',
        unlisted.length === 0, unlisted.join(', '));

  // The other dangerous direction. .claspignore is deny-by-default with an
  // explicit "!" whitelist, so a manifest file with no "!" line is tested and
  // version-checked locally and then silently NOT deployed.
  //
  // ROOTDIR-RELATIVE. clasp crawls rootDir with fdir and filters ignore
  // patterns against the crawl's RELATIVE paths, so src/Config.gs must be
  // whitelisted as "!Config.gs". This check previously compared the
  // repo-relative name, which passed happily against "!src/Config.gs" —
  // entries that match nothing. With "*.gs" denied above, that resolves to
  // clasp pushing ZERO files and replacing the deployed script with nothing.
  // Confirmed against clasp 3.3.0's own micromatch.
  // NOT trimmed. clasp's loadIgnoreFileOrDefaults is
  // splitLines(content).filter(name => name.length > 0) — no trim and no
  // comment stripping — so "!Config.gs " with one trailing space is a pattern
  // that matches nothing. That is the PARTIAL-whitelist case: clasp pushes the
  // other 20 files and updateContent DELETES Config.gs from the deployed
  // project. Trimming here hid exactly that.
  const claspRaw = fs.readFileSync(path.join(root, '.claspignore'), 'utf8');
  const claspLines = claspRaw.split('\n');
  const notWhitelisted = listed.filter(
    f => claspLines.indexOf('!' + srcManifest.claspRelative(f)) === -1);
  check('every manifest file is whitelisted in .claspignore (rootDir-relative)',
        notWhitelisted.length === 0, notWhitelisted.join(', '));

  // And the specific mistake: a "!" line that still carries the rootDir prefix
  // matches nothing, so it is worse than absent — it LOOKS correct in review.
  const prefixed = claspLines.filter(
    l => l.startsWith('!' + srcManifest.rootDir() + '/'));
  check('no .claspignore "!" line is repo-relative', prefixed.length === 0,
        prefixed.join(', '));

  const trailing = claspLines.filter(l => /[ \t\r]+$/.test(l));
  check('no .claspignore line has trailing whitespace', trailing.length === 0,
        trailing.map(l => JSON.stringify(l)).join(', '));

  // rootDir must hold NOTHING but the manifest and appsscript.json.
  //
  // Enumerating deny patterns cannot win this race: clasp lowercases the
  // extension before matching file types (files.js:97), so "Config.GS" is
  // SERVER_JS and "page.HTML" is HTML, while micromatch is case-SENSITIVE and
  // "*.gs"/"*.html" miss both. Anything clasp recognises and we did not list is
  // deployed untested, invisible to the pre-push guard (which only asks whether
  // manifest files are present) and to the deployed-file assertion (which
  // filters to SERVER_JS). Listing the directory sidesteps pattern matching
  // entirely.
  const allowed = new Set(listed.map(f => srcManifest.claspRelative(f))
                                .concat(['appsscript.json']));
  const strays = fs.readdirSync(path.join(root, srcManifest.rootDir()),
                                { recursive: true })
    .map(f => String(f).split(path.sep).join('/'))
    .filter(f => fs.statSync(path.join(root, srcManifest.rootDir(), f)).isFile())
    .filter(f => !allowed.has(f));
  check('rootDir holds only manifest files + appsscript.json (' +
        allowed.size + ' allowed)', strays.length === 0, strays.join(', '));

  // LF only. Python's open() normalizes CRLF to LF and Node's readFileSync
  // does not, so a CRLF file would make the two manifest readers emit
  // different bytes for identical content. sources.py reads with newline=''
  // to keep the bytes honest; this keeps the inputs honest.
  const crlf = listed.filter(f => fs.readFileSync(path.join(root, f), 'utf8').includes('\r'));
  check('every manifest file uses LF line endings', crlf.length === 0, crlf.join(', '));

  // concatSource() joins with NOTHING so the concatenation is byte-identical to
  // the pre-split source. That is only safe while every file ends with a
  // newline; without this, one file's last line would weld onto the next file's
  // first — silently, and producing valid-looking JavaScript.
  const noEol = listed.filter(f => !fs.readFileSync(path.join(root, f), 'utf8').endsWith('\n'));
  check('every manifest file ends with a newline', noEol.length === 0, noEol.join(', '));

  // Duplicate top-level function/var across files is LAST-WINS IN SILENCE.
  // Apps Script concatenates every .gs into one scope; duplicate const/let
  // throws a load-time SyntaxError (so the concat lint catches those), but
  // duplicate `function` and `var` are legal JS and simply overwrite. A
  // mechanical split of a 5,600-line file with shared helpers is the canonical
  // way to produce one, and every suite here would stay green while the real
  // implementation was silently replaced.
  const declaredIn = new Map();
  for (const f of listed) {
    const body = fs.readFileSync(path.join(root, f), 'utf8');
    // async function and function* are valid Apps Script V8 and neither is in
    // the source today — but a refactor is exactly when one would appear.
    for (const m of body.matchAll(
           /^(?:(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)|var\s+([A-Za-z_$][\w$]*))/gm)) {
      const name = m[1] || m[2];
      if (!declaredIn.has(name)) declaredIn.set(name, []);
      declaredIn.get(name).push(f);
    }
  }
  const clashes = [...declaredIn.entries()]
    .filter(([, files]) => files.length > 1)
    .map(([name, files]) => name + ' (' + files.join(' + ') + ')');
  check('no top-level function/var is declared twice (' + declaredIn.size + ' checked)',
        clashes.length === 0, clashes.join(', '));
}

console.log('\n=== deploy hygiene: clasp must not pick up Node scripts ===');
// clasp treats ANY .js under rootDir as Apps Script source and uploads it as
// .gs. Adding scripts/patch_version.js broke a deploy with
// "ParseError: Unexpected token ILLEGAL ... file: scripts/patch_version.gs",
// because .claspignore's bare "*.js" matches only top-level files. This walks
// the repo for .js files and asserts each one is excluded.
{
  const root = path.join(__dirname, '..');
  const ignore = fs.readFileSync(path.join(root, '.claspignore'), 'utf8')
    .split('\n').map(l => l.trim())
    .filter(l => l && !l.startsWith('#') && !l.startsWith('!'));

  const jsFiles = [];
  (function walk(dir, rel) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (['.git', 'node_modules', 'venv', '__pycache__'].indexOf(entry.name) !== -1) continue;
      const abs = path.join(dir, entry.name);
      const r = rel ? rel + '/' + entry.name : entry.name;
      if (entry.isDirectory()) walk(abs, r);
      else if (entry.name.endsWith('.js')) jsFiles.push(r);
    }
  })(root, '');

  const covered = f => ignore.some(pat => {
    if (pat === '**/*.js') return f.indexOf('/') !== -1;
    if (pat === '*.js') return f.indexOf('/') === -1;
    if (pat.endsWith('/**')) return f.startsWith(pat.slice(0, -3) + '/');
    return pat === f;
  });

  check('repo contains .js files to check (' + jsFiles.length + ')', jsFiles.length > 0);
  const uncovered = jsFiles.filter(f => !covered(f));
  check('every .js file is excluded by .claspignore', uncovered.length === 0,
        uncovered.join(', '));
}

console.log('\n' + '='.repeat(70));
console.log(failures === 0
  ? '✅ PATCH-VERSION TESTS PASSED (' + passed + ' assertions)'
  : '❌ PATCH-VERSION TESTS FAILED: ' + failures);
process.exit(failures === 0 ? 0 : 1);
