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

let failures = 0, passed = 0;
const check = (d, c, detail) => {
  if (c) { passed++; console.log('  ✅ ' + d); }
  else { failures++; console.log('  ❌ ' + d + (detail ? ' — ' + detail : '')); }
};

const real = fs.readFileSync(path.join(__dirname, '..', 'SpamDetector.gs'), 'utf8');

console.log('\n=== patch_version against the real SpamDetector.gs ===');
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
