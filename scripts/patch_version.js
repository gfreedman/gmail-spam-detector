#!/usr/bin/env node
/**
 * Patch the two version markers in SpamDetector.gs to a given version.
 *
 * Called by the deploy workflow with the version parsed from the commit
 * message. Replaces:
 *   1. the header doc tag   ->  " * @version X.Y.Z"
 *   2. the runtime constant ->  "const SCRIPT_VERSION = 'X.Y.Z';"
 *
 * Both must land. runPeriodicMaintenance() compares SCRIPT_VERSION against the
 * last version recorded in Script Properties to force an immediate maintenance
 * cycle on a new deploy; if that constant went stale the detection would
 * silently never fire, so a failed patch exits non-zero and fails the deploy.
 *
 * This lives in a script rather than inline `sed` because the sed form had to
 * survive YAML block-scalar, shell double-quote and sed-expression quoting all
 * at once. The anchored version ("s|^ \* @version .*|...|") parsed fine locally
 * on BSD sed and died on GNU sed in CI with "unterminated `s' command" — a
 * failure mode that is invisible until deploy time. Regex in a real file is
 * both readable and testable: see `npm test`-less local check in
 * tests/test_patch_version.js.
 *
 * Usage: node scripts/patch_version.js 6.45.0 [path/to/SpamDetector.gs]
 */
'use strict';
const fs = require('fs');

function patchVersion(source, version) {
  if (!/^\d+\.\d+\.\d+$/.test(version)) {
    throw new Error('Version must look like X.Y.Z, got: ' + version);
  }

  // Anchored to the header tag's exact form. An unanchored /@version .*/ used
  // to match ANY line containing the tag, so a changelog line reading
  // "Fix @version tag, rule numbering..." was rewritten in every deployed copy.
  const headerRe = /^ \* @version .*$/m;
  if (!headerRe.test(source)) {
    throw new Error('Could not find a header line matching " * @version ..."');
  }
  let out = source.replace(headerRe, ' * @version ' + version);

  const constRe = /^const SCRIPT_VERSION = '[^']*';$/m;
  if (!constRe.test(out)) {
    throw new Error("Could not find a line matching \"const SCRIPT_VERSION = '...';\"");
  }
  out = out.replace(constRe, "const SCRIPT_VERSION = '" + version + "';");

  // Verify, rather than trust the replace. A silent no-op here is exactly the
  // class of failure this script exists to prevent.
  if (out.indexOf(' * @version ' + version) === -1 ||
      out.indexOf("const SCRIPT_VERSION = '" + version + "';") === -1) {
    throw new Error('Patch verification failed for version ' + version);
  }
  return out;
}

module.exports = { patchVersion };

if (require.main === module) {
  const version = process.argv[2];
  const file = process.argv[3] || 'SpamDetector.gs';
  if (!version) {
    console.error('Usage: node scripts/patch_version.js X.Y.Z [file]');
    process.exit(1);
  }
  try {
    const src = fs.readFileSync(file, 'utf8');
    fs.writeFileSync(file, patchVersion(src, version));
    console.log('Patched @version and SCRIPT_VERSION to ' + version + ' in ' + file);
  } catch (e) {
    console.error('::error::' + e.message);
    process.exit(1);
  }
}
