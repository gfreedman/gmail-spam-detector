/**
 * Node-side reader for sources.json, the Apps Script source manifest.
 *
 * Every Node consumer — the three vm-based test suites, patch_version.js, the
 * .claspignore hygiene check, and the deploy workflow's syntax lint — loads the
 * script through here, so splitting SpamDetector.gs into several .gs files
 * changes one JSON file and nothing else.
 *
 * concatSource() is the important one. Apps Script concatenates every .gs file
 * in the project into a single global scope before running anything, so the
 * faithful way to test the shipped code in a `vm` is to concatenate it the same
 * way. Loading files into separate vm.Scripts would give each its own scope and
 * quietly break every cross-file reference — a test harness that disagrees with
 * production about something that basic is worse than no harness.
 */
'use strict';
const fs   = require('fs');
const path = require('path');

const ROOT          = path.join(__dirname, '..');
const MANIFEST_PATH = path.join(ROOT, 'sources.json');

function manifest() {
  let raw;
  try {
    raw = fs.readFileSync(MANIFEST_PATH, 'utf8');
  } catch (e) {
    throw new Error('Cannot read the source manifest at ' + MANIFEST_PATH +
                    ' — ' + e.message);
  }

  let m;
  try {
    m = JSON.parse(raw);
  } catch (e) {
    throw new Error('sources.json is not valid JSON — ' + e.message);
  }

  // Validated rather than trusted. A manifest that silently reads as empty
  // would make every consumer "succeed" against no source at all: the vm suites
  // would load nothing and pass, and the syntax lint would lint nothing. Fail
  // loudly instead.
  if (!Array.isArray(m.sources) || m.sources.length === 0) {
    throw new Error('sources.json: "sources" must be a non-empty array');
  }
  if (!m.sources.every(s => typeof s === 'string' && s)) {
    throw new Error('sources.json: every entry in "sources" must be a filename');
  }
  const dupes = m.sources.filter((s, i) => m.sources.indexOf(s) !== i);
  if (dupes.length) {
    throw new Error('sources.json: duplicate entries in "sources": ' +
                    [...new Set(dupes)].join(', ') + ' — a file listed twice is ' +
                    'concatenated twice, which is a duplicate-declaration ' +
                    'SyntaxError at load time');
  }
  const bad = m.sources.filter(s => s.startsWith('/') || s.split('/').includes('..'));
  if (bad.length) {
    throw new Error('sources.json: entries must be repo-relative paths without ' +
                    '"..": ' + bad.join(', '));
  }
  if (typeof m.versionFile !== 'string' || !m.versionFile) {
    throw new Error('sources.json: "versionFile" must be a non-empty string');
  }
  if (m.sources.indexOf(m.versionFile) === -1) {
    throw new Error('sources.json: versionFile ' + JSON.stringify(m.versionFile) +
                    ' is not listed in "sources"');
  }
  return m;
}

/** Manifest-ordered source filenames, repo-relative. @return {string[]} */
function sourceNames() {
  return manifest().sources.slice();
}

/** Manifest-ordered absolute paths. @return {string[]} */
function sourcePaths() {
  return manifest().sources.map(f => path.join(ROOT, f));
}

/** Absolute path of the file carrying the version markers. @return {string} */
function versionFilePath() {
  return path.join(ROOT, manifest().versionFile);
}

/**
 * The deployed script as Apps Script will see it: every source file
 * concatenated in manifest order.
 *
 * Joined with NOTHING, deliberately. The split that produced these files was
 * verified by `cmp`: concatenating them must reproduce the pre-split
 * SpamDetector.gs byte for byte, which is the proof that the split moved code
 * and changed none. Any separator here would break that property.
 *
 * Safe because every source file is required to end with a newline —
 * tests/test_patch_version.js asserts it — so no file's last line can weld
 * onto the next file's first.
 *
 * @return {string}
 */
function concatSource() {
  return sourcePaths().map(p => {
    let body;
    try {
      body = fs.readFileSync(p, 'utf8');
    } catch (e) {
      throw new Error('sources.json lists ' + path.relative(ROOT, p) +
                      ', which cannot be read — ' + e.message);
    }
    // Enforced HERE, not only in a test. The '' join is correct only while
    // every part ends with a newline, and a test in another process is too far
    // from the function that depends on it: with the assertion living only in
    // tests/test_patch_version.js — the fifth CI step — four suites ran to
    // green on welded source before anything complained.
    if (body !== '' && !body.endsWith('\n')) {
      throw new Error(path.relative(ROOT, p) + ' does not end with a newline. ' +
                      'concatSource() joins with no separator, so this would ' +
                      "weld its last line onto the next file's first.");
    }
    return body;
  }).join('');
}

module.exports = { sourceNames, versionFilePath, concatSource };
