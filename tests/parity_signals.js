/**
 * Signal-parity bridge: run the SHIPPED SpamDetector.gs over inputs supplied by
 * the Python harness, and print what the real JavaScript concluded.
 *
 * Why this exists
 * ---------------
 * tests/test_spam_detector.py hand-mirrors the .gs detection logic in Python.
 * Option B (parsing constants out of the source) keeps the PATTERNS honest, but
 * the LOGIC is duplicated, so a fix applied to one side and not the other
 * passes CI silently. That is not hypothetical — it happened once, and was
 * caught by accident when someone added a scam fixture.
 *
 * Hand-copied "parity tables" in both suites were the previous answer, and they
 * have the same flaw one level up: a human has to remember to update both.
 *
 * So compare the implementations mechanically instead. Python owns the INPUTS
 * (it parses the .eml files, so there is no second .eml parser to drift), pipes
 * them here, and this runs them through the genuine collectSignals(),
 * makeVerdict() and getRuleFromSignals(). Python then asserts both sides agree
 * signal-by-signal on every fixture in the corpus.
 *
 * Because it is driven by the fixture corpus rather than a hand-written table,
 * it extends itself: every new .eml is automatically a parity case, and every
 * new signal is automatically compared.
 *
 * Usage:  node tests/parity_signals.js <input.json>
 *   input:  [{file, subject, from, plainBody, html, raw, hasAttachment}, ...]
 *   output: {signalKeys: [...], results: {file: {...}}}
 */
'use strict';
const fs = require('fs');
const vm = require('vm');
const path = require('path');

const inputPath = process.argv[2];
if (!inputPath) {
  console.error('usage: node tests/parity_signals.js <input.json>');
  process.exit(2);
}
const cases = JSON.parse(fs.readFileSync(inputPath, 'utf8'));

// Minimal Apps Script surface. Deliberately NOT the disposition stubs: nothing
// here may write, label or delete — collectSignals is a pure read.
const ctx = {
  console: { log() {}, error() {}, warn() {} },
  Logger: { log() {} },
  Utilities: { sleep() {}, base64Encode: () => 'b64', newBlob: () => ({}) },
  Session: { getScriptTimeZone: () => 'UTC' },
  PropertiesService: {
    getScriptProperties: () => ({
      getProperty: () => null, setProperty() {}, deleteProperty() {}
    })
  }
};
vm.createContext(ctx);
new vm.Script(fs.readFileSync(path.join(__dirname, '..', 'SpamDetector.gs'), 'utf8'))
  .runInContext(ctx);

/** A GmailMessage stub carrying exactly the fields Python parsed. */
function stub(c) {
  const atts = c.hasAttachment ? [{ getName: () => 'a.pdf' }] : [];
  return {
    getId:         () => c.file,
    getSubject:    () => c.subject || '',
    getFrom:       () => c.from || '',
    getPlainBody:  () => c.plainBody || '',
    getBody:       () => c.html || '',
    getRawContent: () => c.raw || '',
    getAttachments: () => atts,
    getDate:       () => new Date('2026-09-17T00:00:00Z'),
    getReplyTo:    () => '',
    getHeader:     () => '',
    getThread:     () => ({ getId: () => 't-' + c.file })
  };
}

// The signal key list comes from the live object, not a hardcoded copy, so a
// signal added to SpamDetector.gs shows up here automatically and Python can
// fail on one it does not mirror.
const signalKeys = Object.keys(
  vm.runInContext('collectSignals', ctx)
    ? ctx.collectSignals(stub({ file: '_probe', from: 'a@b.invalid',
                                subject: 'x', plainBody: 'x', html: '', raw: '' })) || {}
    : {}
)
  // `_`-prefixed keys are META, not detection signals (e.g. _degraded, set when
  // a signal threw and was skipped). They have no Python counterpart by design,
  // so they are excluded from the parity contract rather than forcing a mirror
  // of something that is not a signal.
  .filter(k => k !== 'matched_patterns' && k.charAt(0) !== '_');

const results = {};
for (const c of cases) {
  try {
    const signals = ctx.collectSignals(stub(c));
    if (signals === null) {
      results[c.file] = { whitelisted: true };
      continue;
    }
    const out = { whitelisted: false, signals: {} };
    for (const k of Object.keys(signals)) {
      if (k.charAt(0) === '_') continue;   // meta, see signalKeys above
      out.signals[k] = signals[k];
    }
    out.degraded = signals._degraded === true;
    out.isSpam = ctx.makeVerdict(signals) === true;
    out.rule   = ctx.getRuleFromSignals(signals).rule;
    results[c.file] = out;
  } catch (e) {
    results[c.file] = { error: String(e && e.stack || e) };
  }
}

process.stdout.write(JSON.stringify({ signalKeys, results }));
