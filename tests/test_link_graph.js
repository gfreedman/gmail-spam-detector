/**
 * Link-graph tests — URL host parsing, domain matching and Signal 7.
 *
 * Runs against the REAL SpamDetector.gs by loading it into a `vm` context.
 * The Python harness mirrors these helpers in Python (see the Link-Graph
 * Helpers section in tests/test_spam_detector.py); that mirror could drift
 * without the suite noticing, so these assertions exercise the shipped
 * JavaScript directly.
 *
 * Every row below corresponds to a real bypass or false positive, most of them
 * found by review AFTER the code shipped. Keep it that way: add the row first,
 * watch it fail, then fix.
 *
 * Run: node tests/test_link_graph.js
 */
'use strict';
const fs = require('fs');
const vm = require('vm');
const path = require('path');

const ctx = {
  console,
  Logger: { log() {} },
  PropertiesService: {
    getScriptProperties: () => ({ getProperty: () => null, setProperty() {} })
  }
};
vm.createContext(ctx);
new vm.Script(fs.readFileSync(path.join(__dirname, '..', 'SpamDetector.gs'), 'utf8'))
  .runInContext(ctx);

let failures = 0, passed = 0;
function check(desc, got, want) {
  const ok = got === want;
  if (ok) { passed++; console.log('  ✅ ' + desc); }
  else { failures++; console.log('  ❌ ' + desc + ' = ' + got + ' (want ' + want + ')'); }
}
/** Build a one-anchor HTML body and ask whether Signal 7 fires. */
const cta = (text, href, sender) =>
  ctx.hasBrandMismatchedCta('<a href="' + href + '">' + text + '</a>', sender);

// ---------------------------------------------------------------------------
console.log('\n=== extractUrlHost: bypass table ===');
[
  ['https://cptlbpolicy.com/',        'cptlbpolicy.com'],
  // userinfo — browsers resolve these to the host AFTER the last '@'
  ['https://docusign.net@evil.com/',  'evil.com'],
  ['https://a@b@evil.com/',           'evil.com'],
  // suffix / prefix confusion
  ['https://docusign.net.evil.com/',  'docusign.net.evil.com'],
  ['https://EU.DocuSign.NET:443/x',   'eu.docusign.net'],
  ['https://docusign.net./',          'docusign.net'],
  // scheme handling
  ['//docusign.net/x',                'docusign.net'],
  ['https:evil.com',                  'evil.com'],
  ['https:\\\\evil.com',              'evil.com'],
  ['https://ev\til.com',              'evil.com'],
  ['mailto:x@docusign.net',           ''],
  ['javascript:alert(1)',             ''],
  ['#anchor',                         ''],
  ['/relative/path',                  ''],
  ['',                                ''],
  ['https://[2001:db8::1]:8443/x',    '[2001:db8::1]']
].forEach(([href, want]) => check('extractUrlHost(' + JSON.stringify(href) + ')',
                                  ctx.extractUrlHost(href), want));

console.log('\n=== hostMatchesDomain: exact-or-dot-suffix only ===');
[
  ['docusign.net',          'docusign.net', true],
  ['eu.docusign.net',       'docusign.net', true],
  ['notdocusign.net',       'docusign.net', false],   // prefix bug
  ['docusign.net.evil.com', 'docusign.net', false],   // suffix bug
  ['evil.com',              'docusign.net', false]
].forEach(([h, d, want]) =>
  check('hostMatchesDomain(' + h + ', ' + d + ')', ctx.hostMatchesDomain(h, d), want));

console.log('\n=== addressMatchesDomain: the local part is attacker-chosen ===');
[
  // Substring entries must test the HOST only. Matching the full address made
  // 'dragonfly' whitelist any sender who picked that local part, and
  // 'financebuzz' blacklist (i.e. permanently delete) a legitimate one.
  ['dragonfly@attacker.tld',           'dragonfly',            false],
  ['a@dragonfly-evil.ru',              'dragonfly',            true],
  ['financebuzz@realcompany.com',      'financebuzz',          false],
  ['x@news.financebuzz.com',           'financebuzz',          true],
  // '@' entries must end on a domain-label boundary
  ['customerservice@stanley-evil.com', 'customerservice@stan', false],
  ['customerservice@stan.com',         'customerservice@stan', true],
  // dot-bearing entries are strict
  ['mail@linkedin.com.secure-login.top', 'linkedin.com',       false],
  ['a@notlinkedin.com',                  'linkedin.com',       false],
  ['news@e.linkedin.com',                'linkedin.com',       true]
].forEach(([a, d, want]) =>
  check('addressMatchesDomain(' + a + ', ' + d + ')', ctx.addressMatchesDomain(a, d), want));

console.log('\n=== Signal 7: fires on real lures ===');
check('the original Capital B lure',
      cta('VIEW IN DOCUSIGN→', 'https://cptlbpolicy.com/', 'info@cptlbnews.press'), true);
check('entity-obfuscated brand (D&#111;cu&shy;Sign)',
      ctx.hasBrandMismatchedCta(
        '<a href="https://evil.com/">Open D&#111;cu&shy;Sign</a>', 'a@b.com'), true);
check('brand split across nested elements',
      ctx.hasBrandMismatchedCta(
        '<a href="https://evil.com/">View <span>Docu</span><span>Sign</span></a>',
        'a@b.com'), true);
check('userinfo-disguised host',
      cta('Review in DocuSign', 'https://docusign.net@evil.com/', 'a@b.com'), true);
// One CNAME on an attacker-owned domain used to defeat the signal entirely.
['r', 'go', 'click', 't', 'e', 'em', 'link', 'url'].forEach(l =>
  check('tracker label on attacker domain: ' + l + '.cptlbpolicy.com',
        cta('VIEW IN DOCUSIGN', 'https://' + l + '.cptlbpolicy.com/',
            'info@cptlbnews.press'), true));
// Length cap is measured on normalized text, so padding and verbosity fail.
check('67-char natural button label',
      cta('Please review and open your secure DocuSign document envelope today',
          'https://evil.com/', 'a@b.com'), true);
check('zero-width-space padded label',
      cta('View in DocuSign' + '​'.repeat(50), 'https://evil.com/', 'a@b.com'), true);
// The body is no longer truncated to 100KB before the scan.
const late = '<div>' + 'x'.repeat(120000) +
             '</div><a href="https://evil.com/">VIEW IN DOCUSIGN</a>';
check('CTA beyond 100KB', ctx.hasBrandMismatchedCta(late, 'a@b.com'), true);

console.log('\n=== Signal 7: abstains on legitimate mail ===');
check('genuine docusign.net destination',
      cta('VIEW IN DOCUSIGN', 'https://eu.docusign.net/s?a=1', 'dse@docusign.net'), false);
check('third-party ESP click tracker',
      cta('View in DocuSign', 'https://u8.ct.sendgrid.net/ls/click?u=1', 'b@vendor.ca'), false);
check('sender-owned CNAMEd tracker',
      cta('View in DocuSign', 'https://click.acme.com/x', 'billing@acme.com'), false);
check('sender-aligned destination',
      cta('View in DocuSign', 'https://sign.acme.com/x', 'a@acme.com'), false);
check('brand named in prose, no CTA verb',
      cta('About DocuSign', 'https://evil.com/', 'a@b.com'), false);
check('long prose mentioning the brand',
      cta('This newsletter discusses how DocuSign and other electronic signature '
        + 'vendors approach compliance review across regulated industries today',
          'https://news.example.com/', 'e@news.com'), false);
check('mailto: destination abstains',
      cta('Sign in DocuSign', 'mailto:x@y.com', 'a@b.com'), false);
check('no brand in the anchor at all',
      cta('Click here now', 'https://evil.com/', 'a@b.com'), false);
// "Sign Now" normalizes to "signnow"; that key was removed for this reason.
check('"Sign Now" button (Ironclad)',
      cta('Sign Now', 'https://app.ironcladapp.com/x', 'noreply@ironclad.com'), false);
check('"Please review and sign now" (BambooHR)',
      cta('Please review and sign now', 'https://acme.bamboohr.com/f', 'hr@acme.com'), false);

console.log('\n=== Bounds: attacker-controlled input cannot hang the scan ===');
const patho = '<a href="https://evil.com/">DOCUSIGN'.repeat(900);
let t0 = Date.now();
const anchors = ctx.extractAnchors(patho);
const dt = Date.now() - t0;
check('900 unclosed anchors bounded to maxAnchorsScanned',
      anchors.length <= vm.runInContext('LIMITS.maxAnchorsScanned', ctx), true);
check('900 unclosed anchors complete under 250ms', dt < 250, true);
t0 = Date.now();
ctx.hasBrandMismatchedCta('x'.repeat(500000) +
  '<a href="https://evil.com/">View in DocuSign</a>', 'a@b.com');
check('500KB body completes under 250ms', (Date.now() - t0) < 250, true);

console.log('\n=== Entity decoding ===');
check('no double-decoding of &amp;#47;', ctx.decodeHtmlEntities('&amp;#47;'), '&#47;');
check('out-of-range codepoint does not throw',
      ctx.decodeHtmlEntities('a&#1114112;b'), 'ab');
check('soft hyphen removed', ctx.decodeHtmlEntities('Docu&shy;Sign'), 'DocuSign');

console.log('\n' + '='.repeat(70));
console.log(failures === 0
  ? '✅ LINK-GRAPH TESTS PASSED (' + passed + ' assertions)'
  : '❌ LINK-GRAPH TESTS FAILED: ' + failures + ' of ' + (passed + failures));
process.exit(failures === 0 ? 0 : 1);
