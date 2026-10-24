/**
 * Text.gs — Input sanitization and HTML-to-text helpers.
 *
 * sanitizeInput() bounds attacker-controlled text before any regex touches it —
 * the cap exists to stop quadratic backtracking on a hostile body, not for
 * tidiness. Everything that reads a message field goes through here first.
 *
 * Also the raw-header helpers behind Signals 2f/2g — getRawHeader() and
 * hasRandomCaseLabel() — which read the RFC 822 text getRawContent() returns.
 *
 * Apps Script concatenates every .gs file in sources.json into ONE global
 * scope. These are not modules: nothing is imported, and every function here
 * is a global visible to all other files.
 */

// =============================================================================
// Input Sanitization
// =============================================================================

/**
 * Sanitize input strings to prevent memory issues from oversized content.
 *
 * Truncates to 100 KB max. Applied to subject, body, and from fields before
 * pattern matching. Some regular expressions take exponentially longer as input
 * grows (called "ReDoS" — Regular Expression Denial of Service). Capping input
 * at 100 KB closes that window; no real email field is longer than a few KB.
 *
 * @param {string} input - Input string to sanitize.
 * @return {string} Sanitized string (truncated if over 100KB). Empty string if falsy.
 */
function sanitizeInput(input)
{
  if (input == null) return '';
  const str = String(input);
  return str.length > LIMITS.maxInputChars ? str.substring(0, LIMITS.maxInputChars) : str;
}

/**
 * Strip HTML tags from a string, collapsing whitespace.
 *
 * Used as a fallback body source when getPlainBody() returns empty (HTML-only
 * email). Without this, body pattern checks (e.g. BODY_CRYPTO_PATTERNS) would
 * silently never fire on HTML-only messages.
 *
 * Tags go through replaceAngles(), not /<[^>]+>/g. That regex was documented
 * here as "O(n), safe against ReDoS" — no nested quantifiers — but it retries
 * from every '<', and an HTML body of 100 KB of '<' (the sanitizeInput() cap)
 * took 4.4 s (v6.74.0). Same output.
 *
 * @param {string} html - Raw HTML string.
 * @return {string}       Plain text with tags removed and whitespace collapsed.
 */
function stripHtmlTags(html)
{
  return replaceAngles(html, ' ', 1).replace(/\s+/g, ' ').trim();
}

/**
 * Lookalike letters Signal 14 folds to ASCII, as two parallel strings
 * (Cyrillic and Greek that render like a Latin letter). Lower-case only: the
 * text is lower-cased first. Mirrored by _AD_CONFUSABLES in the Python suite;
 * a test on each side pins the same fold, so a character added to one fails.
 * @const {string}
 */
const AD_CONFUSABLES_FROM = '\u0430\u0435\u043e\u0440\u0441\u0445\u0443\u0456\u0458\u0455\u0501\u03bf\u03bd\u03b9\u03c1';
const AD_CONFUSABLES_TO   = 'aeopcxyijsdovip';

/**
 * Prepare text for Signal 14's phrase patterns (v6.83.0). The review of the
 * first regex draft evaded it five ways, each now closed here, IN THIS ORDER:
 * entities decoded ("sponsored&nbsp;by"), NFKC (full-width and math-bold
 * letters; re-capped because NFKC can expand text up to 18x), lower-cased,
 * lookalike letters folded ("sp\u043ensored"), every dash variant made '-'
 * (a non-breaking hyphen for the space), zero-width characters and soft
 * hyphens deleted (they sit INSIDE words, so no space), then every Unicode
 * space run collapsed to one space.
 *
 * Linear: each step is one pass over text capped at LIMITS.maxRawScanChars.
 * Mirrored by _normalize_ad_text() in tests/test_spam_detector.py.
 *
 * @param {string} text
 * @return {string}
 */
function normalizeAdText(text)
{
  return decodeHtmlEntities(text).normalize('NFKC')
    .substring(0, LIMITS.maxRawScanChars)
    .toLowerCase()
    .replace(/[\u0430\u0435\u043e\u0440\u0441\u0445\u0443\u0456\u0458\u0455\u0501\u03bf\u03bd\u03b9\u03c1]/g,
             function(ch) { return AD_CONFUSABLES_TO.charAt(AD_CONFUSABLES_FROM.indexOf(ch)); })
    .replace(/[\u2010-\u2015\u2212]/g, '-')
    .replace(/[\u00ad\u200b-\u200f\u2060\ufeff]/g, '')
    .replace(/[\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+/g, ' ');
}

/**
 * Decode the HTML entities a mail client honours inside link text and hrefs.
 *
 * This is NOT cosmetic — a plain substring search for a brand name is defeated
 * by one entity. "D&#111;cuSign" and "Docu&shy;Sign" both render as "DocuSign"
 * in every mail client while matching no literal search.
 *
 * Numeric forms are decoded FIRST and &amp; LAST. Browsers do not double-decode,
 * so neither may we: decoding &amp; first would turn "&amp;#47;" into "/"
 * and hand an attacker a free layer of indirection.
 *
 * @param {string} str - Raw text possibly containing HTML entities.
 * @return {string} Decoded text ('' for falsy input).
 */
function decodeHtmlEntities(str)
{
  if (!str) return '';

  return String(str)
    .replace(/&#x([0-9a-f]{1,6});/gi, function(_, hex) {
      const cp = parseInt(hex, 16);
      // Guard String.fromCodePoint against RangeError on out-of-range values
      // (e.g. "&#x110000;"). An uncaught throw here would propagate to
      // analyzeMessage()'s catch-all and silently mark the message not-spam.
      return (cp > 0 && cp <= 0x10FFFF) ? String.fromCodePoint(cp) : '';
    })
    .replace(/&#(\d{1,7});/g, function(_, dec) {
      const cp = parseInt(dec, 10);
      return (cp > 0 && cp <= 0x10FFFF) ? String.fromCodePoint(cp) : '';
    })
    .replace(/&nbsp;/gi, ' ')
    .replace(/&shy;/gi,  '')
    .replace(/&quot;/gi, '"')
    .replace(/&apos;/gi, "'")
    .replace(/&lt;/gi,   '<')
    .replace(/&gt;/gi,   '>')
    .replace(/&amp;/gi,  '&');
}

/**
 * Read one header's value from raw RFC 822 content.
 *
 * Only the header block (up to the first blank line) is searched, so a body
 * line reading "Date: ..." can never be mistaken for the header. Folded
 * continuation lines are unfolded first. Returns the FIRST occurrence.
 *
 * Mirrored by _raw_header() in tests/test_spam_detector.py; Phase 7 parity
 * fails if the two disagree.
 *
 * @param {string} rawContent - Full RFC 822 message.
 * @param {string} name - Header name, matched case-insensitively.
 * @return {string|null} The trimmed value (max 200 chars), or null if absent.
 */
function getRawHeader(rawContent, name)
{
  const raw = String(rawContent || '').replace(/\r\n/g, '\n');
  const end = raw.indexOf('\n\n');
  const headers = (end === -1 ? raw : raw.substring(0, end)).replace(/\n[ \t]+/g, ' ');
  const lines = headers.split('\n');
  const prefix = name.toLowerCase() + ':';
  for (let i = 0; i < lines.length; i++)
  {
    if (lines[i].toLowerCase().indexOf(prefix) === 0)
    {
      return lines[i].substring(prefix.length).trim().substring(0, 200);
    }
  }
  return null;
}

/**
 * The display name of an address header, normalised for comparison.
 *
 * '"Freedman,  Geoff C." <a@b.com>' -> 'c freedman geoff'. Takes everything
 * before the first '<' (so a header whose FIRST mailbox is a bare address
 * yields junk that matches nothing), drops quotes, dots, commas and invisible
 * format characters, case-folds, and SORTS the words — so "Freedman, Geoff C"
 * and "Geoff C. Freedman" compare equal, and a zero-width space cannot split
 * a name to dodge the match. A header with no '<' has no display name: ''.
 *
 * Whitespace is split on an explicit [ \t] class, never \s: JS and Python
 * disagree on what \s covers (\x1c-\x1f, \x85), and this must not.
 *
 * Expects a DECODED header value (Signal 10 passes getFrom()/getTo()). Fed a
 * raw RFC 2047 encoded-word name it fails closed: no spaces, so it never
 * reaches two words — which is why v6.69.0 stopped feeding it raw headers.
 *
 * Mirrored by _header_display_name() in tests/test_spam_detector.py.
 *
 * @param {string|null} headerValue - e.g. message.getFrom().
 * @return {string} Normalised display name, or '' if there is none.
 */
function headerDisplayName(headerValue)
{
  const value = String(headerValue || '');
  const lt = value.indexOf('<');
  if (lt === -1) return '';
  return value.substring(0, lt)
    .replace(/[\u00AD\u200B-\u200F\u2060\uFEFF]/g, '')
    .replace(/[".,]/g, ' ')
    .toLowerCase()
    .split(/[ \t]+/)
    .filter(function(w) { return w !== ''; })
    .sort()
    .join(' ');
}

/**
 * One mailbox, in the form Gmail itself treats as identical.
 *
 * Lower-cased, '+tag' dropped; for gmail.com and googlemail.com the dots in
 * the local part are dropped too and the domain is folded to gmail.com, since
 * Gmail delivers geoff.c.freedman+receipts@googlemail.com and
 * geoffcfreedman@gmail.com to the same inbox. Comparing raw text instead let
 * the user's own mail to a +tag address count as a stranger using their name.
 *
 * Mirrored by _canonical_mailbox() in tests/test_spam_detector.py.
 *
 * @param {string} address
 * @return {string}
 */
function canonicalMailbox(address)
{
  const addr = String(address || '').toLowerCase();
  const at = addr.lastIndexOf('@');
  if (at <= 0) return addr;
  let local = addr.substring(0, at);
  let domain = addr.substring(at + 1);
  const plus = local.indexOf('+');
  if (plus > 0) local = local.substring(0, plus);
  if (domain === 'gmail.com' || domain === 'googlemail.com')
  {
    local = local.replace(/\./g, '');
    domain = 'gmail.com';
  }
  return local + '@' + domain;
}

/**
 * Every address in a header value, lower-cased, by TOKENISING rather than by
 * a regex scan. The v6.69.0 review measured the obvious regex
 * ([A-Za-z0-9._%+-]+@...) at 10-34 s on a 100 KB To header with no '@' —
 * quadratic backtracking on a value the sender controls. Splitting on one
 * character class is linear. Not truncated here beyond the caller's
 * sanitizeInput() 100 KB cap: cutting the header shorter could drop the
 * user's own address from the not-yourself guard, which fails toward firing.
 *
 * Mirrored by _header_addresses() in tests/test_spam_detector.py.
 *
 * @param {string|null} headerValue
 * @return {Array<string>}
 */
function headerAddresses(headerValue)
{
  return String(headerValue || '').split(/[\s,;<>"():]+/)
    .filter(function(t) { return t.indexOf('@') > 0; })
    .map(function(t) { return t.toLowerCase(); });
}

/**
 * The letter-only words of each address's local part: "geoff.c.freedman@x,
 * gcf77@y" -> ['geoff', 'c', 'freedman', 'gcf']. Raw, not canonical — the
 * canonical Gmail form drops the dots that separate the words.
 *
 * Mirrored by _local_part_words() in tests/test_spam_detector.py.
 *
 * @param {Array<string>} addresses - from headerAddresses().
 * @return {Array<string>}
 */
function localPartWords(addresses)
{
  const words = [];
  addresses.forEach(function(a) {
    a.substring(0, a.lastIndexOf('@')).split(/[^a-z]+/)
      .forEach(function(w) { if (w) words.push(w); });
  });
  return words;
}

/**
 * Undo the cheap ways a callback scam hides its phone number from a filter,
 * so CALLBACK_PHONE_PATTERN can see it. Expects LOWERCASED text.
 *
 *   full-width or other compatibility digits  -> ASCII   (NFKC)
 *   "8oo-555-0134", "1-8oo"                    -> zeros   ('o' touching a digit)
 *   "1 8 0 0 5 5 5 0 1 3 4"                    -> one run (single digits, spaced)
 *
 * Only Signal 9 reads the result; it never reaches brand or billing matching.
 *
 * Mirrored by _deobfuscate_phone_text() in tests/test_spam_detector.py.
 *
 * @param {string} text
 * @return {string}
 */
function deobfuscatePhoneText(text)
{
  // NFKC can expand text up to 18x (U+FDFA), so cap again after it.
  const t = String(text || '').normalize('NFKC').substring(0, LIMITS.maxRawScanChars);
  // Linear by construction: split into runs of [0-9o] and everything else,
  // and zero the o's only in runs that hold a digit. The v6.69.0 draft looped
  // "o next to a digit" until stable — one more 'o' per pass, so '1' + 64K
  // 'o's took 64K passes (5.6 s locally, minutes in Apps Script) from any
  // gmail.com sender. Same result, one pass.
  return t.split(/([^0-9o]+)/)
    .map(function(part) { return /[0-9]/.test(part) ? part.replace(/o/g, '0') : part; })
    .join('')
    .replace(/(?<![0-9])([0-9]) (?=[0-9](?![0-9]))/g, '$1');
}

/**
 * Every mailbox named in a header value, canonicalised.
 *
 * Mirrored by _header_mailboxes() in tests/test_spam_detector.py.
 *
 * @param {string|null} headerValue
 * @return {Array<string>}
 */
function headerMailboxes(headerValue)
{
  return headerAddresses(headerValue).map(canonicalMailbox);
}

/**
 * Does any label of this domain have randomised capitalisation?
 *
 * "ktKCtzuMO", "bKnPcRBpO": throwaway domains generated per send. Domains are
 * case-insensitive, so a real sender writes them lower-case — or CamelCase
 * ("FinanceInsiderPro"), which this must NOT match. The discriminator is the
 * lowercase run: CamelCase is made of words, so it always contains a run of
 * 4+ lowercase letters; random case never does. All three conditions:
 *   >= 3 upper, >= 3 lower, >= 3 case switches, longest lowercase run <= 3.
 *
 * Mirrored by _has_random_case_label() in tests/test_spam_detector.py.
 *
 * @param {string} domain
 * @return {boolean}
 */
function hasRandomCaseLabel(domain)
{
  const labels = String(domain || '').split('.');
  for (let i = 0; i < labels.length; i++)
  {
    const letters = labels[i].replace(/[^A-Za-z]/g, '');
    let upper = 0, lower = 0, switches = 0, run = 0, maxRun = 0;
    for (let j = 0; j < letters.length; j++)
    {
      const isUpper = letters[j] >= 'A' && letters[j] <= 'Z';
      if (isUpper) { upper++; run = 0; }
      else { lower++; run++; if (run > maxRun) maxRun = run; }
      if (j > 0 && isUpper !== (letters[j - 1] >= 'A' && letters[j - 1] <= 'Z')) switches++;
    }
    if (upper >= 3 && lower >= 3 && switches >= 3 && maxRun <= 3) return true;
  }
  return false;
}
