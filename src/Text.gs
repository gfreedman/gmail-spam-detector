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
 * The SET of words and link hosts of a message, for the finance-pitch score (v6.99.0).
 *
 * Lower-cased NFKC text of subject + body (capped at LIMITS.maxRawScanChars); every
 * http(s) URL is reduced to " h_<host>" (leading "www." dropped) so the destination
 * counts and the tracking path does not; the tokens are "h_<host>" and runs of 3+
 * ASCII letters; "f_lu" is added when the message carries a List-Unsubscribe header.
 * Explicit character classes, no \s and no \b, because the Python mirror
 * (tests/test_spam_detector.py _bayes_tokens) must agree token for token and JS and
 * Python disagree on exotic whitespace. scripts/train_bayes.py imports the Python
 * twin, so training, the mirror and this function share one definition.
 *
 * @param {string} subject
 * @param {string} body - Plain body.
 * @param {boolean} hasListUnsubscribe
 * @return {Object} A null-prototype set: {token: true}.
 */
function bayesTokens(subject, body, hasListUnsubscribe)
{
  const text = ((subject || '') + ' ' + (body || '')).substring(0, LIMITS.maxRawScanChars)
    .normalize('NFKC').toLowerCase()
    .replace(/https?:\/\/([^\/ \t\r\n>]+)[^ \t\r\n>]*/g,
             function(m, host) { return ' h_' + host.replace(/^www\./, '') + ' '; });
  const found = text.match(/h_[a-z0-9.\-]+|[a-z]{3,}/g) || [];
  const set = Object.create(null);
  for (let i = 0; i < found.length; i++) set[found[i]] = true;
  if (hasListUnsubscribe) set['f_lu'] = true;
  return set;
}

/**
 * The finance-pitch score of a token set: the sum of the BAYES_TOP_K largest weights
 * among tokens in BAYES_TABLE (Patterns.gs, generated by scripts/train_bayes.py). The
 * table holds POSITIVE integers only (spam-leaning words), so no appended word can lower
 * a score, equal weights tie harmlessly (the sum is the same whichever is cut), and JS and
 * Python are bit-identical.
 *
 * @param {Object} tokens - From bayesTokens().
 * @return {number}
 */
function bayesScore(tokens)
{
  const known = [];
  for (const t in tokens)
  {
    // hasOwnProperty: BAYES_TABLE is a plain object, and a word like "constructor"
    // or "valueof" must not resolve to something inherited.
    if (Object.prototype.hasOwnProperty.call(BAYES_TABLE, t)) known.push(t);
  }
  known.sort(function(a, b) { return BAYES_TABLE[b] - BAYES_TABLE[a]; });
  let sum = 0;
  for (let i = 0; i < known.length && i < BAYES_TOP_K; i++) sum += BAYES_TABLE[known[i]];
  return sum;
}

/**
 * The text of a message that its SENDER wrote: quoted lines ("> ...") dropped and
 * everything from the first forwarded-message / original-message / "On ... wrote:"
 * marker onward cut off (v6.98.0, for Signal 16).
 *
 * Why: a footer address is evidence about the sender only if the sender wrote it.
 * A friend asking "is this a scam?" forwards the mill's whole footer, and a reply
 * quotes it; both carry the address with nothing else in common with the mill.
 * Line-based and linear: one split, one scan, each marker regex anchored at the
 * start of a line and bounded (no nested quantifier).
 *
 * Known evasions, left open (cheap for a mill that controls its own plain-text part): it
 * can print its footer as "> ..." lines, or put a fake "On x wrote:" line above the
 * footer; a body padded past LIMITS.maxRawScanChars pushes the footer out of the scan;
 * HTML-only mail reaches this as ONE line (stripHtmlTags collapses newlines), so the
 * quote protection does nothing there. Known gap too: a forwarder that pastes the mill's text with no marker and
 * no ">" is indistinguishable from the mill (it then also needs List-Unsubscribe,
 * which a forward from a person does not carry).
 *
 * @param {string} text - Plain-text body.
 * @return {string} The sender-authored text ('' for falsy input).
 */
function stripQuotedAndForwarded(text)
{
  if (!text) return '';
  const lines = String(text).split('\n');
  const kept = [];
  for (let i = 0; i < lines.length; i++)
  {
    // Lower-cased instead of /i, and [^\n] instead of ".", so the Python mirror
    // (re.I folds U+017F and U+212A, "." admits \r and U+2028) cannot disagree;
    // the whitespace class is spelled out for the same reason (JS \s has U+FEFF).
    const line = lines[i].toLowerCase();
    if (/^[ \t\r\f\v\u00a0\u2028\u2029\ufeff]*(?:-{2,} ?(?:forwarded message|original message) ?-{2,}|begin forwarded message:?|on [^\n]{1,120} wrote:)[ \t\r\f\v\u00a0\u2028\u2029\ufeff]*$/.test(line)) break;
    // Outlook / Google Groups quoting has no ">" and no marker line, only a header
    // block: "From: x" immediately followed by "Sent:" or "Date:".
    if (/^[ \t\r\f\v\u00a0\u2028\u2029\ufeff]*from:/.test(line) && i + 1 < lines.length &&
        /^[ \t\r\f\v\u00a0\u2028\u2029\ufeff]*(?:sent|date):/.test(lines[i + 1].toLowerCase())) break;
    if (/^[ \t\r\f\v\u00a0\u2028\u2029\ufeff]*>/.test(line)) continue;
    kept.push(lines[i]);
  }
  return kept.join('\n');
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

/**
 * Is this host's top-level domain absent from the IANA root zone (v6.110.0)?
 *
 * Strips one trailing dot, then judges the last label. ABSTAINS (returns false) on anything it
 * cannot judge: a dotless host, a numeric or IP-literal last label, a non-ASCII label, a label
 * outside DNS syntax, and every name in PRIVATE_TLDS. Only a well-formed ASCII label that is in
 * neither IANA_TLDS nor PRIVATE_TLDS is "unknown". Linear: one lastIndexOf and an object lookup.
 *
 * Mirrored by _is_unknown_tld() in tests/test_spam_detector.py.
 *
 * @param {string} host
 * @return {boolean}
 */
function isUnknownTld(host)
{
  let h = String(host || '').toLowerCase();
  if (h.charAt(h.length - 1) === '.') h = h.substring(0, h.length - 1);
  const dot = h.lastIndexOf('.');
  if (dot <= 0) return false;
  const label = h.substring(dot + 1);
  if (!/^[a-z]{2,63}$/.test(label) && !/^xn--[a-z0-9-]{1,59}$/.test(label)) return false;
  if (!isUnknownTld._set)
  {
    const set = Object.create(null);
    IANA_TLDS.forEach(function(t) { set[t] = true; });
    PRIVATE_TLDS.forEach(function(t) { set[t] = true; });
    isUnknownTld._set = set;
  }
  return isUnknownTld._set[label] !== true;
}

/**
 * The organisational domain of a host on an UNKNOWN TLD: its last two labels (v6.110.0). There is
 * no public-suffix entry for a TLD that does not exist, so two labels is the whole registrable
 * name. 'tw51isf.ymv' -> 'tw51isf.ymv', 'lists.corp.intern' -> 'corp.intern'.
 *
 * @param {string} host - Lower-cased, trailing dot already stripped.
 * @return {string}
 */
function unknownTldOrgDomain(host)
{
  const labels = String(host || '').split('.');
  return labels.slice(-2).join('.');
}

/**
 * Trim the given characters (default space and tab) from both ends, with a linear scan. Not
 * String.prototype.trim(): JS and Python disagree on what counts as whitespace (U+0085, U+FEFF ...),
 * and Signal 18's Python mirror (str.strip(chars)) must agree byte for byte. Not a regex either:
 * /[ \t\r\n]+$/ backtracks across every interior run and took 5.7 s on a 100K From (PR #39 round 3).
 */
function trimSpTab(v, chars)
{
  const set = chars || ' \t';
  let a = 0, b = v.length;
  while (a < b && set.indexOf(v.charAt(a)) !== -1) a++;
  while (b > a && set.indexOf(v.charAt(b - 1)) !== -1) b--;
  return v.substring(a, b);
}

/**
 * Signal 18 (v6.110.0): a From address on a TLD that does not exist, sent as mass mail whose
 * unsubscribe links ALL point at a DIFFERENT organisation on a TLD that does not exist, with no
 * DKIM pass aligned with the From domain. All of it, or false.
 *
 * "Cloud-Storage <alert-143-23903@nsnvy.ymv>", "Your Photos & Videos Are at Risk of Permanent
 * Deletion!": a storage-scam mill that sends from real .my.id / .web.id hosts (DKIM passes for
 * THOSE) but writes random hosts on invented TLDs into From (nsnvy.ymv) and List-Unsubscribe
 * (tw51isf.ymv). Gmail filed it as spam; only FEAR fired, so it sat out the 7-day grace.
 *
 * Why each condition (PR #39 review, two rounds):
 *  - A fake From TLD alone is also self-hosted mail - NAS, UPS, Nagios, Proxmox, AD domains on
 *    .lab, .intern, .novalocal, .hq ... - exactly the mail Gmail misfiles. Such alerts carry no
 *    List-Unsubscribe.
 *  - Self-hosted LIST mail does (GitLab on gitlab.corp.intern, Mailman on lists.corp.intern,
 *    listmonk on list.family.lab) - but its unsubscribe host is the sender's own organisation.
 *    The mill's is a different random name. So every unsubscribe host must be on an unknown TLD
 *    AND in a different organisational domain from the From.
 *  - A domain that does not exist cannot pass DKIM; a real sender on a TLD delegated after the
 *    IANA_TLDS snapshot can, so an aligned pass (same organisational domain) abstains.
 *  - The signal abstains outright once the snapshot is older than TLD_SNAPSHOT_MAX_AGE_DAYS.
 *  - Only an UNAMBIGUOUS From is judged: one bare address, or exactly one <addr> ending the
 *    header. A display name holding an address, a comment form or several mailboxes abstain.
 *
 * Every List-Unsubscribe and Authentication-Results header is read in full, within the first
 * LIMITS.maxRawScanChars of the message. Spam-folder CORROBORATION ONLY: STRONG in
 * hasCorroboratingSignal(), no inbox rule. Known evasion: put a real domain in From.
 * Mirrored by _fake_tld_sender() in tests/test_spam_detector.py.
 *
 * @param {string} fromHeader - The decoded From header (getFrom()).
 * @param {string} rawContent - Full RFC 822 message.
 * @param {number} nowMs - Current time (ms since epoch); injectable for the age test.
 * @return {boolean}
 */
function fakeTldSender(fromHeader, rawContent, nowMs)
{
  const snap = Date.parse(TLD_SNAPSHOT_DATE + 'T00:00:00Z');
  if (!(nowMs >= snap) || nowMs - snap > TLD_SNAPSHOT_MAX_AGE_DAYS * 86400000) return false;

  // (a) The From address, from an unambiguous header only.
  const f = trimSpTab(String(fromHeader || ''), ' \t\r\n');
  const lts = f.split('<').length - 1, gts = f.split('>').length - 1;
  let addr;
  if (lts === 0 && gts === 0)
  {
    if (/[ \t\r\n]/.test(f)) return false;
    addr = f;
  }
  else if (lts === 1 && gts === 1 && f.charAt(f.length - 1) === '>' && f.indexOf('<') < f.length - 1)
  {
    addr = trimSpTab(f.substring(f.indexOf('<') + 1, f.length - 1));
  }
  else return false;
  addr = addr.toLowerCase();
  const at = addr.indexOf('@');
  if (at <= 0 || addr.indexOf('@', at + 1) !== -1) return false;
  let domain = addr.substring(at + 1);
  if (!/^[a-z0-9.\-]+$/.test(domain) || !isUnknownTld(domain)) return false;
  if (domain.charAt(domain.length - 1) === '.') domain = domain.substring(0, domain.length - 1);
  const fromOrg = unknownTldOrgDomain(domain);

  // The header block, unfolded, within the scan cap; every occurrence of each header.
  const raw = String(rawContent || '').substring(0, LIMITS.maxRawScanChars).replace(/\r\n/g, '\n');
  const end = raw.indexOf('\n\n');
  const lines = (end === -1 ? raw : raw.substring(0, end)).replace(/\n[ \t]+/g, ' ').split('\n');

  // (b) List-Unsubscribe: at least one http(s)/mailto host; EVERY one on an unknown TLD and in a
  // different organisational domain from the From.
  const hosts = [];
  for (let i = 0; i < lines.length; i++)
  {
    if (lines[i].toLowerCase().indexOf('list-unsubscribe:') !== 0) continue;
    const lu = lines[i].substring('list-unsubscribe:'.length);
    let pos = 0;
    while (true)
    {
      const open = lu.indexOf('<', pos);
      if (open === -1) break;
      const close = lu.indexOf('>', open + 1);
      if (close === -1) break;               // unterminated entry: ignore, never guess a host
      const uri = trimSpTab(lu.substring(open + 1, close)).toLowerCase();
      pos = close + 1;
      if (uri.indexOf('http://') === 0 || uri.indexOf('https://') === 0)
      {
        hosts.push(uri.substring(uri.indexOf('//') + 2).split(/[\/?#:]/)[0]);
      }
      else if (uri.indexOf('mailto:') === 0)
      {
        const mat = uri.lastIndexOf('@');
        if (mat !== -1) hosts.push(uri.substring(mat + 1).split(/[?#]/)[0]);
      }
    }
  }
  if (hosts.length === 0) return false;
  for (let i = 0; i < hosts.length; i++)
  {
    let h = hosts[i];
    if (!isUnknownTld(h)) return false;
    if (h.charAt(h.length - 1) === '.') h = h.substring(0, h.length - 1);
    if (unknownTldOrgDomain(h) === fromOrg) return false;
  }

  // (c) No dkim=pass whose header.d / header.i is in the From's organisational domain, in ANY
  // Authentication-Results header. A forged pass only makes this abstain.
  for (let i = 0; i < lines.length; i++)
  {
    const line = lines[i].toLowerCase();
    if (line.indexOf('authentication-results:') !== 0) continue;
    const parts = line.split(';');
    for (let j = 0; j < parts.length; j++)
    {
      if (parts[j].indexOf('dkim=pass') === -1) continue;
      const ds = [dkimIdentityDomain(parts[j], 'header.d='), dkimIdentityDomain(parts[j], 'header.i=')];
      for (let k = 0; k < 2; k++)
      {
        if (ds[k] && unknownTldOrgDomain(ds[k]) === fromOrg) return false;
      }
    }
  }
  return true;
}

/**
 * The domain in an Authentication-Results "header.d=" / "header.i=" property, or '' (v6.110.0).
 * Reads up to whitespace, ';', '(' or '"' (one leading '"' skipped), then keeps the part after
 * the last '@': "header.i=@mail.example.com", "header.i=first_last+tag@example.com" and
 * header.i="@example.com" all give the domain. A linear scan; the text is sender-influenced.
 * Mirrored in Python by _dkim_identity_domain().
 *
 * @param {string} part - One ';'-separated, lower-cased segment of the header.
 * @param {string} key - 'header.d=' or 'header.i='.
 * @return {string}
 */
function dkimIdentityDomain(part, key)
{
  const at = part.indexOf(key);
  if (at === -1) return '';
  let i = at + key.length;
  if (part.charAt(i) === '"') i++;
  const start = i;
  while (i < part.length && ' \t;("'.indexOf(part.charAt(i)) === -1) i++;
  let v = part.substring(start, i);
  v = v.substring(v.lastIndexOf('@') + 1);
  return v.charAt(v.length - 1) === '.' ? v.substring(0, v.length - 1) : v;
}
