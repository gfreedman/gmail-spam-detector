/**
 * Text.gs — Input sanitization and HTML-to-text helpers.
 *
 * sanitizeInput() bounds attacker-controlled text before any regex touches it —
 * the cap exists to stop quadratic backtracking on a hostile body, not for
 * tidiness. Everything that reads a message field goes through here first.
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
 * The regex /<[^>]+>/ has no nested quantifiers — it is O(n) on input length
 * and safe against ReDoS. Input is also pre-truncated by sanitizeInput().
 *
 * @param {string} html - Raw HTML string.
 * @return {string}       Plain text with tags removed and whitespace collapsed.
 */
function stripHtmlTags(html)
{
  return html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
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
