/**
 * LinkGraph.gs — URL/host parsing, domain matching, and the brand-mismatched CTA scan.
 *
 * The link-graph signal (Rule 7) lives here: it compares the BRAND NAMED IN A
 * LINK'S TEXT against the host the link actually points at, which catches
 * phishing that carries no clickbait, no urgency and a valid DKIM signature.
 *
 * addressMatchesDomain() is also the whitelist/blacklist matcher, and its
 * substring-vs-boundary semantics are security-critical — read its comments
 * before changing them.
 *
 * Apps Script concatenates every .gs file in sources.json into ONE global
 * scope. These are not modules: nothing is imported, and every function here
 * is a global visible to all other files.
 */

/**
 * Extract the lowercase host from a URL taken from an href attribute.
 *
 * Hand-rolled because the Apps Script V8 runtime is not a browser: it exposes
 * no WHATWG URL class (nor URLSearchParams or fetch). Each normalization step
 * below exists because of a specific bypass a mail client would honour:
 *
 *   TAB/CR/LF       browsers DELETE these anywhere in a URL, so
 *                   "https://ev<TAB>il.com" navigates to evil.com. Not
 *                   stripping them means we parse a different host than the
 *                   victim's client does.
 *   backslash       browsers normalize \ to / in the authority, so
 *                   "https:\\evil.com" navigates to evil.com.
 *   scheme          only http/https carry a host we can judge. mailto:, tel:,
 *                   javascript:, cid: and data: return '' (abstain).
 *   missing slashes for special schemes "https:evil.com" is valid.
 *   userinfo        "https://docusign.net@evil.com/" has host evil.com. Split
 *                   on the LAST '@' — that is what browsers do, and browser
 *                   behaviour is what the victim experiences.
 *   port            "docusign.net:8443" -> docusign.net. IPv6 literals are
 *                   bracketed, so the colon scan must follow the ']'.
 *   trailing dot    "docusign.net." and "docusign.net" are the same host.
 *   IDN/punycode    xn--* is already ASCII and compared verbatim; never
 *                   decoded. A raw homoglyph host matches no allowlist entry,
 *                   which reads as a mismatch — the outcome we want.
 *
 * @param {string} href - href value, with HTML entities ALREADY decoded.
 * @return {string} Lowercase host without userinfo, port or trailing dot;
 *                  '' when the URL has no http(s) authority.
 */
function extractUrlHost(href)
{
  if (!href) return '';

  let s = String(href).replace(/[\t\r\n]/g, '').trim();
  if (!s) return '';
  s = s.replace(/\\/g, '/');

  let authority;
  const scheme = s.match(/^([a-z][a-z0-9+.\-]*):\/*/i);
  if (scheme)
  {
    const name = scheme[1].toLowerCase();
    if (name !== 'http' && name !== 'https') return '';
    authority = s.substring(scheme[0].length);
  }
  else if (s.substring(0, 2) === '//')
  {
    authority = s.substring(2); // scheme-relative: //host/path
  }
  else
  {
    return ''; // relative path, #fragment, or no authority at all
  }

  const end = authority.search(/[\/?#]/);
  if (end !== -1) authority = authority.substring(0, end);

  const at = authority.lastIndexOf('@');
  if (at !== -1) authority = authority.substring(at + 1);

  if (authority.charAt(0) === '[') // IPv6 literal
  {
    const close = authority.indexOf(']');
    if (close !== -1) authority = authority.substring(0, close + 1);
  }
  else
  {
    const colon = authority.indexOf(':');
    if (colon !== -1) authority = authority.substring(0, colon);
  }

  return authority.toLowerCase().replace(/\.+$/, '');
}

/**
 * True if `host` is exactly `domain` or a subdomain of it.
 *
 * Exact-or-dot-suffix is the only correct comparison:
 *   includes(domain)  accepts "notdocusign.net" AND "docusign.net.evil.com"
 *   endsWith(domain)  accepts "notdocusign.net"
 *   this              accepts "docusign.net" and "eu.docusign.net" only
 *
 * @param {string} host   - Lowercase host from extractUrlHost().
 * @param {string} domain - Lowercase registrable domain.
 * @return {boolean}
 */
function hostMatchesDomain(host, domain)
{
  if (!host || !domain) return false;
  return host === domain || host.endsWith('.' + domain);
}

/**
 * True if an email address belongs to `domain` or a subdomain of it.
 *
 * Replaces the substring `senderAddress.includes(domain)` idiom, which was a
 * whitelist bypass: "mail@linkedin.com.secure-login.top" contains
 * "linkedin.com" and so skipped ALL detection, as did "a@notlinkedin.com".
 *
 * @param {string} address - Lowercase email address (local@host).
 * @param {string} domain  - Lowercase domain from the whitelist or blacklist.
 * @return {boolean}
 */
function addressMatchesDomain(address, domain)
{
  if (!address || !domain) return false;

  const at = address.lastIndexOf('@');
  const host = (at === -1 ? address : address.substring(at + 1))
    .toLowerCase().replace(/\.+$/, '');

  // Some list entries are deliberately not registrable domains (e.g.
  // 'dragonfly', 'financebuzz'). Those keep substring semantics — but ONLY
  // against the HOST, never the full address.
  //
  // Matching the full address let the local part satisfy the check, and the
  // local part is attacker-chosen:
  //   dragonfly@attacker.tld          -> whitelisted, all detection skipped
  //   financebuzz@realcompany.com     -> blacklisted, Rule 1, PERMANENTLY DELETED
  // The first is a free bypass of the entire detector (and this list is public
  // in the repo); the second destroys a legitimate email. Nine of the
  // blacklist entries have no dot, so the delete path was broadly exposed.
  if (domain.indexOf('.') === -1 || domain.indexOf('@') !== -1)
  {
    // An entry containing '@' was written to match an address fragment
    // (e.g. 'customerservice@stan'), so compare it against the whole address;
    // otherwise restrict the substring test to the host.
    if (domain.indexOf('@') !== -1)
    {
      // Entry written as localpart@hostprefix (e.g. 'customerservice@stan').
      // Require the match to start the address AND end on a domain-label
      // boundary. Without the boundary check 'customerservice@stan' also
      // whitelists 'customerservice@stanley-evil.com' - an attacker need only
      // register a domain beginning with the prefix.
      if (address.indexOf(domain) !== 0) return false;
      const next = address.charAt(domain.length);
      return next === '' || next === '.';
    }
    return host.indexOf(domain) !== -1;
  }

  return hostMatchesDomain(host, domain);
}

/**
 * True if a host is a click-tracker, link-wrapper or security rewriter.
 *
 * Two mechanisms, both needed: an explicit list of ESP/gateway domains, and a
 * leftmost-label heuristic for customer-CNAMEd trackers ("click.acme.com").
 *
 * @param {string} host - Lowercase host from extractUrlHost().
 * @return {boolean}
 * @param {string} host - Host the link actually points at, lowercased.
 * @param {string} senderHost - Host of the sender address, lowercased. A
 *   wrapper on the sender's OWN domain is not a redirect worth flagging.
 */
function isLinkWrapperHost(host, senderHost)
{
  if (!host) return false;

  for (let i = 0; i < LINK_WRAPPER_DOMAINS.length; i++)
  {
    if (hostMatchesDomain(host, LINK_WRAPPER_DOMAINS[i])) return true;
  }

  // The leftmost-label heuristic is honoured ONLY when the host sits under the
  // sender's own domain.
  //
  // Applied globally it was a one-DNS-record bypass of Signal 7: the attacker
  // points the lure at r.evil.com or click.evil.com and the signal abstains,
  // because 'r' and 'click' are tracker labels. The original Capital B lure
  // would have escaped entirely for the cost of one CNAME.
  //
  // The real pattern this models — a sender CNAMEing their own subdomain onto
  // an ESP's click tracker — is always on the sender's own registrable domain
  // (click.acme.com in mail from acme.com). Requiring that alignment keeps the
  // abstention that matters and closes the bypass. Third-party ESP trackers are
  // unaffected: they match LINK_WRAPPER_DOMAINS above.
  if (!senderHost) return false;

  const firstLabel = host.split('.')[0];
  if (TRACKER_LABELS.indexOf(firstLabel) === -1) return false;

  const parent = host.substring(firstLabel.length + 1);
  return parent !== '' && (hostMatchesDomain(parent, senderHost) ||
                           hostMatchesDomain(senderHost, parent));
}

/**
 * Extract href/text pairs from HTML anchors.
 *
 * Deliberately NOT a paired-tag regex. A pattern like
 *   /<a[^>]*>([\s\S]*?)<\/a>/g
 * is polynomial in (anchor count x document length) on attacker-controlled
 * input: every <a> with no closing </a> makes the engine scan to
 * end-of-document before failing, so 900 unclosed anchors in a 4 MB body costs
 * ~3e9 character steps — tens of seconds inside a 6-minute total budget. Mail
 * clients tolerate unclosed anchors, so this is trivially reachable.
 *
 * Instead: one BOUNDED regex for the open tag, then String.indexOf() for the
 * close. indexOf is a native linear scan with no backtracking. It does scan to
 * end-of-document; maxAnchorTextChars caps the substring we KEEP, not the
 * search, so the real bound is maxAnchorsScanned x maxHtmlScanChars — measured
 * at ~9ms worst case. Every quantifier below is explicitly bounded too, so a
 * malformed tag missing its '>' cannot walk the document.
 *
 * @param {string} html - Decoded HTML body from message.getBody().
 * @return {Array<Object>} At most LIMITS.maxAnchorsScanned objects with
 *                         `href` and `text` string properties.
 * @param {string} html - The document being scanned.
 * @param {number} startIdx - Index of the '<' that opens the tag.
 * @param {number} limit - Hard stop; scanning never runs past it, so a tag that
 *   is never closed costs bounded work rather than the rest of the document.
 */
function findTagEnd(html, startIdx, limit)
{
  // Quote-aware scan for the '>' that actually closes a tag.
  //
  // A regex like /<a\s[^>]*>/ terminates at the FIRST '>', including one
  // inside a quoted attribute value. That made
  //     <a title=">" href="https://evil.com/">VIEW IN DOCUSIGN</a>
  // invisible to Signal 7: the "tag" ended at the title's '>', contained no
  // href, and the scan resumed past the real one. Every mail client renders
  // and navigates that anchor normally, so it was a zero-cost bypass.
  //
  // Character scan rather than regex: bounded, linear, no backtracking.
  let quote = '';
  const end = Math.min(startIdx + limit, html.length);

  for (let i = startIdx; i < end; i++)
  {
    const c = html.charAt(i);

    if (quote)
    {
      if (c === quote) quote = '';
      continue;
    }
    if (c === '"' || c === "'") { quote = c; continue; }
    if (c === '>') return i;
  }

  return -1; // unterminated within the bound
}

/**
 * Pull every value of the given attributes out of a bounded HTML fragment.
 *
 * Used for two purposes: reading href off an anchor's own tag, and harvesting
 * the accessible-name attributes (alt/title/aria-label) that a mail client
 * shows the user but a tag-stripper throws away.
 *
 * Safe against ReDoS by construction — callers pass a fragment already bounded
 * by maxAnchorTagChars or maxAnchorTextChars.
 *
 * @param {string} fragment - Bounded HTML.
 * @param {string} namePattern - Alternation of attribute names, e.g. 'alt|title'.
 * @return {Array<string>} Decoded values, in document order.
 */
function extractAttributeValues(fragment, namePattern)
{
  const out = [];
  if (!fragment) return out;

  const re = new RegExp(
    // [\\s/] not just \\s: HTML5 allows '/' as an attribute separator, so
    // <a/href="..."> is a valid anchor that clients navigate normally. Requiring
    // whitespace made it invisible to Signal 7 for the cost of one character.
    '[\\s/](?:' + namePattern + ')\\s*=\\s*(?:"([^"]*)"|\'([^\']*)\'|([^\\s"\'>]*))',
    'gi');

  let m;
  while ((m = re.exec(fragment)) !== null)
  {
    if (m.index === re.lastIndex) { re.lastIndex++; continue; }
    const v = m[1] !== undefined ? m[1] : (m[2] !== undefined ? m[2] : m[3]);
    if (v) out.push(decodeHtmlEntities(v));
    if (out.length >= 32) break; // a tag with 32 alt attributes is not real
  }

  return out;
}

/**
 * Pull every anchor in the HTML out as a {href, text} pair.
 *
 * Hand-written rather than regex-per-anchor because the input is attacker
 * controlled: a crafted body can make a naive /<a[^>]*>(.*?)<\/a>/g backtrack
 * quadratically. This walks the string once, bounded twice over — by
 * LIMITS.maxAnchorsScanned on the number of anchors and by
 * LIMITS.maxAnchorTagChars / maxAnchorTextChars on each one — so a hostile
 * body costs a predictable amount of work rather than a timeout.
 *
 * That bounding is why hasBrandMismatchedCta() can safely be handed the
 * UNTRUNCATED body: the cost ceiling lives here, not in the caller.
 *
 * @param {string} html - Raw message HTML. May be empty, malformed, or hostile.
 * @return {Array<{href: string, text: string}>} Anchors in document order,
 *   href and text both entity-decoded. Empty when there are none.
 */
function extractAnchors(html)
{
  const out = [];
  if (!html) return out;

  const scan = html.length > LIMITS.maxHtmlScanChars
    ? html.substring(0, LIMITS.maxHtmlScanChars)
    : html;

  const lower = scan.toLowerCase();
  let searchFrom = 0;

  while (out.length < LIMITS.maxAnchorsScanned)
  {
    const tagStart = lower.indexOf('<a', searchFrom);
    if (tagStart === -1) break;

    // The character after "<a" must be whitespace or '/'. Requiring only
    // whitespace missed <a/href="..."> — '/' is a valid attribute separator in
    // HTML5 and clients navigate it fine. Anything else (<abbr>, <article>)
    // is a different element.
    const next = scan.charAt(tagStart + 2);
    if (next !== '/' && !/\s/.test(next))
    {
      searchFrom = tagStart + 2;
      continue;
    }

    const tagEnd = findTagEnd(scan, tagStart, LIMITS.maxAnchorTagChars);
    if (tagEnd === -1) { searchFrom = tagStart + 2; continue; }

    const tag  = scan.substring(tagStart, tagEnd + 1);
    const hrefs = extractAttributeValues(tag, 'href');
    searchFrom  = tagEnd + 1;
    if (hrefs.length === 0) continue;

    const textStart = tagEnd + 1;
    const closeIdx  = lower.indexOf('</a', textStart);
    // indexOf() scans to end-of-document; maxAnchorTextChars caps the substring
    // we KEEP, not the search. The overall bound is therefore
    // maxAnchorsScanned x maxHtmlScanChars, measured at ~9ms worst case.
    const cap     = Math.min(textStart + LIMITS.maxAnchorTextChars, scan.length);
    const textEnd = (closeIdx === -1 || closeIdx > cap) ? cap : closeIdx;
    const innerRaw = scan.substring(textStart, textEnd);

    // Visible text: strip nested markup so <span>Docu</span><span>Sign</span>
    // collapses to "DocuSign" — attackers split brand names across elements.
    const visible = decodeHtmlEntities(innerRaw.replace(/<[^>]{0,2000}>/g, ''));

    // Accessible text: alt, title and aria-label, from the anchor's own tag and
    // from anything nested inside it.
    //
    // Without this an image button defeated Signal 7 completely:
    //     <a href="https://evil.com/"><img alt="View in DocuSign"></a>
    // There is no text node at all, so the stripper produced an empty string.
    // This is not an exotic evasion — an image CTA is what real phishing
    // already uses, because it renders identically and dodges text scanners.
    // A mail client shows the user "View in DocuSign"; now so do we.
    const accessible = extractAttributeValues(tag, 'title|aria-label')
      .concat(extractAttributeValues(innerRaw, 'alt|title|aria-label'))
      .join(' ');

    const text = (visible + ' ' + accessible).replace(/\s+/g, ' ').trim();

    // A single anchor can legitimately carry several hrefs only if malformed;
    // judge the first, which is what a client honours.
    out.push({ href: hrefs[0], text: text });

    if (textEnd > searchFrom) searchFrom = textEnd;
  }

  return out;
}

/**
 * Detect a call-to-action link that borrows a document brand's name while
 * pointing somewhere that brand does not control.
 *
 * All four conditions must hold for an anchor to fire:
 *   1. normalized link text contains a BRAND_CTA_DOMAINS key, carries a
 *      CTA verb, and its NORMALIZED text is <= 80 chars (a button label,
 *      not prose) — measured after stripping non-alphanumerics, so padding
 *      with zero-width characters cannot inflate it past the bound
 *   2. href resolves to an http(s) host
 *   3. that host matches none of the brand's legitimate domains
 *   4. that host is not a link wrapper, and is not aligned with the sender's
 *      own domain
 *
 * Condition 4's wrapper exemption is what keeps legitimate ESP-tracked mail
 * out; condition 1's verb and length requirements are what keep a genuine
 * DocuSign email's "About DocuSign" footer prose out.
 *
 * @param {string} html          - Decoded HTML body.
 * @param {string} senderAddress - Lowercase sender email address.
 * @return {boolean} true if a brand-mismatched CTA is present.
 */
function hasBrandMismatchedCta(html, senderAddress)
{
  if (!html) return false;

  // Cheap necessary-condition gate: no anchors, no brand CTA. This is the only
  // safe document-level shortcut available.
  //
  // A tempting stronger gate — indexOf(brandKey) over the whole HTML before
  // walking anchors — is WRONG, and silently so. Link text is normalized
  // per-anchor (tags stripped, entities decoded, punctuation removed) precisely
  // because attackers write "D&#111;cu&shy;Sign" or
  // "<span>Docu</span><span>Sign</span>". Neither contains the literal
  // "docusign", so a raw-HTML brand gate rejects exactly the evasions the
  // normalization exists to catch. The gate would have to normalize the whole
  // document to be correct, which costs as much as the bounded anchor walk it
  // was meant to avoid. So: no brand pre-gate. The walk is bounded by
  // LIMITS (256 KB scanned, 300 anchors, 2 KB text each) and measures ~1 ms.
  if (html.indexOf('<a') === -1) return false;

  const brands     = Object.keys(BRAND_CTA_DOMAINS);
  const senderAt   = senderAddress ? senderAddress.lastIndexOf('@') : -1;
  const senderHost = senderAt === -1 ? '' : senderAddress.substring(senderAt + 1);

  const anchors = extractAnchors(html);
  for (let a = 0; a < anchors.length; a++)
  {
    const text = anchors[a].text;
    if (!text) continue;
    if (!CTA_VERB_PATTERN.test(text)) continue;

    // Normalize away spacing and punctuation so "Docu Sign", "Docu-Sign" and
    // "DOCUSIGN->" all collapse onto the bare key form.
    const normText = text.toLowerCase().replace(/[^a-z0-9]+/g, '');

    // Length bound measured on the NORMALIZED text, not the raw text.
    //
    // Measuring raw length was evadable two ways, one of them accidental:
    //   - padding with characters JS \s does not match (U+200B zero-width
    //     space) inflated length past the cap while rendering identically;
    //   - an ordinary verbose label — "Please review and open your secure
    //     DocuSign document envelope today" (67 chars) — exceeded it with no
    //     trickery at all.
    // Counting only alphanumerics makes padding useless, and 80 leaves room
    // for genuinely wordy buttons while still excluding prose paragraphs.
    if (normText.length > 80) continue;

    for (let b = 0; b < brands.length; b++)
    {
      const brand = brands[b];
      if (normText.indexOf(brand) === -1) continue;

      const host = extractUrlHost(anchors[a].href);
      if (!host) break;                       // mailto:/relative — abstain

      const legit = BRAND_CTA_DOMAINS[brand];
      let isLegit = false;
      for (let d = 0; d < legit.length; d++)
      {
        if (hostMatchesDomain(host, legit[d])) { isLegit = true; break; }
      }
      if (isLegit) break;                     // genuine brand destination

      if (isLinkWrapperHost(host, senderHost)) break; // wrapped — destination unknown

      // Aligned with the sender's own domain: a company linking its own
      // infrastructure is not impersonating anyone.
      if (senderHost && (hostMatchesDomain(host, senderHost) ||
                         hostMatchesDomain(senderHost, host))) break;

      logDebug('Brand-mismatched CTA: text=' + sanitizeForLog(text) +
               ' brand=' + brand + ' host=' + sanitizeForLog(host));
      return true;
    }
  }

  return false;
}

/**
 * Extract the email address from a From header value.
 *
 * Handles both "Display Name <user@domain.com>" and bare "user@domain.com".
 * Used so whitelist/blacklist checks operate on the actual sender address,
 * not the display name — prevents display-name spoofing such as:
 *   "LinkedIn News <spammer@spam.com>" bypassing the whitelist, or
 *   "financeinsiderpro.com news <legit@gmail.com>" triggering the blacklist.
 *
 * @param {string} from - Normalized From header value (RFC 2822 quotes stripped).
 * @return {string}       Lowercase email address, or full from if no <> present.
 */
function extractEmailAddress(from)
{
  if (!from) return '';

  // Angle-bracket form first: "Display Name <addr@host>". Most common.
  const angled = from.match(/<([^>]+)>/);
  if (angled) return angled[1].trim().toLowerCase();

  // RFC 2822 also permits the comment form: "addr@host (Display Name)".
  // Returning the whole string here made addressMatchesDomain() derive a host
  // of "substack.com (substack digest)", which matches no whitelist entry — so
  // a WHITELISTED sender using this form failed the whitelist check. That was
  // harmless while the consequence was "stays in the Spam folder"; it becomes
  // data loss the moment any path deletes on a failed whitelist match.
  const commented = from.match(/([^\s<>()]+@[^\s<>()]+)/);
  if (commented) return commented[1].trim().toLowerCase();

  return from.trim().toLowerCase();
}

/**
 * Sanitize text for safe inclusion in log messages.
 *
 * Truncates to 100 chars and strips newlines to prevent "log injection".
 * Example: a spam subject of "OK\n[ERROR] Deleted your inbox" would print two
 * separate log lines without sanitization — the second line looks like the
 * script emitted it. Stripping newlines closes that loophole.
 *
 * @param {string} text - Text to sanitize for logging.
 * @return {string} Truncated, single-line string safe for log output.
 */
function sanitizeForLog(text)
{
  if (text == null) return '';
  return String(text).substring(0, LIMITS.maxLogChars).replace(/[\n\r]/g, ' ');
}
