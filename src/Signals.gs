/**
 * Signals.gs — Signal collection: the whitelist gate, field extraction, 15 detections.
 *
 * ONE function, deliberately long. Twenty-two try/catch blocks write sixteen signal
 * keys (seven of them accumulate into clickbaitCount), and every block is wrapped
 * individually because a single throw once discarded eight of eleven signals.
 *
 * That structure is load-bearing, not accidental: code INSIDE a block degrades
 * one signal; code OUTSIDE one propagates to analyzeMessage()'s catch-all and
 * the message is never judged at all. Moving a line across a try boundary
 * changes disposition. A decomposition was reviewed and declined — see
 * docs/BACKLOG.md 2.3a for what it would require first.
 *
 * Apps Script concatenates every .gs file in sources.json into ONE global
 * scope. These are not modules: nothing is imported, and every function here
 * is a global visible to all other files.
 */

// =============================================================================
// Spam Detection Engine
// =============================================================================

/**
 * Collect all spam signals from a message.
 *
 * Design principle — separation of concerns:
 *   collectSignals() answers "what's in this email?" (facts)
 *   makeVerdict()    answers "is this spam?"           (judgement)
 * Keeping them separate makes each function easier to test and debug.
 * If an email is incorrectly flagged, you can inspect the signals object
 * to see exactly which patterns fired, without needing to trace through
 * the rule logic at the same time.
 *
 * Extracts and normalizes email fields, checks the whitelist, then populates
 * a signals object from independent detection categories. Each signal is
 * evaluated without reference to the others — verdict logic lives in
 * makeVerdict().
 *
 * @param {GmailMessage} message - The Gmail message to analyze.
 * @return {Object|null} Signals object with boolean/numeric fields,
 *                       or null if sender is whitelisted (skip detection).
 */
function collectSignals(message)
{
  // ── Whitelist check first — before any expensive field fetch ────────────
  // getFrom() is cheap (metadata from cached search results). getRawContent()
  // is an expensive separate HTTP download of the full RFC 822 message.
  // Checking the whitelist immediately means whitelisted senders (LinkedIn,
  // Substack, Meetup, etc. — DEFAULT_DOMAINS.legitimate is the real list;
  // GitHub/Stripe/banks are NOT in it) never trigger a raw message download.
  // IMPORTANT: match against the extracted email address only, not the full
  // From string — prevents display-name spoofing such as:
  //   "LinkedIn News <spammer@spam.com>" bypassing the whitelist check.
  // Extract the address from the UNTRUNCATED From, then truncate only what
  // feeds pattern matching.
  //
  // Truncating first cut the address off any header with a display name longer
  // than maxFromChars, so the whitelist check silently missed. Same story as
  // the comment form above: tolerable when the outcome was "stays in Spam",
  // unacceptable once a failed whitelist match can mean deletion. The
  // truncation exists to bound quadratic regex cost on attacker-controlled
  // text, which the address extraction does not participate in.
  const fromRaw = sanitizeInput(message.getFrom());
  const senderAddress = extractEmailAddress(
    fromRaw.replace(RFC2822_QUOTED_NAME, '$1$2'));
  const from = fromRaw
    .substring(0, LIMITS.maxFromChars)
    .replace(RFC2822_QUOTED_NAME, '$1$2');

  const whitelist = getCachedWhitelist();
  for (let i = 0; i < whitelist.length; i++)
  {
    // addressMatchesDomain(), NOT includes(). Substring matching here was a
    // complete detection bypass: "mail@linkedin.com.secure-login.top" contains
    // "linkedin.com" and so returned null before any signal was collected, as
    // did "a@notlinkedin.com". Anyone who registered a domain containing a
    // whitelisted string got a blanket exemption.
    if (addressMatchesDomain(senderAddress, whitelist[i]))
    {
      logDebug('Whitelisted domain detected: ' + whitelist[i]);
      return null; // null = whitelisted, skip all detection
    }
  }

  // ── Extract remaining fields (only reached for non-whitelisted senders) ─
  // Truncated hard for pattern matching — see LIMITS.maxSubjectChars for the
  // quadratic-regex measurements that motivate it.
  const subject = sanitizeInput(message.getSubject()).substring(0, LIMITS.maxSubjectChars);
  // Fall back to HTML-stripped body if plain body is empty (HTML-only emails).
  // Without this fallback, BODY_CRYPTO_PATTERNS would silently never fire on
  // messages that have no text/plain part.
  const plainBody = message.getPlainBody();

  // getBody() returns the decoded, charset-normalized HTML.
  //
  // This is free ONLY on the inbox path. shouldProcessMessage() calls getBody()
  // for its size check, so the GmailMessage has it cached — but that guard is
  // called from exactly one place, Thread.gs, and four other paths reach
  // collectSignals() without it: cleanseInbox(), checkFalseNegatives(),
  // recheckRecentSpamChecked() and reviewGmailSpam(). On those, this IS an
  // extra round trip, and CONFIG.maxEmailSizeBytes is not enforced either — so
  // the Spam-folder review will happily pull a 25MB message.
  //
  // getRawContent() costs a separate fetch (format=raw vs format=full) on
  // every path, guarded or not.
  const rawHtml = message.getBody();
  const html = sanitizeInput(rawHtml);

  // Truncate BEFORE stripping, not after. Previously sanitizeInput() wrapped
  // the *result* of stripHtmlTags(), so the two regex passes ran across up to
  // 5 MB (the shouldProcessMessage ceiling) and allocated two 5 MB
  // intermediates on every HTML-only message.
  // .trim() matters: a text/plain part containing a single space is truthy,
  // so the HTML fallback never ran and Signals 2b/2c/2d all saw an empty
  // body. One space in the plain part disabled every body-based signal.
  //
  // Counts signals that threw and were skipped. A verdict reached with fewer
  // signals than intended is not a trustworthy "clean" — see _degraded below.
  // Declared HERE, before the first thing that can throw, because the body
  // extraction below is itself guarded.
  let signalsSkipped = 0;

  // Guarded, unlike the fetches around it. getBody()/getRawContent() failing is
  // transient, so analyzeMessage() turning it into unevaluated:'error' and
  // retrying is right. This line is computation on attacker-supplied HTML, so a
  // throw would recur on every retry. Unguarded, it discards the sender, subject
  // and link-graph signals along with the body ones; guarded, those still run
  // and CAN convict. (Without a verdict, a clean-looking message ends flagged
  // and stamped after one retry either way.) An empty body plus signalsSkipped
  // keeps every signal that does not need the body and marks the verdict
  // degraded. Other computation above (sanitizeInput, extractEmailAddress) is
  // also unguarded; neither is known to throw on a string.
  let body = '';
  try
  {
    body = sanitizeInput(plainBody).trim() || stripHtmlTags(html);
  }
  catch (bodyError)
  {
    signalsSkipped++;
    logError('Body extraction threw; body signals will see an empty body: ' + bodyError.toString());
  }
  const rawContent = message.getRawContent(); // Full RFC 822 content (includes all headers)

  // ── Values shared across signal blocks ──────────────────────────────────
  // Declared here, not inside the block that first needs them, because each
  // signal below is individually wrapped in try/catch — and a `const` declared
  // inside a try is not visible to the next block. Anything two signals share
  // has to outlive both.
  const textToCheck = subject + ' ' + from;   // Signals 2 and 3
  const atIdx       = senderAddress.lastIndexOf('@');
  let   isThrowawayHost = false;              // free mail OR a throwaway tenant; set by 8, read by 9 and 10
  let   selfNamedLoose  = false;              // set by Signal 10, read ONLY by Signal 9 — see Signal 10

  // ── Initialize signal accumulators ───────────────────────────────────────
  // Each detection phase below populates one signal. makeVerdict() combines
  // them to produce the spam/not-spam decision.
  const signals = {
    bulkEmailService: false,          // Sent via Amazon SES, SendGrid, or Mailchimp
    blacklistedSender: false,         // From a known spam mill domain
    clickbaitCount: 0,                // Number of clickbait patterns matched
    fearMongering: false,             // Contains fear-mongering language
    marketingFormat: false,           // From field uses marketing formatting
    suspiciousFromName: false,        // Display name is headline-like
    emptySubjectWithAttachment: false, // Empty subject + has attachment (payload scam)
    serviceImpersonation: false,       // Cloud service subject from non-service sender (phishing)
    brandMismatchedCta: false,         // CTA names a document brand, links elsewhere (phishing)
    freeMailRandomLocal: false,        // free-mail sender with a machine-generated local part
    callbackPhishing: false,           // fake brand invoice from free mail, payload is a phone number
    selfNamedSender: false,            // free-mail sender using the recipient's own name, not their address
    calendarLure: false,               // unknown-sender calendar invite: voicemail lure in the title + off-domain link
    headlineFromName: false,           // display name is "<headline> - <brand>"; Spam-folder corroboration only
    attachmentPayloadScam: false,      // Bcc'd free-mail ALL-CAPS note whose payload is an attachment; Spam-folder corroboration only
    sponsoredAdTemplate: false,        // ad disclaimer + advertiser sentence + "Sponsored Content" block + 2 credits; Rule 11
    blacklistedRelayIdentity: false,   // a blacklisted brand domain behind an ESP relay (From mailbox + Reply-To); Rule 12
    millFooterAddress: false,          // a known mill footer address in sender-authored text + List-Unsubscribe; Rule 13 (DELETES, archived first)
    pitchScore: false                  // List-Unsubscribe + a finance-pitch word/link-host score over the threshold; Rule 14 (DELETES, archived first; no-history gate in analyzeMessage)
  };

  // ── Signal 1a: Bulk email service detection ─────────────────────────────
  // Check raw email headers for bulk service fingerprints (see BULK_EMAIL_FINGERPRINTS).
  // Bulk email services (Amazon SES, SendGrid, Mailchimp) are used by both legitimate senders
  // like LinkedIn AND spam mills, so this signal alone is not enough to call
  // something spam. But it "multiplies" other signals: if you're using bulk
  // infrastructure AND have clickbait subjects, that combination is very suspicious.
  // Rules 1-3 all require bulk email as a prerequisite for exactly this reason.
  try
  {
    if (isBulkEmail(rawContent))
    {
      signals.bulkEmailService = true;
      logDebug('Bulk email service detected');
    }
  }
  catch (signalError)
  {
    // Fail CLOSED for this signal only: it contributes nothing, the
    // rest still run, and signalsSkipped makes the gap visible.
    signalsSkipped++;
    logError('Signal 1a threw and was skipped: ' + signalError.toString());
  }

  // ── Signal 1b: Blacklisted sender domain ────────────────────────────────
  // Substring match against known spam mill domains from Script Properties.
  // One match is enough — these domains have no legitimate use.
  // Match against the extracted email address only (not the display name) for
  // the same reason as the whitelist check above — prevents spoofing both ways.
  try
  {
    const blacklist = getCachedBlacklist();
    for (let i = 0; i < blacklist.length; i++)
    {
      // Strict domain matching, same reasoning as the whitelist above.
      if (addressMatchesDomain(senderAddress, blacklist[i]))
      {
        signals.blacklistedSender = true;
        logDebug('Blacklisted sender detected: ' + blacklist[i]);
        break;
      }
    }
  }
  catch (signalError)
  {
    // Fail CLOSED for this signal only: it contributes nothing, the
    // rest still run, and signalsSkipped makes the gap visible.
    signalsSkipped++;
    logError('Signal 1b threw and was skipped: ' + signalError.toString());
  }

  // ── Signal 1c: Suspicious From display name ─────────────────────────────
  // Strip the <email@address> portion, then check the remaining display name.
  // Legitimate senders use plain names ("John Smith"); spam mills stuff
  // headlines into display names ("Breaking • Banks Closing • Alert").
  try
  {
    const fromDisplayName = stripTrailingAngle(from).trim(); // quotes already stripped above
    if (fromDisplayName.includes('•') ||     // Bullet separator — never used by legitimate senders
        fromDisplayName.length > LIMITS.maxDisplayNameLength) // Excessive length — keyword stuffing
    {
      signals.suspiciousFromName = true;
      logDebug('Suspicious From name detected: ' + sanitizeForLog(fromDisplayName));
    }

    // Subject echo removed: caused false positives on legitimate company emails
    // (e.g. "Your Converse Canada order" + From "Converse Canada") — a company
    // using its own name in both fields is normal, not suspicious. All spam
    // previously caught by this signal was already caught by Rule 1 (blacklist).
  }
  catch (signalError)
  {
    // Fail CLOSED for this signal only: it contributes nothing, the
    // rest still run, and signalsSkipped makes the gap visible.
    signalsSkipped++;
    logError('Signal 1c threw and was skipped: ' + signalError.toString());
  }

  // ── Signal 12: Headline-then-brand From display name ───────────────────
  // "Stop Eating Fruit This Way - (Smart Fund Insiders)". The spam mills in the
  // Raw Log put a teaser headline in the display name and the brand after a
  // separator; 633 of 704 logged detections (90%) have this shape. It reached
  // the Spam folder from a fresh domain at exactly 50 characters — one short
  // of Signal 1c's length cap — with FEAR as its only other signal, so it sat
  // out the 7-day grace period.
  //
  // CORROBORATION ONLY, never an inbox conviction: two of the 26 ham fixtures
  // have the same shape ("The LINE Austin - P6 Up 'n go Pay", a Toast receipt),
  // and so does any "Jane Doe - Acme Realty". It is not in makeVerdict() or
  // getRuleFromSignals(); hasCorroboratingSignal() counts it as the From
  // name's ONE weak point, shared with suspiciousFromName, so a name that
  // trips both still scores one. It deletes nothing unless Gmail already
  // filed the message as spam AND a second weak signal fired — which may come
  // from the same display name, since clickbait and fear scan it too.
  //
  // indexOf scans only — linear on a sender-controlled string.
  try
  {
    const displayName = stripTrailingAngle(from).trim();
    let sepAt = -1, sepLen = 0;
    HEADLINE_NAME_SEPARATORS.forEach(function(ch) {
      const i = displayName.indexOf(' ' + ch + ' ');
      if (i !== -1 && (sepAt === -1 || i < sepAt)) { sepAt = i; sepLen = ch.length + 2; }
    });
    if (sepAt !== -1 &&
        displayName.substring(0, sepAt).trim().split(/\s+/).length >= 2 &&
        displayName.substring(sepAt + sepLen).trim() !== '')
    {
      signals.headlineFromName = true;
      logDebug('Headline-then-brand From name: ' + sanitizeForLog(displayName));
    }
  }
  catch (signalError)
  {
    // Fail CLOSED for this signal only: it contributes nothing, the
    // rest still run, and signalsSkipped makes the gap visible.
    signalsSkipped++;
    logError('Signal 12 threw and was skipped: ' + signalError.toString());
  }

  // ── Signal 14: Sponsored-ad template ───────────────────────────────────
  // "The \"1973 Loophole\" in Trump's new financial plan", From "Trend Watchers
  // Lab <cole.emerson.trendwatcherslab.com@email.cyberimpact.com>": a gold-IRA
  // lead-gen promo that scored ZERO on every other signal - clean subject, a
  // shared ESP's sending domain, no bulk fingerprint. Its template is the tell:
  // an "This is an advertisement." disclaimer followed by the ad network's "If
  // you no longer wish to receive promotional messages from this advertiser"
  // sentence, a "Sponsored Content" block, and a "Sponsored by <name>" (or, from v6.85.0, "Ad by <name>") credit
  // under each teaser link.
  //
  // v6.79.0/6.80.0 keyed on the SENDER STRUCTURE instead (display name ==
  // dotted mailbox) from a header nobody had seen, and never fired on the real
  // mail. Adding the ESP to BULK_EMAIL_FINGERPRINTS was also rejected: bulk
  // gates Rules 1-3, which delete, for every legitimate sender on that ESP.
  //
  // Convicts on its own (Rule 11, DELETES - the user's explicit call, including
  // for the relay shape below, which Signal 15 also reads for its own purpose) and is STRONG in hasCorroboratingSignal().
  // Text goes through normalizeAdText() first (entities, NFKC, lookalike letters,
  // dashes, zero-width characters, spaces). Two shapes, both needing the
  // disclaimer and the block heading:
  //   STRICT - plus the ad network's advertiser sentence and 2 credit lines
  //            ("Sponsored by" or "Ad by"; pattern 4).
  //            The guard the first review asked for: six plausible editorial-
  //            newsletter bodies carried the other three phrases and would have
  //            been deleted without it.
  //   RELAY  - (v6.83.0) instead of the sentence: 3 credit lines AND the sender
  //            shape of an ad mill on an ESP relay - the From mailbox is
  //            "<brand-domain>@<esp>" (its local part ends in the Reply-To
  //            domain) and the Reply-To is on a different domain. Same network,
  //            reworded disclaimer, no advertiser sentence: the 2026-10-24
  //            AutoCamp miss. A first draft accepted "disclaimer twice" here;
  //            the panel built editorial digests with two labelled ad blocks
  //            that it deleted. A second draft's disclaimer matched "this is an
  //            ad-free edition"; the short form must now end its clause.
  //            Authentication cannot separate a mill from a tenant (the ESP signs
  //            for both), so it is not used. Declined on review, with reasons:
  //            an ESP allowlist (the mill can move ESPs; the shape is the tell),
  //            and a header-only conviction (Precedence/one-click are on every
  //            newsletter - that is the scored classifier, not this rule).
  // Checked on three views of the message (plain body; HTML with tags as spaces;
  // HTML with tags deleted), because a multipart message's plain part is not
  // guaranteed to carry the sponsor block and a tag inside a word splits it.
  // Cheap to evade - reword the heading/credit/disclaimer, put the credits in
  // images, or change the sender shape - it buys time, not lasting coverage.
  // False positive class: a legitimate sender that carries the template; none
  // exists in the user's mailbox, and the Drive archive keeps a copy of anything
  // deleted.
  //
  // split() over text capped by sanitizeInput - linear. The patterns have no
  // capture groups (split would splice them into the count); a test asserts it.
  try
  {
    const relayShape = function() {
      const sender = senderAddress.toLowerCase();
      const local = sender.substring(0, atIdx);
      const senderHost = sender.substring(atIdx + 1);
      const replyTo = headerAddresses(getRawHeader(rawContent, 'Reply-To'))[0] || '';
      const replyHost = replyTo.substring(replyTo.lastIndexOf('@') + 1);
      return atIdx > 0 && replyHost.indexOf('.') > 0 && replyHost !== senderHost &&
             (local === replyHost || local.endsWith('.' + replyHost));
    };
    const hasAdTemplate = function(text) {
      const t = normalizeAdText(text);
      const count = function(i) { return t.split(SPONSORED_AD_PATTERNS[i]).length - 1; };
      if (count(0) < 1 || count(2) < 1) return false;
      // STRICT: the advertiser sentence, 2 credits. RELAY: the sender shape
      // and 3 credits - one more than strict, because the sentence is gone.
      // STRICT counts the wider credit label (index 4: "sponsored by" or "ad by"); RELAY
      // keeps the tight one (index 3) because it has no advertiser sentence to guard it.
      return (count(1) >= 1 && count(4) >= 2) || (count(3) >= 3 && relayShape());
    };
    // Three views of the same message: the plain body, the HTML with tags turned
    // into spaces, and the HTML with tags DELETED (a tag inside a word, "adver<b>
    // </b>tisement", glues back together only in the last).
    if (hasAdTemplate(body) || hasAdTemplate(stripHtmlTags(html)) ||
        hasAdTemplate(replaceAngles(html, '', 1)))
    {
      signals.sponsoredAdTemplate = true;
      logDebug('Sponsored-ad template: disclaimer + sponsor block + credit lines + advertiser sentence or relay sender');
    }
  }
  catch (signalError)
  {
    // Fail CLOSED for this signal only: it contributes nothing, the
    // rest still run, and signalsSkipped makes the gap visible.
    signalsSkipped++;
    logError('Signal 14 threw and was skipped: ' + signalError.toString());
  }

  // ── Signal 15: Blacklisted brand domain behind an ESP relay ─────────────
  // The Trend Watchers Lab ad mill reworded its template three times in four
  // days (v6.81, v6.83, v6.85), each time slipping past Signal 14, which is bound
  // to wording. What did not change: it always sends as
  // "<name>.trendwatcherslab.com@email.cyberimpact.com" with
  // "Reply-To: support@trendwatcherslab.com". The sender blacklist (Signal 1b)
  // cannot see that, because it matches the SENDING domain, which here is the
  // ESP's; and Rule 1 needs a bulk fingerprint, which a shared ESP deliberately
  // is not (it would expose every legitimate tenant to Rules 1-3).
  //
  // So match the blacklist against the brand BEHIND the relay: the Reply-To host
  // must be a blacklist entry AND the sender must have the relay shape (the From
  // mailbox is, or ends with ".", the Reply-To host, and that host is not the
  // sending host). The shape is the stand-in for "bulk": a human writing from a
  // Gmail address cannot satisfy it, so a colleague, a mailing list or a friend
  // forwarding a mill email (each reproduced in review with Reply-To alone) does
  // not fire. A third party cannot use it to get someone else's mail deleted:
  // the legitimate sender must have authored both headers. Convicts alone (Rule
  // 12, DELETES like Rule 1, behind the Drive-archive gate) and is STRONG in
  // hasCorroboratingSignal(). The post-deploy recheck only HOLDS it: the
  // blacklist is user-editable at runtime, so an entry added tomorrow must not
  // retroactively delete mail already read (RECHECK_DELETE_RULES).
  //
  // Reads EVERY Reply-To address, so a decoy listed first is not enough, and
  // strips a trailing dot and zero-width characters. Only FULL-DOMAIN blacklist
  // entries count (see the loop). Known gaps, cheap for the mill and not closed,
  // each pinned by a test: dropping Reply-To; a second "Reply-To:" line;
  // "Reply-To :" with whitespace before the colon (getRawHeader() is shared with
  // Delivered-To/To/Cc, and Signal 13 fires only when Delivered-To is ABSENT, so
  // loosening it could flip that signal toward a false positive - not touched
  // here); a display name past getRawHeader()'s 200-char cap; a From mailbox
  // that stops embedding the brand host (one ESP template change); a Reply-To on a
  // subdomain while the mailbox embeds the parent. A fresh brand domain also escapes
  // until one data line is added; that is the point: the answer to a new brand is
  // data, not code or a deploy. False positive class: a legitimate tenant of a
  // full-domain entry the user blacklisted.
  try
  {
    if (atIdx > 0)
    {
      const relaySender = senderAddress.toLowerCase();
      const relayLocal  = relaySender.substring(0, atIdx);
      const relayHost   = relaySender.substring(atIdx + 1).replace(/\.+$/, '');
      const replyTos    = headerAddresses(getRawHeader(rawContent, 'Reply-To'));
      const blacklistForRelay = getCachedBlacklist();
      // No cap on the address count: getRawHeader() already bounds the header at 200
      // chars, so the loop is bounded; a count cap only handed the mill a free
      // evasion (11 decoys, reproduced in review).
      for (let r = 0; r < replyTos.length && !signals.blacklistedRelayIdentity; r++)
      {
        // Zero-width characters are removed first: one after the host (a@brand.com<U+200B>)
        // otherwise made the host a different string and hid the match.
        const replyTo   = replyTos[r].replace(/[\u200b-\u200d\u2060\ufeff]/g, '').replace(/\.+$/, '');
        const replyHost = replyTo.substring(replyTo.lastIndexOf('@') + 1);
        if (replyHost.indexOf('.') <= 0 || replyHost === relayHost) continue;
        if (relayLocal !== replyHost && !relayLocal.endsWith('.' + replyHost)) continue;
        for (let i = 0; i < blacklistForRelay.length; i++)
        {
          // FULL DOMAINS ONLY. A dotless entry ("financebuzz", "investorplace") has
          // host-SUBSTRING semantics in addressMatchesDomain(), which is tolerable for
          // Signal 1b (it also needs bulk) but here would delete an unrelated relay
          // tenant whose host merely contains the fragment (financebuzzfans.org,
          // realinvestorplace.co.uk - both reproduced in review). So skip entries
          // without a dot, and address-fragment entries ('@'), including user-added ones.
          if (blacklistForRelay[i].indexOf('.') === -1 || blacklistForRelay[i].indexOf('@') !== -1) continue;
          if (addressMatchesDomain(replyTo, blacklistForRelay[i]))
          {
            signals.blacklistedRelayIdentity = true;
            logDebug('Blacklisted brand behind an ESP relay: ' + blacklistForRelay[i]);
            break;
          }
        }
      }
    }
  }
  catch (signalError)
  {
    // Fail CLOSED for this signal only: it contributes nothing, the
    // rest still run, and signalsSkipped makes the gap visible.
    signalsSkipped++;
    logError('Signal 15 threw and was skipped: ' + signalError.toString());
  }

  // ── Signal 16: Known mill footer address (v6.98.0) ───────────────────────
  // DELETES (Rule 13) since v6.100.0, after the Drive archive (v6.98.0 shipped it as a
  // quarantine). The finance-ad mill rotates brand
  // domains, templates and wording for free (Signals 14 and 15 were each beaten
  // by a one-word change), but CAN-SPAM obliges every send to print a postal
  // address, and that changes far more slowly. The observer that logged this
  // address on the Macro View Digest miss (`postal=fwy`) took no action; this
  // makes the same evidence act.
  //
  // Two conditions, both required:
  //   (a) a MILL_POSTAL_NEEDLES address in the text the SENDER wrote
  //       (stripQuotedAndForwarded(): a forwarded or quoted mill email does not
  //       fire), matched on word boundaries after normalizeAdText() and a
  //       non-alphanumeric fold;
  //   (b) a List-Unsubscribe header. Mass mail carries one (Gmail requires it of
  //       bulk senders) and a person forwarding or replying does not, which is
  //       the stand-in for "bulk" on a shared ESP, where isBulkEmail() is false
  //       on purpose (see Signal 15 / Rule 11).
  // The rule is NOT bound to wording, brand or sending domain.
  //
  // Measured on the fixtures before shipping: the address alone matches 24/66
  // spam, 0/28 ham, 0/8 scam. Panel review (Google, Yahoo, Stanford, Waterloo,
  // 2026-11-06) scored the address+themes design 56/100 and asked for exactly
  // these amendments; the "no sender history" condition it also asked for needs
  // a Gmail search and so cannot live in a signal that the Python mirror and the
  // parity phase must reproduce. It is not implemented.
  //
  // False positive classes, recoverable only from the Drive archive copy and the Raw Log row
  // (the message itself is deleted): a legitimate sender in a shared building that
  // prints the same address; a newsletter that lists scam addresses in its own
  // text (an anti-fraud digest); a needle that goes stale when a mill leaves
  // and a legitimate tenant arrives. Known evasions, cheap for the mill: a new
  // address, the address as an image, dropping List-Unsubscribe.
  try
  {
    if (getRawHeader(rawContent, 'List-Unsubscribe'))
    {
      const authored = ' ' + normalizeAdText(stripQuotedAndForwarded(body))
        .replace(/[^a-z0-9 ]/g, ' ').replace(/ +/g, ' ') + ' ';
      for (let i = 0; i < MILL_POSTAL_NEEDLES.length; i++)
      {
        if (authored.indexOf(' ' + MILL_POSTAL_NEEDLES[i] + ' ') !== -1)
        {
          signals.millFooterAddress = true;
          logDebug('Mill footer address: ' + MILL_POSTAL_NEEDLES[i]);
          break;
        }
      }
      // (c) v6.102.0: a "Sponsored Content" block crediting TWO distinct paid-promo publishers
      // (MILL_PROMO_PUBLISHERS) that the From line is not itself one of. This is the ad slot a
      // mill sells; a publisher's own list, a news story naming two firms, or an event "sponsored
      // by" one of them all lack the block or the second name. Narrowed after review built 11
      // deleted false positives from a broader credit-phrase design: the no-history gate does NOT
      // protect a first welcome email or a never-opened subscription (Thread.gs).
      if (!signals.millFooterAddress)
      {
        const credit = millPromoCredit(authored, from);
        if (credit)
        {
          signals.millFooterAddress = true;
          logDebug('Mill paid-promo credit: ' + credit);
        }
      }
    }
  }
  catch (signalError)
  {
    // Fail CLOSED for this signal only: it contributes nothing, the
    // rest still run, and signalsSkipped makes the gap visible.
    signalsSkipped++;
    logError('Signal 16 threw and was skipped: ' + signalError.toString());
  }

  // ── Signal 17: Finance-pitch score (v6.99.0) ─────────────────────────────
  // DELETES (Rule 14) since v6.100.0, after the Drive archive. Signals 14, 15 and 16 each test something the mill rotates (a
  // phrase, a brand domain, an address); 11 releases in 14 days patched one sighting at a
  // time. This scores the whole mail instead: the words and link hosts of a direct-response
  // pitch, weighted by a table trained on the spam and ham fixtures (scripts/train_bayes.py;
  // BAYES_TABLE in Patterns.gs), so a reworded or rebranded pitch still scores.
  //
  // WHAT WAS FOUND AND FIXED BEFORE THIS SHIPPED (two reviews, CHANGELOG v6.99.0): a first
  // signed table had learned length and boilerplate ("llc", "conditions", "could") and could
  // be pushed under the bar by appending ordinary words. The table now holds POSITIVE weights
  // only (padding cannot lower a score) and is trained with ten long realistic marketing
  // emails as ham. Measured: trained only on mail dated before 2026-10-23 it scores all six
  // misses since then 587 to 609 against 550; ten marketing emails it never saw (brokerage,
  // fundraiser, gold dealer, crypto digest, insurer, alumni appeal...) score 466 at most.
  // That 466 is NOT a margin: a final review wrote ten dense marketing mails knowing the table
  // and they scored 576 to 622, and ordinary long English sits near 400 to 500. The score still
  // rewards length plus marketing vocabulary, which is why the bar is 550 (the six misses are
  // 587 to 609) and why the sender must also have no history with you. Link hosts are tokens
  // too, but the current table holds none, so they add nothing today.
  //
  // Requires List-Unsubscribe (mass mail; a person writing to you has none). The "this sender
  // has no history with you" gate needs a Gmail search, so it lives in analyzeMessage(), not
  // here: this signal is pure and the Python mirror reproduces it exactly (numeric score
  // parity is asserted on every fixture). BAYES_RULE_ENABLED is the kill switch.
  // KNOWN WEAKNESS: a nonprofit newsletter on the same ESP scores 577 (leave-one-out) and
  // would be DELETED (archived to Drive first) if it carries the header and the sender is new to
  // you; recover it from the Raw Log row's Drive link. Known evasions: leave off List-Unsubscribe, or stop writing a pitch.
  try
  {
    if (BAYES_RULE_ENABLED && getRawHeader(rawContent, 'List-Unsubscribe') &&
        bayesScore(bayesTokens(subject, body, true)) >= BAYES_QUARANTINE_SCORE)
    {
      signals.pitchScore = true;
      logDebug('Finance-pitch score over the threshold');
    }
  }
  catch (signalError)
  {
    // Fail CLOSED for this signal only: it contributes nothing, the
    // rest still run, and signalsSkipped makes the gap visible.
    signalsSkipped++;
    logError('Signal 17 threw and was skipped: ' + signalError.toString());
  }

  // ── Signal 2: Clickbait / sensationalism patterns ───────────────────────
  // Each pattern targets a CATEGORY of spam tactic, not specific phrases.
  // Patterns are checked against both subject AND from field concatenated,
  // since spammers stuff clickbait into display names too.
  // Each matching pattern increments clickbaitCount independently.

  try
  {
    for (let i = 0; i < CLICKBAIT_PATTERNS.length; i++)
    {
      if (CLICKBAIT_PATTERNS[i].test(textToCheck))
      {
        signals.clickbaitCount++;
      }
    }
  }
  catch (signalError)
  {
    // Fail CLOSED for this signal only: it contributes nothing, the
    // rest still run, and signalsSkipped makes the gap visible.
    signalsSkipped++;
    logError('Signal 2 threw and was skipped: ' + signalError.toString());
  }

  // ── Signal 2b: Body crypto scam patterns ────────────────────────────────
  // High-confidence terms that almost never appear in legitimate email bodies.
  // Checked against body only — subject/from rarely contain these phrases.
  // Each match increments clickbaitCount independently (supports Rule 4).
  try
  {
    for (let i = 0; i < BODY_CRYPTO_PATTERNS.length; i++)
    {
      if (BODY_CRYPTO_PATTERNS[i].test(body))
      {
        signals.clickbaitCount++;
      }
    }
  }
  catch (signalError)
  {
    // Fail CLOSED for this signal only: it contributes nothing, the
    // rest still run, and signalsSkipped makes the gap visible.
    signalsSkipped++;
    logError('Signal 2b threw and was skipped: ' + signalError.toString());
  }

  // ── Signal 2c: Body fear patterns ───────────────────────────────────────
  // Phishing-specific fear phrases like "your access could be compromised".
  // FEAR_PATTERNS only check subject+from, missing scams that keep the subject
  // bland (e.g. "System Configuration Notice") and put fear in the body.
  // Each match increments clickbaitCount (same as BODY_CRYPTO_PATTERNS).
  try
  {
    for (let i = 0; i < BODY_FEAR_PATTERNS.length; i++)
    {
      if (BODY_FEAR_PATTERNS[i].test(body))
      {
        signals.clickbaitCount++;
      }
    }
  }
  catch (signalError)
  {
    // Fail CLOSED for this signal only: it contributes nothing, the
    // rest still run, and signalsSkipped makes the gap visible.
    signalsSkipped++;
    logError('Signal 2c threw and was skipped: ' + signalError.toString());
  }

  // ── Signal 2d: Unicode obfuscation in body ──────────────────────────────
  // Spammers hide obfuscated "click here" text inside HTML while keeping the
  // subject clean (e.g. body anchor contains "Сⅼіϲkhеrе" in Cyrillic).
  // Subject+from already checked in Signal 2 — this catches body-only evasion.
  // Break after first match: all four patterns detect the same technique, so
  // counting them independently would over-inflate clickbaitCount.
  try
  {
    for (let i = 0; i < BODY_UNICODE_PATTERNS.length; i++)
    {
      if (BODY_UNICODE_PATTERNS[i].test(body))
      {
        signals.clickbaitCount++;
        break;
      }
    }
  }
  catch (signalError)
  {
    // Fail CLOSED for this signal only: it contributes nothing, the
    // rest still run, and signalsSkipped makes the gap visible.
    signalsSkipped++;
    logError('Signal 2d threw and was skipped: ' + signalError.toString());
  }

  // ── Signal 2e: Reward-survey scam disclaimer in body ────────────────────
  // A brand-impersonating survey scam disclaims the brand in its footer. One
  // template, so +1 at most: break after the first match.
  try
  {
    for (let i = 0; i < BODY_SURVEY_SCAM_PATTERNS.length; i++)
    {
      if (BODY_SURVEY_SCAM_PATTERNS[i].test(body))
      {
        signals.clickbaitCount++;
        break;
      }
    }
  }
  catch (signalError)
  {
    // Fail CLOSED for this signal only: it contributes nothing, the
    // rest still run, and signalsSkipped makes the gap visible.
    signalsSkipped++;
    logError('Signal 2e threw and was skipped: ' + signalError.toString());
  }

  // ── Signal 2f: Forged sender headers ────────────────────────────────────
  // Three tells of a campaign's own tooling, +1 at most (one behaviour): a Date
  // header that is not a date (an unfilled template variable), a sender
  // domain generated with random capitalisation, or (v6.73.0) a random-case
  // Content-Transfer-Encoding token in any MIME part. Header-level, so they
  // survive the subject/body/landing-page rotation a campaign relies on.
  //
  // The encoding token: RFC 2045 allows 7bit/8bit/binary/quoted-printable/
  // base64 and x- extensions. "Content-Transfer-Encoding: AYKgrrCx0z" (the
  // 2026-10-06 "Storage 100% Full" phish) is a per-send random string, there
  // to confuse content scanners; no mail software writes one. Judged by
  // hasRandomCaseLabel(), not an allowlist of valid values — real senders do
  // write broken-but-innocent tokens ("utf-8", "7-bit"), and those must not
  // score.
  //
  // Only header blocks this message's own tooling wrote are read: the top
  // block, and a block opening right after a "--boundary" line. A forwarded
  // .eml, a bounce or quoted text carries another message's headers after a
  // part's blank line, and the user forwarding a phish to themselves must not
  // score (v6.73.0 security review). Mail from the recipient's own mailbox is
  // skipped for the same reason. Lines are split on \n only and tokens end at
  // [ \t;(] — never \s or the m flag, which JS and Python read differently.
  try
  {
    const dateHeader = getRawHeader(rawContent, 'Date');
    const fromDomainMatch = from.match(/@([A-Za-z0-9.-]+)[^@]*$/);
    let randomEncoding = false;
    const ownForEncoding = headerMailboxes(getRawHeader(rawContent, 'Delivered-To'))
      .concat(headerMailboxes(getRawHeader(rawContent, 'To')));
    if (ownForEncoding.indexOf(canonicalMailbox(senderAddress)) === -1)
    {
      const lines = String(rawContent || '').substring(0, LIMITS.maxRawScanChars)
        .replace(/\r\n/g, '\n').split('\n');
      const prefix = 'content-transfer-encoding:';
      let inHeaders = true;
      for (let i = 0; i < lines.length && !randomEncoding; i++)
      {
        const line = lines[i];
        if (line === '') { inHeaders = false; continue; }
        if (line.substring(0, 2) === '--') { inHeaders = true; continue; }
        if (inHeaders && line.substring(0, prefix.length).toLowerCase() === prefix)
        {
          const token = line.substring(prefix.length).replace(/^[ \t]+/, '').split(/[ \t;(]/)[0];
          randomEncoding = hasRandomCaseLabel(token);
        }
      }
    }
    if ((dateHeader !== null && !RFC5322_DATE_PATTERN.test(dateHeader)) ||
        (fromDomainMatch && hasRandomCaseLabel(fromDomainMatch[1])) ||
        randomEncoding)
    {
      signals.clickbaitCount++;
    }
  }
  catch (signalError)
  {
    // Fail CLOSED for this signal only: it contributes nothing, the
    // rest still run, and signalsSkipped makes the gap visible.
    signalsSkipped++;
    logError('Signal 2f threw and was skipped: ' + signalError.toString());
  }

  // ── Signal 2g: Recipient address used as a name ─────────────────────────
  // "geoff.c.freedman, Claim Your Free Medicare Kit". A list that holds only
  // the address greets with its local part; a sender who knows the person uses
  // a name. Matched against the recipient's OWN local part (from To:), never a
  // generic "dotted token," pattern — that matched "Node.js, Deno and Bun" and
  // "3.5, the new release". Min 5 chars so "info" / "me" cannot match prose.
  //
  // The FULL address is removed from the subject first: it is an address, not
  // the local part used as a name. Google Calendar appends it to every invite
  // ("Invitation: Board Onsite @ Sat Oct 19 (geoff.c.freedman@gmail.com)"), so
  // until v6.70.0 every calendar invite the user received — ~200 in the
  // mailbox — scored a weak spam point, one hit short of skipping the
  // Spam-folder grace period.
  //
  // v6.73.0 adds the same tell in the From DISPLAY NAME:
  //   From: geoff.c.freedman <alert-4419@plisc.ivz>
  // (the 2026-10-06 "Storage 100% Full" phish, which forged To: me@aol.com, so
  // the recipient is read from Delivered-To, the mailbox that received it).
  // Matched against Delivered-To ONLY, never every To address: the v6.73.0
  // review showed "jsmith <jsmith1987@yahoo.com>" writing to jsmith@work.com
  // (a webmail account with no name set) would otherwise score. To still
  // feeds the not-yourself guard. "@domain" and "+tag" are cut from the name
  // first, so "geoff.c.freedman@gmail.com" as a name is the same tell. The
  // WHOLE display name, dots removed, must equal the local part — never a
  // substring. A name with a space never matches: "Geoff C Freedman" is a
  // real name, Signal 10's business, and the user's own second account may
  // carry it. The sender must also not be one of the
  // recipient's own mailboxes (mail to yourself from an unnamed client). Still
  // +1 at most: one behaviour, whichever field carries it.
  try
  {
    const toHeader = getRawHeader(rawContent, 'To') || '';
    const toAddr = toHeader.match(/([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+)/);
    let addressAsName = false;
    if (toAddr && toAddr[1].length >= 5)
    {
      const local = toAddr[1].toLowerCase();
      const subjectSansAddress = subject.toLowerCase()
        .split(local + '@' + toAddr[2].toLowerCase()).join(' ');
      addressAsName = subjectSansAddress.indexOf(local) !== -1;
    }
    if (!addressAsName)
    {
      const lt = fromRaw.indexOf('<');
      const fromName = lt === -1 ? '' : fromRaw.substring(0, lt)
        .replace(/[\u00AD\u200B-\u200F\u2060\uFEFF"]/g, '')
        .replace(/^[ \t]+|[ \t]+$/g, '').toLowerCase()
        .split('@')[0].split('+')[0].split('.').join('');
      const delivered = headerMailboxes(getRawHeader(rawContent, 'Delivered-To'));
      const own = delivered.concat(headerMailboxes(toHeader));
      // The user's own second account ("geoff.c.freedman.work@gmail.com")
      // carries the name in its local part; the phish's alert-4419@ does not.
      const senderLocalFlat = senderAddress.substring(0, atIdx).split('.').join('');
      addressAsName = fromName.length >= 5 &&
        own.indexOf(canonicalMailbox(senderAddress)) === -1 &&
        senderLocalFlat.indexOf(fromName) === -1 &&
        delivered.some(function(m) {
          return m.substring(0, m.lastIndexOf('@')).replace(/\./g, '') === fromName;
        });
    }
    if (addressAsName)
    {
      signals.clickbaitCount++;
    }
  }
  catch (signalError)
  {
    // Fail CLOSED for this signal only: it contributes nothing, the
    // rest still run, and signalsSkipped makes the gap visible.
    signalsSkipped++;
    logError('Signal 2g threw and was skipped: ' + signalError.toString());
  }

  // ── Signal 3: Fear-mongering detection ──────────────────────────────────
  // Boolean signal — we only need to know if fear is present, not how many
  // patterns match. First match short-circuits the loop.
  try
  {
    for (let i = 0; i < FEAR_PATTERNS.length; i++)
    {
      if (FEAR_PATTERNS[i].test(textToCheck))
      {
        signals.fearMongering = true;
        logDebug('Fear-mongering detected (pattern match)');
        break; // Boolean signal — one match is enough
      }
    }
  }
  catch (signalError)
  {
    // Fail CLOSED for this signal only: it contributes nothing, the
    // rest still run, and signalsSkipped makes the gap visible.
    signalsSkipped++;
    logError('Signal 3 threw and was skipped: ' + signalError.toString());
  }

  // ── Signal 4: Marketing sender format ───────────────────────────────────
  // Checked against From field only (not subject). Detects spammy sender
  // name formatting like "Name | Org", spammy business names, and suspicious
  // email address patterns. Commas deliberately excluded — common in legit
  // org/place names. Bare pipe check removed — subsumed by /\|\s*[A-Z]/.
  try
  {
    for (let i = 0; i < MARKETING_PATTERNS.length; i++)
    {
      if (MARKETING_PATTERNS[i].test(from))
      {
        signals.marketingFormat = true;
        logDebug('Marketing sender format detected');
        break; // Boolean signal — one match is enough
      }
    }
  }
  catch (signalError)
  {
    // Fail CLOSED for this signal only: it contributes nothing, the
    // rest still run, and signalsSkipped makes the gap visible.
    signalsSkipped++;
    logError('Signal 4 threw and was skipped: ' + signalError.toString());
  }

  // ── Signal 5: Empty subject + attachment ────────────────────────────────
  // Payload delivery scams hide their content inside attached files (Excel,
  // PDF) and leave the subject and body empty to evade text-pattern rules.
  // Legitimate email virtually never combines an empty subject with an
  // attachment — this pair alone is sufficient to classify as spam.
  try
  {
    if (subject.trim() === '' && message.getAttachments().length > 0)
    {
      signals.emptySubjectWithAttachment = true;
      logDebug('Empty subject with attachment detected');
    }
  }
  catch (attachError)
  {
    // Non-fatal: skip this signal if attachment check fails (e.g., malformed
    // message). Counted like every other skip — this catch predates
    // signalsSkipped, and leaving it uncounted made a genuinely degraded
    // verdict report itself as complete.
    signalsSkipped++;
    logError('Could not check attachments — signal skipped: ' + attachError.toString());
  }

  // ── Signal 6: Service impersonation phishing ────────────────────────────
  // Cloud document-sharing notifications (Google Docs, OneDrive, Dropbox) are
  // ONLY ever sent by the actual service's own mail servers. A "Document shared
  // with you" email from ywammaui.org is 100% phishing — a compromised
  // legitimate account used as a delivery vector.
  try
  {
    const matchesServiceSubject = IMPERSONATION_SUBJECT_PATTERNS.some(function(p) {
      return p.test(subject);
    });
    if (matchesServiceSubject)
    {
      const senderLower = senderAddress.toLowerCase();
      const fromTrustedService = CLOUD_SERVICE_DOMAINS.some(function(d) {
        return senderLower.endsWith('@' + d) || senderLower.endsWith('.' + d);
      });
      if (!fromTrustedService)
      {
        signals.serviceImpersonation = true;
        logDebug('Service impersonation: cloud service subject from untrusted sender ' + sanitizeForLog(senderAddress));
      }
    }
  }
  catch (signalError)
  {
    // Fail CLOSED for this signal only: it contributes nothing, the
    // rest still run, and signalsSkipped makes the gap visible.
    signalsSkipped++;
    logError('Signal 6 threw and was skipped: ' + signalError.toString());
  }

  // ── Signal 8: Free-mail sender with a machine-generated local part ──────
  // Deliberately NOT part of any inbox rule on its own — plenty of real people
  // have digits in their address, and a false positive here would delete mail
  // from a person. It exists to CORROBORATE an existing spam verdict: in the
  // Spam folder, where Gmail has already judged the message, this signal alone
  // is enough — it is one of the STRONG signals in hasCorroboratingSignal().
  // See reviewGmailSpam().
  try
  {
    if (atIdx > 0)
    {
      const localPart   = senderAddress.substring(0, atIdx);
      const senderHost  = senderAddress.substring(atIdx + 1);
      const isFreeMail  = FREE_MAIL_DOMAINS.some(function(d) {
        return hostMatchesDomain(senderHost, d);
      });
      isThrowawayHost   = isFreeMail || THROWAWAY_TENANT_DOMAINS.some(function(d) {
        return hostMatchesDomain(senderHost, d);
      });

      if (isFreeMail && RANDOM_LOCAL_PART_PATTERNS.some(function(p) {
        return p.test(localPart);
      }))
      {
        signals.freeMailRandomLocal = true;
        logDebug('Free-mail sender with machine-generated local part: ' +
                 sanitizeForLog(senderAddress));
      }
    }
  }
  catch (signalError)
  {
    // Fail CLOSED for this signal only: it contributes nothing, the
    // rest still run, and signalsSkipped makes the gap visible.
    signalsSkipped++;
    logError('Signal 8 threw and was skipped: ' + signalError.toString());
  }

  // ── Signal 10: Free-mail (or throwaway tenant) sender using the recipient's own name
  //
  // Runs BEFORE Signal 9, which reads it.
  //
  //   From: Geoff C Freedman <allbashashaik170@gmail.com>
  //   To:   Geoff C Freedman <geoff.c.freedman@gmail.com>
  //
  // Both callback scams that got past us (Norton, 2026-09-17; "Google
  // Workspace", 2026-09-30) set the From display name to the recipient's own
  // name. It is a structural tell from the campaign's tooling: it costs them
  // nothing to keep and does not rotate with the brand they impersonate, which
  // is exactly what IMPERSONATED_SUPPORT_BRANDS failed to keep up with.
  //
  // Requirements, each closing an innocent reading:
  //   - free-mail or throwaway-tenant sender (isThrowawayHost): services that
  //     send you a copy of your own action ("Geoff C Freedman
  //     <noreply@forms.example>") use their own domain
  //   - the sender is not one of the recipient's mailboxes. Compared in
  //     Gmail's canonical form (dots, +tag, googlemail) against To, Cc and
  //     Delivered-To — the last is the account that received it, so the
  //     user's own address is excluded even when To names someone else. Two
  //     independent reviews of v6.68.0 caught the first draft comparing raw
  //     text: mail to yourself at a +receipts address fired.
  //   - two or more words of 2+ characters: "Geoff" from a different Geoff is
  //     a coincidence; "Geoff C Freedman" from a stranger's mailbox is not.
  //     This is ALSO what stops two absent names ('' === '') from matching:
  //     removing it made every bare-address message with no To: name fire.
  //   - no word of the name (3+ letters) appears in the sender's local part.
  //     The user's own second account is geoff@icloud.com or
  //     freedman.g@yahoo.com; the scams were allbashashaik170@ and raju47326yu@.
  //     A campaign that reads your name off your address could close this
  //     gap, but then the address is no longer a throwaway it can rotate.
  //
  // The residual false positive is the recipient's OWN second free-mail
  // account under the same name. So this convicts nothing in the inbox on its
  // own: it is a STRONG corroborator in the Spam folder (Gmail has already
  // judged the message), and it fills Signal 9's brand slot, where Rule 9
  // quarantines rather than deletes.
  //
  // Names come from the DECODED headers (getFrom/getTo), not the raw text: an
  // RFC 2047 encoded-word name ("=?utf-8?B?R2VvZmYg...?=") otherwise had no
  // spaces, never reached two words, and evaded this for one line of tooling.
  //
  // selfNamedLoose (v6.69.0) is the same test with the exact-name requirement
  // relaxed: every 2+ character word of the From name appears among the
  // recipient's name words OR the local-part words of the recipient's OWN
  // mailbox — Delivered-To, plus any To entry that is that mailbox
  // ("geoff.c.freedman@"). That reaches a To with no display name at all —
  // Bcc, undisclosed-recipients, a bare address — and "Geoff Freedman" with
  // the middle initial dropped. It is looser, so it feeds ONLY Signal 9's
  // brand slot, and a Signal 9 hit that rests on it alone is marked
  // _callbackLooseOnly so hasCorroboratingSignal() does not count it: inbox
  // quarantine, never Spam-folder deletion. (The first draft claimed this
  // without the marker; the review showed callbackPhishing is itself STRONG,
  // so the loose match reached deletion through it.) All the not-yourself
  // guards still apply.
  try
  {
    if (isThrowawayHost)
    {
      const fromName = headerDisplayName(fromRaw.replace(RFC2822_QUOTED_NAME, '$1$2'));
      const toHeader = sanitizeInput(message.getTo());
      const deliveredTo = getRawHeader(rawContent, 'Delivered-To');
      const nameWords = fromName.split(' ').filter(function(w) { return w.length >= 2; });
      const ownMailboxes = headerMailboxes(toHeader)
        .concat(headerMailboxes(getRawHeader(rawContent, 'Cc')))
        .concat(headerMailboxes(deliveredTo));
      const senderLocal = senderAddress.substring(0, atIdx);
      if (nameWords.length >= 2 &&
          ownMailboxes.indexOf(canonicalMailbox(senderAddress)) === -1 &&
          !nameWords.some(function(w) {
            return w.length >= 3 && senderLocal.indexOf(w) !== -1;
          }))
      {
        const toName = headerDisplayName(toHeader);
        if (fromName === toName)
        {
          signals.selfNamedSender = true;
          logDebug('Free-mail sender using the recipient\'s own name: ' +
                   sanitizeForLog(senderAddress));
        }
        // Local-part words from the RECIPIENT'S OWN mailbox only: Delivered-To
        // and any To entry that is the same mailbox. Taking every To entry let
        // "Mary Jones <mj.design@gmail.com>" cc'ing mary.jones@company.com match
        // herself (v6.69.0 review).
        const delivered = headerAddresses(deliveredTo);
        const deliveredCanon = delivered.map(canonicalMailbox);
        const ownTo = headerAddresses(toHeader).filter(function(a) {
          return deliveredCanon.indexOf(canonicalMailbox(a)) !== -1;
        });
        const recipientWords = toName.split(' ')
          .concat(localPartWords(delivered.concat(ownTo)));
        selfNamedLoose = signals.selfNamedSender || nameWords.every(function(w) {
          return recipientWords.indexOf(w) !== -1;
        });
      }
    }
  }
  catch (signalError)
  {
    // Fail CLOSED for this signal only: it contributes nothing, the
    // rest still run, and signalsSkipped makes the gap visible.
    signalsSkipped++;
    logError('Signal 10 threw and was skipped: ' + signalError.toString());
  }

  // ── Signal 9: Callback phishing (the payload is a phone number) ─────────
  //
  // Closes the class that got raju47326yu@gmail.com past every other signal.
  // That message was a fake Norton renewal notice: From display name set to the
  // recipient's own name, sender a throwaway gmail.com address, body a plausible
  // invoice ($145.91, a product key, a payment ID) and a support number to call.
  //
  // Nothing else could see it. It carried NO links at all, so Signal 7 had
  // nothing to compare; it was direct-send, so Rules 1-3 had no bulk
  // prerequisite; its subject is a flat statement, so no clickbait or fear
  // pattern fired. Only Signal 8 touched it, and Signal 8 deliberately cannot
  // convict alone. The scam works precisely BECAUSE it has no link to inspect —
  // the victim is moved to a phone call, where no email filter follows.
  //
  // So detect the anatomy rather than the wording. All four must hold:
  //   1. free-mail sender          — a real brand never bills from gmail.com
  //      (or a throwaway *.onmicrosoft.com tenant, v6.69.0)
  //   2. names an impersonated brand — claims to be someone it provably isn't
  //      OR uses the recipient's own name (Signal 10, loose form). The brand
  //      list alone missed the 2026-09-30 "Google Workspace" wave.
  //   3. billing language           — asserts money is moving
  //   4. a phone number             — the actual payload, matched after
  //      deobfuscatePhoneText() so "8OO", full-width digits and digit-by-digit
  //      spacing do not hide it (v6.69.0)
  //
  // A four-way conjunction because no single part is rare. Real people do send
  // invoices from Gmail, and real invoices carry phone numbers; it is the
  // combination with an impersonated brand that has no innocent reading.
  //
  // Quarantines rather than deletes (Rule 9 is absent from DESTRUCTIVE_RULES).
  // The residual false-positive class is a person forwarding a genuine Norton
  // receipt and adding a callback number, which is unlikely but not absurd —
  // and per the project's standing rule, a fuzzy signal gets a recoverable
  // disposition. In the Spam folder it still deletes, because it counts toward
  // hasCorroboratingSignal() where Gmail has already judged the message.
  try
  {
    if (isThrowawayHost)
    {
      const scanText = (subject + ' ' + body)
        .substring(0, LIMITS.maxRawScanChars)
        .toLowerCase();
      const phoneText = deobfuscatePhoneText(scanText);

      const impersonated = IMPERSONATED_SUPPORT_BRANDS.filter(function(b) {
        return scanText.indexOf(b) !== -1;
      });

      if ((impersonated.length > 0 || selfNamedLoose) &&
          (CALLBACK_PHONE_PATTERN.test(phoneText) || TOLL_FREE_DIGIT_RUN.test(phoneText)) &&
          BILLING_LANGUAGE_PATTERNS.some(function(p) { return p.test(scanText); }))
      {
        signals.callbackPhishing = true;
        // Meta: true when the ONLY impersonation evidence is the loose name
        // match. hasCorroboratingSignal() refuses to delete on that alone.
        signals._callbackLooseOnly = impersonated.length === 0 && !signals.selfNamedSender;
        logDebug('Callback phishing: free-mail sender invoicing as "' +
                 (impersonated[0] || 'the recipient') + '" with a phone number');
      }
    }
  }
  catch (signalError)
  {
    // Fail CLOSED for this signal only: it contributes nothing, the
    // rest still run, and signalsSkipped makes the gap visible.
    signalsSkipped++;
    logError('Signal 9 threw and was skipped: ' + signalError.toString());
  }

  // ── Signal 11: Voicemail lure in an unknown-sender calendar invite ──────
  //
  // "New Voice Message Notification Received", 2026-09-30: a REAL Google
  // Calendar invite sent from a compromised Workspace account
  // (lakeviewmillworks.com, valid SPF/DKIM), whose description said "A voice
  // message was recently recorded in your inbox. Listen to voicemail" — the
  // link wrapped by Calendar in google.com/url and pointing at the typosquat
  // strykertraiilers.com. Gmail spam-filed it; we scored it zero.
  //
  // Calendar invites are trusted by design: they land on the calendar and
  // carry a real sender. So detect the anatomy, all four required:
  //   1. a real invite        — a text/calendar MIME part
  //   2. an unknown organiser — Google's OWN subject marker, "Invitation from
  //      an unknown sender:", meaning the user has never interacted with them
  //   3. a message-waiting lure IN THE EVENT TITLE — CALENDAR_LURE_PATTERNS
  //      (voicemail, voice/audio message, fax) on the subject after the marker
  //   4. a payload            — a link whose real destination (after
  //      unwrapping google.com/url) is neither the sender's domain nor a
  //      CALENDAR_SAFE_LINK_DOMAINS host
  // A new contact inviting you to a meeting has 1 and 2 and a Zoom/Meet link;
  // it is the voicemail pretext plus a link to an unrelated site that has no
  // innocent reading. Rule 10 DELETES (the user's explicit call, 2026-10-04),
  // archived to Drive first like every delete; it is also a STRONG corroborator.
  //
  // The draft also accepted a PHONE NUMBER as the payload and matched the lure
  // anywhere in the body. Review showed both delete ordinary invites: every
  // Meet and Zoom invite carries dial-in numbers, and a recruiter writing "if
  // I miss you I'll leave a voicemail" is not a lure. Removed before shipping.
  try
  {
    // [\s\S] not '.': Python's mirror uses re.S, and '.' stops at a newline.
    // The text/calendar test is line-anchored so it means a MIME part header,
    // not those words anywhere in a body.
    const marker = subject.match(/^invitation from an unknown sender:([\s\S]*)$/i);
    if (marker &&
        /^content-type:[ \t]*text\/calendar/im.test(rawContent) &&
        CALENDAR_LURE_PATTERNS.some(function(p) { return p.test(marker[1]); }))
    {
      const senderHost = atIdx > 0 ? senderAddress.substring(atIdx + 1) : '';
      const offDomainLink = extractAnchors(rawHtml).some(function(a) {
        const host = extractUrlHost(unwrapGoogleRedirect(a.href));
        return host !== '' &&
          !(senderHost && hostMatchesDomain(host, senderHost)) &&
          !CALENDAR_SAFE_LINK_DOMAINS.some(function(d) { return hostMatchesDomain(host, d); });
      });
      if (offDomainLink)
      {
        signals.calendarLure = true;
        logDebug('Calendar voicemail lure from unknown organiser ' +
                 sanitizeForLog(senderAddress));
      }
    }
  }
  catch (signalError)
  {
    // Fail CLOSED for this signal only: it contributes nothing, the
    // rest still run, and signalsSkipped makes the gap visible.
    signalsSkipped++;
    logError('Signal 11 threw and was skipped: ' + signalError.toString());
  }

  // ── Signal 13: Attachment-payload note from free mail (advance-fee scam) ─
  // "CHARITY AND ORPHANAGE HOMES." from a free-mail account to someone else,
  // Bcc'ing us, with a .docx and a two-line ALL-CAPS body: "PLEASE SEE READ AND
  // VIEW THE ATTACHMENT FILE PROPOSAL". Nothing in it for any other signal:
  // no link, no brand, no number, no clickbait. The tells are structural.
  //
  // Every condition closes an innocent reading:
  //   - free-mail sender: the class is advance-fee mail, which does not use a
  //     domain of its own
  //   - an attachment: the attachment IS the payload
  //   - we are not in To or Cc (we were Bcc'd): compared in canonical form
  //     against Delivered-To, the mailbox that received it. With no
  //     Delivered-To there is no way to tell, so the signal does not fire.
  //   - a short plain body with no link: this is a note pointing at a file
  //   - at least 40 letters, 70%+ upper case: people do not write like this
  //     to a group they Bcc. A friend's "see attached" is lower case.
  //
  // CORROBORATION ONLY, a STRONG point in hasCorroboratingSignal(): not in
  // makeVerdict() or getRuleFromSignals(), so it can never delete from the
  // inbox. A shouted note from someone's own Gmail account is still a person,
  // and Gmail's Spam verdict is what licenses the deletion. Linear scans only;
  // the 1500-char cap is checked before any of them.
  try
  {
    if (atIdx > 0 &&
        FREE_MAIL_DOMAINS.some(function(d) {
          return hostMatchesDomain(senderAddress.substring(atIdx + 1), d);
        }) &&
        body.length <= LIMITS.attachmentNoteMaxChars &&
        body.toLowerCase().indexOf('http') === -1 &&
        body.toLowerCase().indexOf('www.') === -1)
    {
      const delivered = headerMailboxes(getRawHeader(rawContent, 'Delivered-To'));
      // getRawHeader() caps a value at 200 chars, so a Cc list that long can
      // hide us past the cut and the signal fires toward a false positive — the
      // accepted direction (see getRawHeader), and the reason this stays
      // corroboration-only.
      const named = headerMailboxes(sanitizeInput(message.getTo()))
        .concat(headerMailboxes(getRawHeader(rawContent, 'Cc')));
      let letters = 0, upper = 0;
      // for...of walks CODE POINTS. charAt() walked UTF-16 units, so a cased
      // astral letter (Deseret, Osage, Adlam) was two caseless surrogates here
      // and one letter in the Python mirror — a parity gap (v6.77.0 review).
      for (const ch of body)
      {
        if (ch.toLowerCase() !== ch.toUpperCase())
        {
          letters++;
          if (ch === ch.toUpperCase()) upper++;
        }
      }
      if (delivered.length > 0 &&
          !delivered.some(function(m) { return named.indexOf(m) !== -1; }) &&
          letters >= 40 && upper >= letters * 0.7 &&
          // Last: getAttachments() is the one expensive call, and every cheaper
          // gate above has already passed.
          message.getAttachments().length > 0)
      {
        signals.attachmentPayloadScam = true;
        logDebug('Bcc\'d ALL-CAPS free-mail note with an attachment: ' +
                 sanitizeForLog(senderAddress));
      }
    }
  }
  catch (signalError)
  {
    // Fail CLOSED for this signal only: it contributes nothing, the
    // rest still run, and signalsSkipped makes the gap visible.
    signalsSkipped++;
    logError('Signal 13 threw and was skipped: ' + signalError.toString());
  }

  // ── Signal 7: Brand-mismatched call-to-action ───────────────────────────
  // A button reading "VIEW IN DOCUSIGN" whose href is not DocuSign borrows
  // trust the sender has not earned. This is the only signal that inspects the
  // LINK GRAPH rather than sender-side vocabulary, which is why it reaches a
  // class of phishing that carries no clickbait, no urgency, no Unicode
  // obfuscation and a valid DKIM signature for its own domain.
  //
  // Wrapped in its own try/catch, exactly as Signal 5 is. analyzeMessage()'s
  // catch-all returns {isSpam:false, signals:null}, so an uncaught throw from
  // the anchor scan would discard EVERY other signal on the message and
  // silently mark it not-spam. Degrade one signal, never the whole verdict.
  try
  {
    // rawHtml, not the sanitizeInput()-truncated `html`. sanitizeInput caps at
    // LIMITS.maxInputChars (100 000), which made LIMITS.maxHtmlScanChars
    // (262 144) unreachable dead config AND hid any CTA past 100KB - real
    // marketing HTML with inlined CSS and base64 images routinely exceeds it.
    // extractAnchors() is independently bounded, which is precisely why it is
    // safe to hand it the untruncated body. Measured worst case ~9ms.
    if (hasBrandMismatchedCta(rawHtml, senderAddress))
    {
      signals.brandMismatchedCta = true;
    }
  }
  catch (ctaError)
  {
    signalsSkipped++;
    logError('Brand-CTA scan failed — signal skipped: ' + ctaError.toString());
  }

  // Meta, not a detection signal — hence the underscore, which the parity
  // bridge filters out. True when at least one signal threw, meaning a
  // "not spam" verdict here was reached with less evidence than intended and
  // must not be treated as a clean bill of health. See processThread().
  signals._degraded = signalsSkipped > 0;
  // Meta, set by Signal 9 when its hit rests only on the loose name match.
  // Defaulted here so it is always present, like _degraded.
  if (signals._callbackLooseOnly !== true) signals._callbackLooseOnly = false;

  return signals;
}

/**
 * Signal 16 (c), v6.102.0: the paid-promo credit in a mill email, or ''.
 *
 * `authored` is the folded text Signal 16 builds: lower-case, letters, digits and single
 * spaces, padded with one space at each end. Fires only when it carries " sponsored content "
 * AND two DISTINCT MILL_PROMO_PUBLISHERS, and no publisher (spaces removed) appears in the
 * folded From line: a publisher mailing its own list is never convicted by its own name.
 * Mirrored by _mill_promo_credit() in tests/test_spam_detector.py.
 *
 * @param {string} authored - Folded sender-authored text, space-padded.
 * @param {string} from - The From header (display name and address).
 * @return {string} "a + b" for the two publishers that convicted, or ''.
 */
function millPromoCredit(authored, from)
{
  if (authored.indexOf(' sponsored content ') === -1) return '';
  const fromKey = normalizeAdText(String(from || '')).replace(/[^a-z0-9]/g, '');
  const found = [];
  for (let i = 0; i < MILL_PROMO_PUBLISHERS.length; i++)
  {
    if (fromKey.indexOf(MILL_PROMO_PUBLISHERS[i].replace(/ /g, '')) !== -1) return '';
    if (authored.indexOf(' ' + MILL_PROMO_PUBLISHERS[i] + ' ') !== -1) found.push(MILL_PROMO_PUBLISHERS[i]);
  }
  return found.length >= 2 ? found[0] + ' + ' + found[1] : '';
}
