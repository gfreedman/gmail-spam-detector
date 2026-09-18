/**
 * Signals.gs — Signal collection: the whitelist gate, field extraction, 11 detections.
 *
 * ONE function, deliberately long. Fourteen try/catch blocks write eleven signal
 * keys (four of them accumulate into clickbaitCount), and every block is wrapped
 * individually because a single throw used to discard eight of eleven signals.
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

  // getBody() returns the decoded, charset-normalized HTML. It is NOT an extra
  // API round trip: shouldProcessMessage() already calls it on every message
  // for the size check, so the GmailMessage has it cached. Only
  // getRawContent() costs a separate fetch (format=raw vs format=full).
  const rawHtml = message.getBody();
  const html = sanitizeInput(rawHtml);

  // Truncate BEFORE stripping, not after. Previously sanitizeInput() wrapped
  // the *result* of stripHtmlTags(), so the two regex passes ran across up to
  // 5 MB (the shouldProcessMessage ceiling) and allocated two 5 MB
  // intermediates on every HTML-only message.
  // .trim() matters: a text/plain part containing a single space is truthy,
  // so the HTML fallback never ran and Signals 2b/2c/2d all saw an empty
  // body. One space in the plain part disabled every body-based signal.
  const body = sanitizeInput(plainBody).trim() || stripHtmlTags(html);
  const rawContent = message.getRawContent(); // Full RFC 822 content (includes all headers)

  // ── Values shared across signal blocks ──────────────────────────────────
  // Declared here, not inside the block that first needs them, because each
  // signal below is individually wrapped in try/catch — and a `const` declared
  // inside a try is not visible to the next block. Anything two signals share
  // has to outlive both.
  const textToCheck = subject + ' ' + from;   // Signals 2 and 3
  const atIdx       = senderAddress.lastIndexOf('@');
  let   isFreeMail  = false;                  // set by Signal 8, read by Signal 9

  // Counts signals that threw and were skipped. A verdict reached with fewer
  // signals than intended is not a trustworthy "clean" — see _degraded below.
  let signalsSkipped = 0;

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
    callbackPhishing: false            // fake brand invoice from free mail, payload is a phone number
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
    const fromDisplayName = from.replace(/<[^>]*>$/, '').trim(); // quotes already stripped above
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
  // Spam folder, where Gmail has already judged the message, one independent
  // signal is enough. See reviewGmailSpam().
  try
  {
    if (atIdx > 0)
    {
      const localPart   = senderAddress.substring(0, atIdx);
      const senderHost  = senderAddress.substring(atIdx + 1);
      isFreeMail        = FREE_MAIL_DOMAINS.some(function(d) {
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
  //   2. names an impersonated brand — claims to be someone it provably isn't
  //   3. billing language           — asserts money is moving
  //   4. a phone number             — the actual payload
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
    if (isFreeMail)
    {
      const scanText = (subject + ' ' + body)
        .substring(0, LIMITS.maxRawScanChars)
        .toLowerCase();

      const impersonated = IMPERSONATED_SUPPORT_BRANDS.filter(function(b) {
        return scanText.indexOf(b) !== -1;
      });

      if (impersonated.length > 0 &&
          CALLBACK_PHONE_PATTERN.test(scanText) &&
          BILLING_LANGUAGE_PATTERNS.some(function(p) { return p.test(scanText); }))
      {
        signals.callbackPhishing = true;
        logDebug('Callback phishing: free-mail sender invoicing as "' +
                 impersonated[0] + '" with a phone number');
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

  return signals;
}
