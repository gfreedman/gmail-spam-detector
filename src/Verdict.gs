/**
 * Verdict.gs — The nine rules, and the analyze entry point.
 *
 * makeVerdict() evaluates the rules in priority order, first match wins, and
 * returns a boolean. analyzeMessage() wraps collectSignals() + makeVerdict() and
 * is the catch-all: anything thrown below it returns unevaluated:'error' so the
 * message is retried rather than silently marked clean.
 *
 * NOTE: the same nine rules are implemented a second time as
 * getRuleFromSignals() in Flush.gs, which is what the destroy-vs-quarantine
 * decision actually reads. The two are pinned to each other by an exhaustive
 * 5,120-combination test in tests/test_disposition.js.
 *
 * Apps Script concatenates every .gs file in sources.json into ONE global
 * scope. These are not modules: nothing is imported, and every function here
 * is a global visible to all other files.
 */

/**
 * Apply the 7-rule decision cascade to a collected signals object.
 *
 * Rules are evaluated in priority order. The first rule that fires wins —
 * later rules are not evaluated. Returns immediately on the first match.
 *
 * @param {Object} signals - Signal object returned by collectSignals().
 * @return {boolean} true if the email is spam, false if it is not.
 */
function makeVerdict(signals)
{
  // Rule 1: Bulk email + blacklisted sender = definitive spam
  // Rationale: Known spam domain + bulk infrastructure = zero false positive risk
  if (signals.bulkEmailService && signals.blacklistedSender)
  {
    logInfo('SPAM DETECTED: Bulk email + blacklisted sender');
    return true;
  }

  // Rule 2: Bulk email + 2+ clickbait patterns = spam
  // Rationale: Legitimate bulk senders rarely use multiple clickbait tactics
  if (signals.bulkEmailService && signals.clickbaitCount >= 2)
  {
    logInfo('SPAM DETECTED: Bulk email + clickbait (' + signals.clickbaitCount + ' patterns)');
    return true;
  }

  // Rule 3: Bulk email + 2+ distinct spam behaviors = spam
  // "Distinct behaviors" are: any clickbait, fear-mongering, marketing format,
  // or suspicious From name — four INDEPENDENT signals that each detect a
  // different aspect of spam. Finding 2+ of them is strong evidence because
  // it's very unlikely that two unrelated spam indicators both fire on a
  // legitimate email by coincidence.
  let spamBehaviorCount = 0;
  if (signals.clickbaitCount >= 1) spamBehaviorCount++;
  if (signals.fearMongering) spamBehaviorCount++;
  if (signals.marketingFormat) spamBehaviorCount++;
  if (signals.suspiciousFromName) spamBehaviorCount++;

  if (signals.bulkEmailService && spamBehaviorCount >= 2)
  {
    logInfo('SPAM DETECTED: Bulk email + ' + spamBehaviorCount + ' spam behaviors');
    return true;
  }

  // Rule 4: Extreme clickbait alone (no bulk email required)
  // Rationale: 3+ clickbait hits is so anomalous that even non-bulk senders
  // are almost certainly spam (catches direct-send spam)
  if (signals.clickbaitCount >= 3)
  {
    logInfo('SPAM DETECTED: Extreme clickbait (' + signals.clickbaitCount + ' patterns)');
    return true;
  }

  // Rule 5: Empty subject + attachment = payload delivery scam
  // Rationale: Legitimate email virtually never has both an empty subject
  // and an attachment. This pattern is the fingerprint of file-based scams
  // that hide phishing links or malware inside Excel/PDF attachments to
  // bypass text-pattern detection entirely.
  if (signals.emptySubjectWithAttachment)
  {
    logInfo('SPAM DETECTED: Empty subject with attachment (payload delivery scam)');
    return true;
  }

  // Rule 6: Service impersonation phishing (no bulk email required)
  // Rationale: Phishing campaigns impersonating Google Docs/Drive, OneDrive, or
  // Dropbox are delivered via compromised legitimate accounts — not bulk
  // infrastructure. The subject template alone is definitive: a real cloud
  // service ALWAYS sends notifications from its own domain.
  if (signals.serviceImpersonation)
  {
    logInfo('SPAM DETECTED: Service impersonation phishing (cloud service subject from non-service sender)');
    return true;
  }

  // Rule 7: Brand-mismatched CTA phishing (no bulk email required)
  // Rationale: a call-to-action naming DocuSign/Adobe Sign/SharePoint that
  // resolves to a host the brand does not control has no legitimate form. The
  // signal already abstains on click-trackers, link-wrappers and
  // sender-aligned hosts, so what reaches here is an unexplained brand
  // mismatch. Deliberately NOT gated on bulk email: this class also arrives
  // via compromised legitimate accounts, the same reasoning Rule 6 accepted.
  if (signals.brandMismatchedCta)
  {
    logInfo('SPAM DETECTED: Brand-mismatched CTA phishing (link text names a document brand the destination does not control)');
    return true;
  }

  // Rule 8: Free-mail machine-generated sender + 2+ spam behaviors (no bulk)
  // Rationale: Rules 1-3 all require bulk infrastructure, so a direct-send
  // 419/advance-fee scam from a throwaway free-mail account slipped through
  // entirely — it is not bulk-routed, and gmail.com cannot be blacklisted
  // without distrusting every real person who uses it.
  //
  // freeMailRandomLocal is the gate, and it is a narrow one: a consumer
  // free-mail domain AND a local part no human would choose. It fires on 0 of
  // the 22 ham examples and cannot fire at all for a sender on their own
  // domain. Requiring two further independent behaviours on top means a real
  // person would need a machine-shaped address AND two clickbait/fear hits.
  if (signals.freeMailRandomLocal && spamBehaviorCount >= 2)
  {
    logInfo('SPAM DETECTED: Free-mail machine-generated sender + ' +
            spamBehaviorCount + ' spam behaviors');
    return true;
  }

  // Rule 9: Callback phishing — fake brand invoice from free mail with a
  // phone-number payload. No bulk prerequisite and no link required, which is
  // the whole point: this class carries neither. See Signal 9 for why all four
  // of its conditions are required together.
  if (signals.callbackPhishing)
  {
    logInfo('PHISHING DETECTED: Callback scam (free-mail sender invoicing as a ' +
            'brand it is not, with a phone number to call)');
    return true;
  }

  // No rule triggered — email is not spam
  logDebug('Not spam - signals: bulk=' + signals.bulkEmailService +
           ', blacklist=' + signals.blacklistedSender +
           ', clickbait=' + signals.clickbaitCount +
           ', fear=' + signals.fearMongering +
           ', marketing=' + signals.marketingFormat +
           ', suspiciousFrom=' + signals.suspiciousFromName +
           ', emptySubjectAttachment=' + signals.emptySubjectWithAttachment +
           ', serviceImpersonation=' + signals.serviceImpersonation +
           ', brandMismatchedCta=' + signals.brandMismatchedCta +
           ', freeMailRandomLocal=' + signals.freeMailRandomLocal +
           ', callbackPhishing=' + signals.callbackPhishing);
  return false;
}

/**
 * Analyze a message and return whether it is spam.
 *
 * Thin orchestrator: delegates signal collection to collectSignals() and
 * verdict logic to makeVerdict(). Whitelisted senders short-circuit to
 * false before any signal collection occurs.
 *
 * @param {GmailMessage} message - The Gmail message to analyze.
 * @return {Object} {isSpam: boolean, signals: Object|null}. `signals` is null
 *                  when the sender is whitelisted or signal collection threw.
 */
function analyzeMessage(message)
{
  try
  {
    const signals = collectSignals(message);
    if (signals === null) return { isSpam: false, signals: null }; // whitelisted
    const isSpam = makeVerdict(signals);

    // A clean verdict reached with a signal missing is not a clean verdict.
    // Spam is still acted on — missing signals can only cause a MISS, never a
    // false positive — but "not spam" from a degraded run is reported as
    // unevaluated so it gets retried rather than permanently exempted.
    const unevaluated = (!isSpam && signals._degraded) ? 'error' : false;
    return { isSpam: isSpam, signals: signals, unevaluated: unevaluated };
  }
  catch (error)
  {
    // `unevaluated` is the important half of this return.
    //
    // Returning {isSpam:false} alone made a throw indistinguishable from a
    // genuine clean verdict, and processInbox() then stamped SpamChecked, so
    // the message was never looked at again. Malformed MIME that makes
    // getRawContent() throw was therefore a PERMANENT detector exemption an
    // attacker could trigger on purpose.
    //
    // The verdict stays not-spam — never destroy mail on an error — but the
    // caller now knows the message was not actually judged.
    logError('Error analyzing message: ' + error.toString());
    return { isSpam: false, signals: null, unevaluated: 'error' };
  }
}
