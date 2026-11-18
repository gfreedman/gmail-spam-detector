/**
 * Verdict.gs — The twelve rules, and the analyze entry point.
 *
 * makeVerdict() evaluates the rules in priority order, first match wins, and
 * returns a boolean. analyzeMessage() wraps collectSignals() + makeVerdict() and
 * is the catch-all: anything thrown below it returns unevaluated:'error' so the
 * message is retried rather than silently marked clean.
 *
 * NOTE: the same twelve rules are implemented a second time as
 * getRuleFromSignals() in Flush.gs, which is what the destroy-vs-quarantine
 * decision actually reads. The two are pinned to each other by an exhaustive
 * 327,680-combination test in tests/test_disposition.js.
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

  // Rule 10: Voicemail lure in an unknown-sender calendar invite (v6.71.0).
  // DELETES — see Signal 11 for the four required conditions.
  if (signals.calendarLure)
  {
    logInfo('PHISHING DETECTED: Calendar invite from an unknown organiser with ' +
            'a voicemail/fax lure in the title and an off-domain link');
    return true;
  }

  // Rule 11: Sponsored-ad template (v6.81.0; v6.79.0-6.80.0 shipped a sender-
  // structure version of this rule that never fired on the real mail). DELETES,
  // at the user's explicit call. See Signal 14 for the conditions. No bulk
  // prerequisite: the sending domain is the ESP's, and Cyberimpact is not a
  // bulk fingerprint on purpose (it would expose every legitimate sender on
  // that ESP to Rules 1-3). The Drive archive gate in
  // disposeDetectedMessage() still applies.
  if (signals.sponsoredAdTemplate)
  {
    logInfo('SPAM DETECTED: Sponsored-ad template (ad disclaimer + sponsor block + credit lines)');
    return true;
  }

  // Rule 12: a blacklisted brand domain behind an ESP relay (v6.86.0). DELETES,
  // like Rule 1 (the other blacklist rule), behind the Drive-archive gate. The
  // relay shape stands in for Rule 1's bulk prerequisite. See Signal 15.
  if (signals.blacklistedRelayIdentity)
  {
    logInfo('SPAM DETECTED: blacklisted brand domain behind an ESP relay (Reply-To)');
    return true;
  }

  // Rule 13: a known mill footer address on bulk-marked mail (v6.98.0). DELETES since
  // v6.100.0 (in DESTRUCTIVE_RULES, behind the Drive-archive gate; v6.98.0 and v6.99.0 shipped
  // it as a quarantine). A legitimate tenant of the same building could print the same
  // address, so the Drive copy and the Raw Log row are the recovery path. See Signal 16.
  if (signals.millFooterAddress)
  {
    logInfo('SPAM DETECTED: known mill footprint (footer address, operator name or Sponsored Content publisher credit)');
    return true;
  }

  // Rule 14: a finance-pitch score over the threshold on List-Unsubscribe mail (v6.99.0).
  // DELETES since v6.100.0 (in DESTRUCTIVE_RULES, behind the Drive-archive gate). analyzeMessage()
  // additionally demands that the sender has NO history with the user; makeVerdict() stays
  // pure so the exhaustive sweep and the Python mirror can pin it. See Signal 17.
  if (signals.pitchScore)
  {
    logInfo('SPAM DETECTED: finance-pitch score over the threshold on bulk mail');
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
           ', callbackPhishing=' + signals.callbackPhishing +
           ', selfNamedSender=' + signals.selfNamedSender +
           ', calendarLure=' + signals.calendarLure +
           ', headlineFromName=' + signals.headlineFromName +
           ', attachmentPayloadScam=' + signals.attachmentPayloadScam +
           ', sponsoredAdTemplate=' + signals.sponsoredAdTemplate +
           ', blacklistedRelayIdentity=' + signals.blacklistedRelayIdentity +
           ', millFooterAddress=' + signals.millFooterAddress +
           ', pitchScore=' + signals.pitchScore);
  return false;
}

/**
 * Does the user have a history with this message's exact sender ADDRESS? true / false / null.
 *
 * The gate for Rules 13 and 14 (L5 review: a deleting rule needs it), shared by analyzeMessage() and the Gmail-Spam-folder review (which reads
 * signals directly and would otherwise bypass it: an L5 review found Rule 14 deleting
 * Gmail-misfiled mail from a known sender in the same run). Only exactly `false` ("no
 * history") lets Rule 14 convict or delete. The address is allowlisted before it reaches a
 * Gmail query: anything with a space or an operator character is "cannot establish" (null).
 *
 * @param {GmailMessage} message
 * @return {?boolean} false = no history; true = history; null = unknown (budget spent, odd address).
 */
function senderHistoryGate(message)
{
  // Keyed on the exact ADDRESS, not the domain. A mill sends as
  // "<name>.<brand>@email.cyberimpact.com": its domain is a shared ESP's, and the user
  // has very likely read some other tenant's mail from it, which would make every
  // mill on that ESP a "known sender" and switch this rule off for them.
  const from = message.getFrom() || '';
  const fromAddr = extractEmailAddress(from).toLowerCase();
  if (!/^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$/.test(fromAddr)) return null;
  const byAddress = senderHasHistory(fromAddr);
  if (byAddress !== false) return byAddress;
  return senderHasNamedDomainHistory(fromAddr, headerDisplayName(from), message.getId());
}

/**
 * v6.103.0: has the user READ mail from this exact domain under this exact display name?
 * true / false / null (lookup budget spent).
 *
 * Why: on 2026-11-18 Rule 14 deleted "The BetaKit Newsletter" (score 601, ordinary tech-news
 * words). The user reads and labels BetaKit's issues from newsletter@betakit.com; this one
 * came from alex.riehl@betakit.com, an address the exact-address gate had never seen. A real
 * publisher changing its From address lost its whole history.
 *
 * Why not the domain alone: a mill sends as "<name>.<brand>@email.cyberimpact.com", and the
 * user has very likely read another tenant's mail from that shared ESP domain. Requiring the
 * SAME normalised display name as well keeps that tenant's history its own: the mill would have
 * to borrow the display name of a sender the user already reads on that same domain.
 *
 * Known weakness, accepted: a mill that keeps one display name while rotating addresses is
 * spared from the moment the user has READ one of its mails more than 2 days old that the
 * script neither deleted nor labelled (historyExcludedLabels(): held, quarantined, purged,
 * reported missed). Known limit: only the 20 newest matching threads are read, so on a busy
 * domain an older read issue under the same name is not found (the mail is then judged as before).
 *
 * Every candidate is re-checked in code, not trusted to Gmail's fuzzy from: match: the host
 * must equal this domain exactly, the display name must normalise identically, and the message
 * itself must be read and older than 2 days.
 *
 * @param {string} fromAddr - Allowlisted, lower-case sender address.
 * @param {string} name     - headerDisplayName() of the From header.
 * @param {string} selfId   - The message being judged: never its own history.
 * @return {?boolean}
 */
function senderHasNamedDomainHistory(fromAddr, name, selfId)
{
  const domain = fromAddr.substring(fromAddr.lastIndexOf('@') + 1);
  if (!name || name.length < 3) return false;              // nothing to match on: the address answer stands

  const props = PropertiesService.getScriptProperties();
  const key   = historyCacheKey('@' + domain + '|' + name); // '@' forces the hashed (address) key form
  const now   = Date.now();
  const cached = props.getProperty(key);
  if (cached)
  {
    const parts = cached.split(':');
    if (now - Number(parts[1]) < 3 * 24 * 3600 * 1000) return parts[0] === 'Y';
  }
  if (shadowHistoryLookups >= SHADOW_HISTORY_BUDGET) return null;
  shadowHistoryLookups++;

  const cutoff  = now - 2 * 24 * 3600 * 1000;
  const threads = GmailApp.search('from:' + domain + ' older_than:2d is:read' + historyLabelExclusions() +
                                  ' -in:spam -in:trash', 0, 20);
  const excluded = historyExcludedLabels();
  let known = false;
  if (threads.length > 0)
  {
    const all = GmailApp.getMessagesForThreads(threads);
    for (let i = 0; i < all.length && !known; i++)
    {
      for (let j = 0; j < all[i].length && !known; j++)
      {
        const m = all[i][j];
        const f = m.getFrom() || '';
        const a = extractEmailAddress(f).toLowerCase();
        if (a.substring(a.lastIndexOf('@') + 1) !== domain) continue;
        if (headerDisplayName(f) !== name) continue;
        if (m.getId() === selfId || m.isUnread()) continue;
        if (m.getDate().getTime() > cutoff) continue;
        // Re-checked in code, not trusted to the query: a thread the script held or quarantined
        // never vouches for anyone. One getLabels() call, only for a candidate that matched.
        const held = threads[i].getLabels().some(function(l) { return excluded.indexOf(l.getName()) !== -1; });
        if (held) continue;
        known = true;
      }
    }
  }
  props.setProperty(key, (known ? 'Y' : 'N') + ':' + now);
  return known;
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
    let isSpam = makeVerdict(signals);
    let unknownHistory = false;

    // Rules 13 (mill footer address) and 14 (finance-pitch score) convict only a sender the user has no history with:
    // not mailed, not read, not already a regular. Done HERE, the one choke point every
    // path goes through (live, cleanse, recheck, held-mail), because it needs a Gmail
    // search that a pure signal cannot make. Only an answer of exactly "no history"
    // convicts: "has history" or "unknown" (lookup budget spent) leaves the mail alone.
    const gatedRule = isSpam ? getRuleFromSignals(signals).rule : '';
    if (gatedRule === 'Rule 13' || gatedRule === 'Rule 14')
    {
      // Keyed on the exact ADDRESS, not the domain. A mill sends as
      // "<name>.<brand>@email.cyberimpact.com": its domain is a shared ESP's, and the user
      // has very likely read some other tenant's mail from it, which would make every
      // mill on that ESP a "known sender" and switch this rule off for them.
      const history = senderHistoryGate(message);
      if (history !== false)
      {
        logInfo(gatedRule + ' skipped (' + (history === true ? 'sender has history' : 'history unknown') + '): ' + sanitizeForLog(extractEmailAddress(message.getFrom() || '').toLowerCase()));
        isSpam = false;
        // UNKNOWN (lookup budget spent, or an address we will not query) is not a clean
        // verdict: reported as unevaluated so processInbox() retries it once instead of
        // stamping it SpamChecked for good (L5 review: a mill could spend the shared budget).
        if (history === null) unknownHistory = true;
      }
    }

    // A clean verdict reached with a signal missing is not a clean verdict.
    // Spam is still acted on — missing signals can only cause a MISS, never a
    // false positive — but "not spam" from a degraded run is reported as
    // unevaluated so it gets retried rather than permanently exempted.
    const unevaluated = (!isSpam && (signals._degraded || unknownHistory)) ? 'error' : false;
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
