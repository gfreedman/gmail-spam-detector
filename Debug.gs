

// =============================================================================
// Debug Tools
// =============================================================================

/**
 * Debug tool — analyze why a specific email was flagged (or not flagged).
 *
 * Searches for an email matching the given term, then prints all detection
 * signals to the log. Useful for investigating false positives or missed spam.
 *
 * Run from the Apps Script editor with a search term:
 *   debugWhyFlagged('from:linkedin')
 *   debugWhyFlagged('subject:your order')
 *
 * @param {string} [searchTerm='from:linkedin'] - Gmail search query to find the email.
 */
function debugWhyFlagged(searchTerm)
{
  try
  {
    const search = searchTerm || 'from:linkedin';
    const threads = GmailApp.search(search, 0, 1);

    if (threads.length === 0)
    {
      logInfo('No email found for: ' + search);
      return;
    }

    const message = threads[0].getMessages()[0];

    logInfo('=== DEBUG: WHY FLAGGED? ===');
    logInfo('Subject: ' + message.getSubject());
    logInfo('From: ' + message.getFrom());
    logInfo('');

    // Run the real production signal collection — guaranteed to match runtime behavior
    const signals = collectSignals(message);

    if (signals === null)
    {
      logInfo('✓ WHITELISTED — detection skipped entirely');
    }
    else
    {
      logInfo('Signals:');
      logInfo('  bulk=' + signals.bulkEmailService);
      logInfo('  blacklist=' + signals.blacklistedSender);
      logInfo('  clickbait=' + signals.clickbaitCount);
      logInfo('  fear=' + signals.fearMongering);
      logInfo('  marketing=' + signals.marketingFormat);
      logInfo('  suspiciousFrom=' + signals.suspiciousFromName);
      logInfo('  emptySubjectAttachment=' + signals.emptySubjectWithAttachment);
      // serviceImpersonation was missing since v6.38.0 — a Rule 6 phishing
      // verdict printed "SPAM" with every listed signal false, in the one tool
      // whose entire job is explaining why something was flagged.
      logInfo('  serviceImpersonation=' + signals.serviceImpersonation);
      logInfo('  brandMismatchedCta=' + signals.brandMismatchedCta);
      logInfo('  freeMailRandomLocal=' + signals.freeMailRandomLocal);
      logInfo('');
      logInfo('Verdict: ' + (makeVerdict(signals) ? 'SPAM' : 'not spam'));
    }

    logInfo('=== END DEBUG ===');
  }
  catch (error)
  {
    logError('Debug failed: ' + error.toString());
  }
}
