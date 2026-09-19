/**
 * Debug.gs — Manual diagnostic: why was this message flagged?
 *
 * Run debugWhyFlagged('search query') from the editor. Prints every signal by
 * ITERATING the returned object — the list was hand-maintained twice and drifted
 * twice, most recently omitting callbackPhishing so Rule 9 verdicts printed
 * SPAM with every listed signal false.
 *
 * Not on the delete path; this tool only reads.
 *
 * Apps Script concatenates every .gs file in sources.json into ONE global
 * scope. These are not modules: nothing is imported, and every function here
 * is a global visible to all other files.
 */

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
 * @param {string} searchTerm - Gmail search query selecting the message to
 *   explain, e.g. 'subject:invoice'. Only the first match is examined.
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
      // ITERATED, never hand-listed.
      //
      // This list was maintained by hand and drifted TWICE. serviceImpersonation
      // went missing from v6.38.0 — a Rule 6 phishing verdict printed "SPAM"
      // with every listed signal false, in the one tool whose entire job is
      // explaining why something was flagged. A comment was added saying so, and
      // then callbackPhishing was added to collectSignals() and never added
      // here, so Rule 9 verdicts printed exactly the same way.
      //
      // Object.keys() cannot drift. A new signal shows up the moment
      // collectSignals() returns it, with no second edit to forget. Meta keys
      // are `_`-prefixed and listed separately: _degraded is worth seeing in a
      // debug dump but is not a detection signal.
      logInfo('Signals:');
      Object.keys(signals).sort().forEach(function(key)
      {
        if (key.charAt(0) !== '_') logInfo('  ' + key + '=' + signals[key]);
      });
      Object.keys(signals).sort().forEach(function(key)
      {
        if (key.charAt(0) === '_') logInfo('  [meta] ' + key + '=' + signals[key]);
      });
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
