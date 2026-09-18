/**
 * Log.gs — Logging primitives and the run heartbeat.
 *
 * logDebug() is suppressed in production. Use logInfo() for anything that
 * matters to diagnosing whether the script did work — a silent skip looks
 * identical to a silent crash.
 *
 * logRunHeartbeat() is called from processInbox()'s finally, so a run that
 * throws still reports.
 *
 * Apps Script concatenates every .gs file in sources.json into ONE global
 * scope. These are not modules: nothing is imported, and every function here
 * is a global visible to all other files.
 */

// =============================================================================
// Logging
// =============================================================================

/**
 * Log an informational message (always visible in Apps Script logs).
 *
 * @param {string} message - Message to log.
 */
function logInfo(message)
{
  Logger.log('[INFO] ' + message);
}

/**
 * Log a debug message (only visible when CONFIG.debug is true).
 *
 * Used for per-email signal details during troubleshooting.
 * Disabled in production to reduce log noise.
 *
 * @param {string} message - Message to log.
 */
function logDebug(message)
{
  if (CONFIG.debug)
  {
    Logger.log('[DEBUG] ' + message);
  }
}

/**
 * Log an error message (always visible in Apps Script logs).
 *
 * @param {string} message - Error message to log.
 */
function logError(message)
{
  Logger.log('[ERROR] ' + message);

  // ALSO console.error, which is what makes this reachable from outside.
  //
  // Logger.log writes only to the Apps Script execution transcript. That is not
  // merely "the place nobody reads" — it cannot be queried by anything at all:
  // the Apps Script API needs the script.processes scope the deploy credential
  // does not hold, and Cloud Logging received nothing, so there was no way to
  // answer "did the last run succeed?" without opening the editor by hand.
  //
  // console.error goes to Cloud Logging under the attached GCP project, where
  // it is queryable and alertable. Errors only — logInfo stays on Logger.log to
  // keep the trigger's routine chatter out of Cloud Logging.
  try { console.error('[ERROR] ' + message); }
  catch (e) { /* console is absent in some contexts; never break logging */ }
}

/**
 * Emit one queryable heartbeat per run, to Cloud Logging.
 *
 * The externally verifiable answer to "is the detector alive and healthy?".
 * Absence of error rows in the Sheet proves nothing on its own — a script that
 * crashes on its first line also writes no rows, and looks identical to a clean
 * run from the outside. One line per execution distinguishes the two.
 *
 * Deliberately a single line, at INFO, once per run: 1440/day is trivial for
 * Cloud Logging and cheap to query, where routing every logInfo there would not
 * be.
 *
 * @param {Object} stats - {processed, spam, errors, auditFindings}
 */
function logRunHeartbeat(stats)
{
  writeHealthRow(stats);

  const line = 'RUN v' + SCRIPT_VERSION +
               ' processed=' + stats.processed +
               ' spam='      + stats.spam +
               ' errors='    + stats.errors +
               ' audit='     + (stats.auditFindings > 0
                                 ? 'FINDINGS:' + stats.auditFindings : 'clean');
  Logger.log('[INFO] ' + line);
  try { console.log(line); }
  catch (e) { /* never break the run over a log line */ }
}
