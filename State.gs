
/**
 * refreshWhitelist() and refreshBlacklist() were removed in v6.47.0.
 *
 * They existed when Script Properties were the only source of the domain lists
 * and had to be re-seeded after a source edit. Since v6.35.0 getWhitelist() and
 * getBlacklist() merge DEFAULT_DOMAINS at runtime, so source edits are live as
 * soon as clasp pushes and there is nothing to refresh. Nothing called them for
 * twelve releases, and three separate comments already described them as
 * obsolete.
 */


// =============================================================================
// Spam Intelligence Logging
// =============================================================================

/**
 * Gmail label the user applies to spam emails the script missed.
 * On the next run, checkFalseNegatives() finds these, logs them, and deletes them.
 * @const {string}
 */
const SPAM_MISSED_LABEL = 'SpamMissed';

/**
 * In-memory buffer of log entries accumulated during a processInbox() run.
 * Populated by accumulateLogEntry(); drained by flushSpamLog() at end of run.
 * Re-initialized to [] on every Apps Script execution, which is the desired behavior.
 * @type {Array<Object>}
 */
let _pendingLogEntries = [];

/**
 * Run-scoped audit state. Reset at the top of every processInbox().
 *
 * These exist because every disposition bug this project has shipped was
 * invisible in production: the code believed it had acted, and the only way to
 * find out was for a human to open the Spam folder or the Sheet and notice. Six
 * messages sat through two releases meant to remove them; a whitelisted keep
 * was filed as a detection failure. Nothing alerted, and every test was green.
 *
 * So record what actually happened and compare it to what must be true.
 * See auditRunIntegrity().
 * @type {Array<string>}
 */
let _destroyedMessageIds = [];
/** @type {Array<string>} Message ids that reached the Sheet buffer this run. */
let _loggedMessageIds    = [];
/**
 * Aged Spam-folder threads phase 2 neither deleted nor deliberately spared.
 * Non-zero means the detector is NOT acting on the folder.
 * @type {number}
 */
let _unresolvedAgedSpam  = 0;

/**
 * What reviewGmailSpam() decided about each Spam-folder message it judged this
 * run, keyed by Gmail message id.
 *
 * Exists so writeSpamFolderSnapshot() can publish a REASON rather than a bare
 * listing. Phase 1 has already paid for collectSignals() on these messages;
 * recomputing the verdict in the snapshot would mean a second getRawContent()
 * each, which is the exact quota bill this file keeps refusing to pay.
 * @type {Object<string, {verdict: string, signals: string}>}
 */
let _spamFolderVerdicts = {};

/**
 * Per-execution caches for domain lists. Populated on first access via
 * getCachedWhitelist() / getCachedBlacklist(); never mutated mid-run.
 * Apps Script re-initializes all module-level vars on each trigger invocation,
 * so no manual reset is needed between runs.
 * @type {Array<string>|null}
 */
let _cachedWhitelist = null;
let _cachedBlacklist = null;

/**
 * Message ids quarantined during this execution.
 *
 * destroySpam() removes these from any batch it is about to delete. Quarantine
 * no longer applies the SPAM label, so the sweeper should never encounter one —
 * but on 2026-09-16 it deleted a quarantined message because quarantine put it
 * in SPAM and relied on a search-index-dependent query to spare it. Excluding
 * by explicit id depends on no index and no query semantics.
 *
 * An earlier version of this guard was a single boolean that skipped the ENTIRE
 * sweep whenever anything had been quarantined. That turned the safety net off
 * for the whole execution, and combined with the re-quarantine loop it stayed
 * off indefinitely. Per-id exclusion keeps the sweep working.
 *
 * Module-level state resets on every Apps Script invocation — one execution,
 * which is the scope we want.
 */
let _quarantinedMessageIds = [];

/** Per-execution cache of label name -> REST API label id. See getLabelId(). */
let _labelIdCache = {};
