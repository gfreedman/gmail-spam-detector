/**
 * Domains.gs — Whitelist and blacklist: reading, caching, and editing.
 *
 * getWhitelist()/getBlacklist() merge DEFAULT_DOMAINS from source with whatever
 * the user added via Script Properties, on every call. That merge is why a new
 * domain in Config.gs takes effect the moment it deploys.
 *
 * The whitelist is checked before any expensive field fetch and before any
 * signal runs, so an entry here disables detection entirely for that sender.
 *
 * Apps Script concatenates every .gs file in sources.json into ONE global
 * scope. These are not modules: nothing is imported, and every function here
 * is a global visible to all other files.
 */

// =============================================================================
// Domain List Management (Whitelist / Blacklist)
//
// Runtime domain lists are stored in Script Properties (persistent key-value
// store). These functions provide CRUD operations for managing the lists
// without editing source code. Run them from the Apps Script editor.
// =============================================================================

/**
 * Get the effective whitelist: source-code defaults merged with any custom
 * domains the user has added via addToWhitelist().
 *
 * Why merge instead of reading Script Properties alone?
 *   Script Properties were initialized from DEFAULT_DOMAINS at setup() time.
 *   When DEFAULT_DOMAINS.legitimate is updated in source (e.g., a new whitelist
 *   entry is deployed), the old Script Properties snapshot doesn't update
 *   automatically — it would need a manual refresh after every deploy.
 *
 *   By merging DEFAULT_DOMAINS.legitimate directly here, the source-code list
 *   is always live the moment clasp pushes the new code. Script Properties
 *   stores only the user-added custom entries; no post-deploy refresh needed.
 *
 * @return {Array<string>} DEFAULT_DOMAINS.legitimate ∪ user-added domains.
 */
function getWhitelist()
{
  // Always start with current source-code defaults (updated on every deploy)
  const list = Array.from(DEFAULT_DOMAINS.legitimate);

  const props = PropertiesService.getScriptProperties();
  const raw = props.getProperty('LEGITIMATE_DOMAINS');
  if (!raw) return list;

  try
  {
    const stored = JSON.parse(raw);
    // Merge any user-added custom domains not already in the defaults
    for (let i = 0; i < stored.length; i++)
    {
      if (!list.includes(stored[i])) list.push(stored[i]);
    }
    return list;
  }
  catch (e)
  {
    logError('Whitelist JSON corrupt — using defaults only: ' + e.toString());
    return list;
  }
}

/**
 * Get the effective blacklist: source-code defaults merged with any custom
 * domains the user has added via addToBlacklist().
 *
 * Same merge strategy as getWhitelist() — DEFAULT_DOMAINS.suspicious is always
 * the live source-code list; Script Properties holds only user-added extras.
 * No post-deploy refresh needed.
 *
 * @return {Array<string>} DEFAULT_DOMAINS.suspicious ∪ user-added domains.
 */
function getBlacklist()
{
  // Always start with current source-code defaults (updated on every deploy)
  const list = Array.from(DEFAULT_DOMAINS.suspicious);

  const props = PropertiesService.getScriptProperties();
  const raw = props.getProperty('SUSPICIOUS_DOMAINS');
  if (!raw) return list;

  try
  {
    const stored = JSON.parse(raw);
    // Merge any user-added custom domains not already in the defaults
    for (let i = 0; i < stored.length; i++)
    {
      if (!list.includes(stored[i])) list.push(stored[i]);
    }
    return list;
  }
  catch (e)
  {
    logError('Blacklist JSON corrupt — using defaults only: ' + e.toString());
    return list;
  }
}

/**
 * Cached wrapper for getWhitelist() — reads Script Properties once per execution.
 * Domain lists don't change mid-run; caching avoids redundant JSON.parse +
 * array-merge work when processing many emails per invocation.
 * @return {Array<string>}
 */
function getCachedWhitelist()
{
  if (_cachedWhitelist === null) _cachedWhitelist = getWhitelist();
  return _cachedWhitelist;
}

/**
 * Cached wrapper for getBlacklist() — reads Script Properties once per execution.
 * @return {Array<string>}
 */
function getCachedBlacklist()
{
  if (_cachedBlacklist === null) _cachedBlacklist = getBlacklist();
  return _cachedBlacklist;
}

/**
 * Add a domain to the whitelist (emails from this domain bypass detection).
 *
 * Duplicate-safe: silently skips if the domain is already in the list.
 *
 * @param {string} domain - Domain substring to whitelist (e.g., 'example.com').
 */
function addToWhitelist(domain)
{
  if (!domain || domain.trim().length === 0)
  {
    logError('addToWhitelist: domain must not be empty');
    return;
  }

  const props = PropertiesService.getScriptProperties();
  const whitelist = getWhitelist();

  if (!whitelist.includes(domain))
  {
    whitelist.push(domain);
    props.setProperty('LEGITIMATE_DOMAINS', JSON.stringify(whitelist));
    logInfo('Added to whitelist: ' + domain);
    logInfo('Whitelist now has ' + whitelist.length + ' domains');
  }
  else
  {
    logInfo('Domain already in whitelist: ' + domain);
  }
}

/**
 * Add a domain to the blacklist (triggers Rule 1 when combined with bulk email).
 *
 * Duplicate-safe: silently skips if the domain is already in the list.
 *
 * @param {string} domain - Domain substring to blacklist (e.g., 'spammer.com').
 */
function addToBlacklist(domain)
{
  if (!domain || domain.trim().length === 0)
  {
    logError('addToBlacklist: domain must not be empty');
    return;
  }

  const props = PropertiesService.getScriptProperties();
  const blacklist = getBlacklist();

  if (!blacklist.includes(domain))
  {
    blacklist.push(domain);
    props.setProperty('SUSPICIOUS_DOMAINS', JSON.stringify(blacklist));
    logInfo('Added to blacklist: ' + domain);
    logInfo('Blacklist now has ' + blacklist.length + ' domains');
  }
  else
  {
    logInfo('Domain already in blacklist: ' + domain);
  }
}

/**
 * Remove a domain from the whitelist.
 *
 * @param {string} domain - Domain substring to remove.
 */
function removeFromWhitelist(domain)
{
  const props = PropertiesService.getScriptProperties();
  const whitelist = getWhitelist();
  const index = whitelist.indexOf(domain);

  if (index > -1)
  {
    whitelist.splice(index, 1);
    props.setProperty('LEGITIMATE_DOMAINS', JSON.stringify(whitelist));
    logInfo('Removed from whitelist: ' + domain);
  }
  else
  {
    logInfo('Domain not found in whitelist: ' + domain);
  }
}

/**
 * Remove a domain from the blacklist.
 *
 * @param {string} domain - Domain substring to remove.
 */
function removeFromBlacklist(domain)
{
  const props = PropertiesService.getScriptProperties();
  const blacklist = getBlacklist();
  const index = blacklist.indexOf(domain);

  if (index > -1)
  {
    blacklist.splice(index, 1);
    props.setProperty('SUSPICIOUS_DOMAINS', JSON.stringify(blacklist));
    logInfo('Removed from blacklist: ' + domain);
  }
  else
  {
    logInfo('Domain not found in blacklist: ' + domain);
  }
}

/**
 * Print the current whitelist to the Apps Script log.
 * Run from the editor to inspect the list.
 */
function viewWhitelist()
{
  const whitelist = getWhitelist();
  logInfo('=== WHITELIST (' + whitelist.length + ' domains) ===');
  whitelist.forEach(function(domain) {
    logInfo('  - ' + domain);
  });
}

/**
 * Print the current blacklist to the Apps Script log.
 * Run from the editor to inspect the list.
 */
function viewBlacklist()
{
  const blacklist = getBlacklist();
  logInfo('=== BLACKLIST (' + blacklist.length + ' domains) ===');
  blacklist.forEach(function(domain) {
    logInfo('  - ' + domain);
  });
}
