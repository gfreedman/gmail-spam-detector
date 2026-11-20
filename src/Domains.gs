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
    // Merge any user-added custom domains not already in the defaults. Each one goes
    // through normalizeBlacklistEntry() HERE, not only in addToBlacklist(): the Script
    // Property can be edited by hand in the project settings, and this read is what
    // feeds Rule 1. A refused entry is DROPPED (fails toward a miss, never a delete).
    const whitelist = getWhitelist();
    for (let i = 0; i < stored.length; i++)
    {
      const checked = normalizeBlacklistEntry(stored[i], whitelist);
      if (checked.error)
      {
        logError('Blacklist entry ignored: ' + sanitizeForLog(String(stored[i])) + ' — ' + checked.error);
        continue;
      }
      if (!list.includes(checked.entry)) list.push(checked.entry);
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
 * Shared-platform sender domains a blacklist entry must never cover (v6.109.0). Each
 * carries mail from many unrelated senders, so an entry matching one would delete all of
 * them. Free-mail and throwaway-tenant domains are checked separately, from their own lists.
 * @const {Array<string>}
 */
const BLACKLIST_REFUSED_HOSTS = Object.freeze([
  'googlegroups.com', 'groups.io', 'google.com', 'calendar-notification.google.com',
  'substack.com', 'medium.com', 'github.com', 'linkedin.com', 'facebookmail.com',
  'amazonses.com', 'sendgrid.net', 'mcsv.net', 'mailchimpapp.net', 'hubspotemail.net',
  'iterable.com', 'cyberimpact.com', 'constantcontact.com', 'mailgun.org',
  'privaterelay.appleid.com', 'example.com'
]);

/** Dotless entries shorter than this are refused: they are host SUBSTRINGS ('news', 'mail'). */
const MIN_DOTLESS_BLACKLIST_LENGTH = 8;

/**
 * Clean up and vet one blacklist entry (v6.109.0).
 *
 * Since v6.108.0 a full-domain entry convicts under Rule 1 with NO bulk fingerprint, and
 * Rule 1 permanently deletes. So one mistaken entry ('gmail.com', 'co.uk', a whitelisted
 * newsletter's domain) would delete every non-bulk email from it. This is the gate.
 *
 * Normalises: trims, lowercases, removes zero-width characters, strips leading/trailing
 * dots and a leading '@'. A malformed entry used to fail CLOSED by accident (an uppercase
 * or leading-dot entry never matched); after normalising it matches as intended.
 *
 * Refuses (returns {error}):
 *   - empty, whitespace inside, or characters outside [a-z0-9.@_+-];
 *   - an entry that would match a free-mail, throwaway-tenant or shared-platform host
 *     (tested with addressMatchesDomain itself, so dotless 'gmail' and 'mail.com' count);
 *   - a public suffix shape: one label before a 2-letter country code with a generic
 *     second level ('co.uk', 'com.au'), or no dot at all and shorter than 8 characters;
 *   - an entry that overlaps the whitelist in either direction (it would match a
 *     whitelisted host, or a whitelisted entry would match it);
 *   - an address entry ending in '@' (matches nothing; almost certainly a typo).
 *
 * @param {*} raw - The entry as typed or as stored.
 * @param {Array<string>} whitelist - The effective whitelist (getWhitelist()).
 * @return {{entry: string}|{error: string}}
 */
function normalizeBlacklistEntry(raw, whitelist)
{
  if (typeof raw !== 'string') return { error: 'not a string' };
  let e = raw.replace(/[​-‍⁠﻿]/g, '').trim().toLowerCase();
  e = e.replace(/^@+/, '').replace(/^\.+/, '').replace(/\.+$/, '');
  if (e.length === 0) return { error: 'empty' };
  if (!/^[a-z0-9.@_+-]+$/.test(e)) return { error: 'contains whitespace or an unexpected character' };
  if (e.indexOf('..') !== -1) return { error: 'empty domain label (..)' };
  if (e.indexOf('@') !== -1 && e.indexOf('@') !== e.lastIndexOf('@')) return { error: 'more than one @' };
  if (e.charAt(e.length - 1) === '@') return { error: 'ends in @, matches nothing' };

  const isAddress = e.indexOf('@') !== -1;
  if (!isAddress && e.indexOf('.') === -1 && e.length < MIN_DOTLESS_BLACKLIST_LENGTH)
  {
    return { error: 'a dotless entry matches any host CONTAINING it; ' +
                    MIN_DOTLESS_BLACKLIST_LENGTH + '+ characters required' };
  }
  if (!isAddress && /^(co|com|net|org|gov|edu|ac|or|ne|go)\.[a-z]{2}$/.test(e))
  {
    return { error: 'a public suffix, not a domain' };
  }

  const shared = FREE_MAIL_DOMAINS.concat(THROWAWAY_TENANT_DOMAINS, BLACKLIST_REFUSED_HOSTS);
  for (let i = 0; i < shared.length; i++)
  {
    if (addressMatchesDomain('probe@' + shared[i], e) ||
        addressMatchesDomain('probe@sub.' + shared[i], e) ||
        (!isAddress && e.indexOf('.') !== -1 && hostMatchesDomain(e, shared[i])))
    {
      return { error: 'would match ' + shared[i] + ', a shared or free-mail domain' };
    }
  }

  const wl = whitelist || [];
  for (let j = 0; j < wl.length; j++)
  {
    const w = String(wl[j] || '').toLowerCase();
    if (!w) continue;
    const wHost = w.substring(w.lastIndexOf('@') + 1);
    const eHost = e.substring(e.lastIndexOf('@') + 1);
    if (addressMatchesDomain('probe@' + wHost, e) ||     // entry would match a whitelisted host
        addressMatchesDomain('probe@' + eHost, w))       // a whitelisted entry covers this one
    {
      return { error: 'overlaps whitelist entry ' + w };
    }
  }

  return { entry: e };
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
 * Add a domain to the blacklist (triggers Rule 1 on the From address alone; a full
 * domain also triggers Rule 12 when a relay-shaped sender's Reply-To is on it).
 *
 * Duplicate-safe: silently skips if the domain is already in the list.
 *
 * @param {string} domain - Domain substring to blacklist (e.g., 'spammer.com').
 */
function addToBlacklist(domain)
{
  // Vetted first (v6.109.0): a full-domain entry deletes on its own under Rule 1.
  const checked = normalizeBlacklistEntry(domain, getWhitelist());
  if (checked.error)
  {
    logError('addToBlacklist REFUSED ' + sanitizeForLog(String(domain)) + ': ' + checked.error);
    return;
  }
  domain = checked.entry;

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
  // Same normalisation addToBlacklist() applies, so 'Spammer.COM' removes 'spammer.com'.
  const index = blacklist.indexOf(String(domain || '').replace(/[\u200b-\u200d\u2060\ufeff]/g, '')
    .trim().toLowerCase().replace(/^@+/, '').replace(/^\.+/, '').replace(/\.+$/, ''));

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
