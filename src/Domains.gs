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

  let stored;
  try
  {
    stored = JSON.parse(raw);
    if (!Array.isArray(stored)) throw new Error('not an array');
  }
  catch (e)
  {
    logError('Blacklist JSON corrupt — using defaults only: ' + e.toString());
    return list;
  }

  // Each stored entry goes through normalizeBlacklistEntry() HERE, not only in
  // addToBlacklist(): the Script Property can be edited by hand in the project settings,
  // and this read is what feeds Rule 1. A refused entry is DROPPED (fails toward a miss,
  // never a delete). Outside the JSON try, and per entry, so a throw in the gate costs one
  // entry under its own message instead of every entry under "JSON corrupt" (PR #38 review).
  // No whitelist means the overlap check cannot run: use the defaults only (a miss, not a delete).
  let whitelist;
  try { whitelist = getWhitelist(); }
  catch (wlError) { logError('getBlacklist: whitelist read failed, user entries skipped: ' + wlError); return list; }
  for (let i = 0; i < stored.length; i++)
  {
    let checked;
    try { checked = normalizeBlacklistEntry(stored[i], whitelist); }
    catch (gateError) { checked = { error: 'gate threw: ' + gateError }; }
    if (checked.error)
    {
      logError('Blacklist entry ignored: ' + sanitizeForLog(String(stored[i])) + ' — ' + checked.error);
      continue;
    }
    if (!list.includes(checked.entry)) list.push(checked.entry);
  }
  return list;
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
  'privaterelay.appleid.com', 'example.com',
  // Help-desk, signing, commerce and meeting platforms (review of PR #38): they send
  // support replies, receipts and signing requests from tenant subdomains, often NOT bulk.
  'zendesk.com', 'freshdesk.com', 'helpscout.net', 'docusign.net', 'shopify.com',
  'eventbrite.com', 'squarespace.com', 'slack.com', 'zoom.us',
  // Hosting suffixes
  'blogspot.com', 'wordpress.com'
]);

/** Dotless entries that are ordinary words in legitimate hosts (review of PR #38). */
const BLACKLIST_REFUSED_WORDS = Object.freeze([
  'newsletter', 'newsletters', 'notification', 'notifications', 'marketing', 'mailing',
  'mailer', 'updates', 'account', 'accounts', 'support', 'service', 'services', 'members'
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
  if (!isAddress && e.indexOf('.') === -1 && BLACKLIST_REFUSED_WORDS.indexOf(e) !== -1)
  {
    return { error: 'an ordinary word; as a host substring it matches legitimate senders' };
  }
  if (!isAddress && /^(co|com|net|org|gov|edu|ac|or|ne|go|ltd|plc|me|sch|nhs|k12)\.([a-z]{2}\.)?[a-z]{2}$/.test(e))
  {
    return { error: 'a public suffix, not a domain' };
  }

  const shared = FREE_MAIL_DOMAINS.concat(THROWAWAY_TENANT_DOMAINS, BLACKLIST_REFUSED_HOSTS);
  for (let i = 0; i < shared.length; i++)
  {
    // Only "would this entry match the platform's own hosts?" A tenant entry
    // (scamco.onmicrosoft.com) matches that tenant alone and is allowed (review of PR #38).
    if (addressMatchesDomain('probe@' + shared[i], e) ||
        addressMatchesDomain('probe@sub.' + shared[i], e))
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

/**
 * EVERY TOP-LEVEL DOMAIN IN THE IANA ROOT ZONE (v6.110.0) - read by Signal 18 (fakeTldSender)
 * through isUnknownTld(). A snapshot of https://data.iana.org/TLD/tlds-alpha-by-domain.txt,
 * Version 2026112201, Last Updated Mon Nov 23 07:07:01 2026 UTC, 1435 entries, lower-cased.
 *
 * STALENESS IS THE DANGEROUS DIRECTION. A TLD retired after the snapshot only costs a miss; a
 * TLD DELEGATED after it looks fake, and Signal 18 would corroborate mail from it. Two guards:
 * Signal 18 also needs an unsubscribe host on a fake TLD and no DKIM pass aligned with the
 * From domain (a real new-TLD sender passes DKIM), and it ABSTAINS entirely once the snapshot
 * is older than TLD_SNAPSHOT_MAX_AGE_DAYS. ICANN's next gTLD round is expected to start
 * delegating around 2027. To refresh: replace this block from the IANA file and bump
 * TLD_SNAPSHOT_DATE.
 */
const TLD_SNAPSHOT_DATE = '2026-11-23';
const TLD_SNAPSHOT_MAX_AGE_DAYS = 365;
const IANA_TLDS = Object.freeze([
  'aaa', 'aarp', 'abb', 'abbott', 'abbvie', 'abc', 'able', 'abogado', 'abudhabi', 'ac',
  'academy', 'accenture', 'accountant', 'accountants', 'aco', 'actor', 'ad', 'ads', 'adult', 'ae',
  'aeg', 'aero', 'aetna', 'af', 'afl', 'africa', 'ag', 'agakhan', 'agency', 'ai',
  'aig', 'airbus', 'airforce', 'airtel', 'akdn', 'al', 'alibaba', 'alipay', 'allfinanz', 'allstate',
  'ally', 'alsace', 'alstom', 'am', 'amazon', 'americanexpress', 'americanfamily', 'amex', 'amfam', 'amica',
  'amsterdam', 'analytics', 'android', 'anquan', 'anz', 'ao', 'aol', 'apartments', 'app', 'apple',
  'aq', 'aquarelle', 'ar', 'arab', 'aramco', 'archi', 'army', 'arpa', 'art', 'arte',
  'as', 'asda', 'asia', 'associates', 'at', 'athleta', 'attorney', 'au', 'auction', 'audi',
  'audible', 'audio', 'auspost', 'author', 'auto', 'autos', 'aw', 'aws', 'ax', 'axa',
  'az', 'azure', 'ba', 'baby', 'baidu', 'banamex', 'band', 'bank', 'bar', 'barcelona',
  'barclaycard', 'barclays', 'barefoot', 'bargains', 'baseball', 'basketball', 'bauhaus', 'bayern', 'bb', 'bbc',
  'bbt', 'bbva', 'bcg', 'bcn', 'bd', 'be', 'beats', 'beauty', 'beer', 'berlin',
  'best', 'bestbuy', 'bet', 'bf', 'bg', 'bh', 'bharti', 'bi', 'bible', 'bid',
  'bike', 'bing', 'bingo', 'bio', 'biz', 'bj', 'black', 'blackfriday', 'blockbuster', 'blog',
  'bloomberg', 'blue', 'bm', 'bms', 'bmw', 'bn', 'bnpparibas', 'bo', 'boats', 'boehringer',
  'bofa', 'bom', 'bond', 'boo', 'book', 'booking', 'bosch', 'bostik', 'boston', 'bot',
  'boutique', 'box', 'br', 'bradesco', 'bridgestone', 'broadway', 'broker', 'brother', 'brussels', 'bs',
  'bt', 'build', 'builders', 'business', 'buy', 'buzz', 'bv', 'bw', 'by', 'bz',
  'bzh', 'ca', 'cab', 'cafe', 'cal', 'call', 'calvinklein', 'cam', 'camera', 'camp',
  'canon', 'capetown', 'capital', 'capitalone', 'car', 'caravan', 'cards', 'care', 'career', 'careers',
  'cars', 'casa', 'case', 'cash', 'casino', 'cat', 'catering', 'catholic', 'cba', 'cbn',
  'cbre', 'cc', 'cd', 'center', 'ceo', 'cern', 'cf', 'cfa', 'cfd', 'cg',
  'ch', 'chanel', 'channel', 'charity', 'chase', 'chat', 'cheap', 'chintai', 'christmas', 'chrome',
  'church', 'ci', 'cipriani', 'circle', 'cisco', 'citadel', 'citi', 'citic', 'city', 'ck',
  'cl', 'claims', 'cleaning', 'click', 'clinic', 'clinique', 'clothing', 'cloud', 'club', 'clubmed',
  'cm', 'cn', 'co', 'coach', 'codes', 'coffee', 'college', 'cologne', 'com', 'commbank',
  'community', 'company', 'compare', 'computer', 'comsec', 'condos', 'construction', 'consulting', 'contact', 'contractors',
  'cooking', 'cool', 'coop', 'corsica', 'country', 'coupon', 'coupons', 'courses', 'cpa', 'cr',
  'credit', 'creditcard', 'creditunion', 'cricket', 'crown', 'crs', 'cruise', 'cruises', 'cu', 'cuisinella',
  'cv', 'cw', 'cx', 'cy', 'cymru', 'cyou', 'cz', 'dad', 'dance', 'data',
  'date', 'dating', 'datsun', 'day', 'dclk', 'dds', 'de', 'deal', 'dealer', 'deals',
  'degree', 'delivery', 'dell', 'deloitte', 'delta', 'democrat', 'dental', 'dentist', 'desi', 'design',
  'dev', 'dhl', 'diamonds', 'diet', 'digital', 'direct', 'directory', 'discount', 'discover', 'dish',
  'diy', 'dj', 'dk', 'dm', 'dnp', 'do', 'docs', 'doctor', 'dog', 'domains',
  'dot', 'download', 'drive', 'dtv', 'dubai', 'dupont', 'durban', 'dvag', 'dvr', 'dz',
  'earth', 'eat', 'ec', 'eco', 'edeka', 'edu', 'education', 'ee', 'eg', 'email',
  'emerck', 'energy', 'engineer', 'engineering', 'enterprises', 'epson', 'equipment', 'er', 'ericsson', 'erni',
  'es', 'esq', 'estate', 'et', 'eu', 'eurovision', 'eus', 'events', 'exchange', 'expert',
  'exposed', 'express', 'extraspace', 'fage', 'fail', 'fairwinds', 'faith', 'family', 'fan', 'fans',
  'farm', 'farmers', 'fashion', 'fast', 'fedex', 'feedback', 'ferrari', 'ferrero', 'fi', 'fidelity',
  'fido', 'film', 'final', 'finance', 'financial', 'fire', 'firestone', 'firmdale', 'fish', 'fishing',
  'fit', 'fitness', 'fj', 'fk', 'flickr', 'flights', 'flir', 'florist', 'flowers', 'fly',
  'fm', 'fo', 'foo', 'food', 'football', 'ford', 'forex', 'forsale', 'forum', 'foundation',
  'fox', 'fr', 'free', 'fresenius', 'frl', 'frogans', 'frontier', 'ftr', 'fujitsu', 'fun',
  'fund', 'furniture', 'futbol', 'fyi', 'ga', 'gal', 'gallery', 'gallo', 'gallup', 'game',
  'games', 'gap', 'garden', 'gay', 'gb', 'gbiz', 'gd', 'gdn', 'ge', 'gea',
  'gent', 'genting', 'george', 'gf', 'gg', 'ggee', 'gh', 'gi', 'gift', 'gifts',
  'gives', 'giving', 'gl', 'glass', 'gle', 'global', 'globo', 'gm', 'gmail', 'gmbh',
  'gmo', 'gmx', 'gn', 'godaddy', 'gold', 'goldpoint', 'golf', 'goodyear', 'goog', 'google',
  'gop', 'got', 'gov', 'gp', 'gq', 'gr', 'grainger', 'graphics', 'gratis', 'green',
  'gripe', 'grocery', 'group', 'gs', 'gt', 'gu', 'gucci', 'guge', 'guide', 'guitars',
  'guru', 'gw', 'gy', 'hair', 'hamburg', 'hangout', 'haus', 'hbo', 'hdfc', 'hdfcbank',
  'health', 'healthcare', 'help', 'here', 'hermes', 'hiphop', 'hisamitsu', 'hitachi', 'hiv', 'hk',
  'hkt', 'hm', 'hn', 'hockey', 'holdings', 'holiday', 'homedepot', 'homegoods', 'homes', 'homesense',
  'honda', 'horse', 'hospital', 'host', 'hosting', 'hot', 'hotels', 'hotmail', 'house', 'how',
  'hr', 'hsbc', 'ht', 'hu', 'hughes', 'hyatt', 'hyundai', 'ibm', 'icbc', 'ice',
  'icu', 'id', 'ie', 'ieee', 'ifm', 'ikano', 'il', 'im', 'imamat', 'imdb',
  'immo', 'immobilien', 'in', 'inc', 'industries', 'infiniti', 'info', 'ing', 'ink', 'institute',
  'insurance', 'insure', 'int', 'international', 'intuit', 'investments', 'io', 'ipiranga', 'iq', 'ir',
  'irish', 'is', 'ismaili', 'ist', 'istanbul', 'it', 'itau', 'itv', 'jaguar', 'java',
  'jcb', 'je', 'jeep', 'jetzt', 'jewelry', 'jio', 'jll', 'jm', 'jmp', 'jnj',
  'jo', 'jobs', 'joburg', 'jot', 'joy', 'jp', 'jpmorgan', 'jprs', 'juegos', 'kaufen',
  'kddi', 'ke', 'kerryhotels', 'kerryproperties', 'kfh', 'kg', 'kh', 'ki', 'kia', 'kids',
  'kim', 'kindle', 'kitchen', 'kiwi', 'km', 'kn', 'koeln', 'komatsu', 'kosher', 'kp',
  'kpmg', 'kpn', 'kr', 'krd', 'kred', 'kuokgroup', 'kw', 'ky', 'kyoto', 'kz',
  'la', 'lacaixa', 'lamborghini', 'lamer', 'land', 'landrover', 'lanxess', 'lasalle', 'lat', 'latino',
  'latrobe', 'law', 'lawyer', 'lb', 'lc', 'lds', 'lease', 'leclerc', 'lefrak', 'legal',
  'lego', 'lexus', 'lgbt', 'li', 'lidl', 'life', 'lifeinsurance', 'lifestyle', 'lighting', 'like',
  'lilly', 'limited', 'limo', 'lincoln', 'link', 'live', 'living', 'lk', 'llc', 'llp',
  'loan', 'loans', 'locker', 'locus', 'lol', 'london', 'lotte', 'lotto', 'love', 'lpl',
  'lplfinancial', 'lr', 'ls', 'lt', 'ltd', 'ltda', 'lu', 'lundbeck', 'luxe', 'luxury',
  'lv', 'ly', 'ma', 'madrid', 'maif', 'maison', 'makeup', 'man', 'management', 'mango',
  'map', 'market', 'marketing', 'markets', 'marriott', 'marshalls', 'mattel', 'mba', 'mc', 'mckinsey',
  'md', 'me', 'med', 'media', 'meet', 'melbourne', 'meme', 'memorial', 'men', 'menu',
  'merck', 'merckmsd', 'mg', 'mh', 'miami', 'microsoft', 'mil', 'mini', 'mint', 'mit',
  'mitsubishi', 'mk', 'ml', 'mlb', 'mls', 'mm', 'mma', 'mn', 'mo', 'mobi',
  'mobile', 'moda', 'moe', 'moi', 'mom', 'monash', 'money', 'monster', 'mormon', 'mortgage',
  'moscow', 'moto', 'motorcycles', 'mov', 'movie', 'mp', 'mq', 'mr', 'ms', 'msd',
  'mt', 'mtn', 'mtr', 'mu', 'museum', 'music', 'mv', 'mw', 'mx', 'my',
  'mz', 'na', 'nab', 'nagoya', 'name', 'navy', 'nba', 'nc', 'ne', 'nec',
  'net', 'netbank', 'netflix', 'network', 'neustar', 'new', 'news', 'next', 'nextdirect', 'nexus',
  'nf', 'nfl', 'ng', 'ngo', 'nhk', 'ni', 'nico', 'nike', 'nikon', 'ninja',
  'nissan', 'nissay', 'nl', 'no', 'nokia', 'norton', 'now', 'nowruz', 'nowtv', 'np',
  'nr', 'nra', 'nrw', 'ntt', 'nu', 'nyc', 'nz', 'obi', 'observer', 'office',
  'okinawa', 'olayan', 'olayangroup', 'ollo', 'om', 'omega', 'one', 'ong', 'onl', 'online',
  'ooo', 'open', 'oracle', 'orange', 'org', 'organic', 'origins', 'osaka', 'otsuka', 'ott',
  'ovh', 'pa', 'page', 'panasonic', 'paris', 'pars', 'partners', 'parts', 'party', 'pay',
  'pccw', 'pe', 'pet', 'pf', 'pfizer', 'pg', 'ph', 'pharmacy', 'phd', 'philips',
  'phone', 'photo', 'photography', 'photos', 'physio', 'pics', 'pictet', 'pictures', 'pid', 'pin',
  'ping', 'pink', 'pioneer', 'pizza', 'pk', 'pl', 'place', 'play', 'playstation', 'plumbing',
  'plus', 'pm', 'pn', 'pnc', 'pohl', 'poker', 'politie', 'porn', 'post', 'pr',
  'praxi', 'press', 'prime', 'pro', 'prod', 'productions', 'prof', 'progressive', 'promo', 'properties',
  'property', 'protection', 'pru', 'prudential', 'ps', 'pt', 'pub', 'pw', 'pwc', 'py',
  'qa', 'qpon', 'quebec', 'quest', 'racing', 'radio', 're', 'read', 'realestate', 'realtor',
  'realty', 'recipes', 'red', 'redumbrella', 'rehab', 'reise', 'reisen', 'reit', 'reliance', 'ren',
  'rent', 'rentals', 'repair', 'report', 'republican', 'rest', 'restaurant', 'review', 'reviews', 'rexroth',
  'rich', 'richardli', 'ricoh', 'ril', 'rio', 'rip', 'ro', 'rocks', 'rodeo', 'rogers',
  'room', 'rs', 'rsvp', 'ru', 'rugby', 'ruhr', 'run', 'rw', 'rwe', 'ryukyu',
  'sa', 'saarland', 'safe', 'safety', 'sakura', 'sale', 'salon', 'samsclub', 'samsung', 'sandvik',
  'sandvikcoromant', 'sanofi', 'sap', 'sarl', 'sas', 'save', 'saxo', 'sb', 'sbi', 'sbs',
  'sc', 'scb', 'schaeffler', 'schmidt', 'scholarships', 'school', 'schule', 'schwarz', 'science', 'scot',
  'sd', 'se', 'search', 'seat', 'secure', 'security', 'seek', 'select', 'sener', 'services',
  'seven', 'sew', 'sex', 'sexy', 'sfr', 'sg', 'sh', 'shangrila', 'sharp', 'shell',
  'shia', 'shiksha', 'shoes', 'shop', 'shopping', 'shouji', 'show', 'si', 'silk', 'sina',
  'singles', 'site', 'sj', 'sk', 'ski', 'skin', 'sky', 'skype', 'sl', 'sling',
  'sm', 'smart', 'smile', 'sn', 'sncf', 'so', 'soccer', 'social', 'softbank', 'software',
  'sohu', 'solar', 'solutions', 'song', 'sony', 'soy', 'spa', 'space', 'sport', 'spot',
  'sr', 'srl', 'ss', 'st', 'stada', 'staples', 'star', 'statebank', 'statefarm', 'stc',
  'stcgroup', 'stockholm', 'storage', 'store', 'stream', 'studio', 'study', 'style', 'su', 'sucks',
  'supplies', 'supply', 'support', 'surf', 'surgery', 'suzuki', 'sv', 'swatch', 'swiss', 'sx',
  'sy', 'sydney', 'systems', 'sz', 'tab', 'taipei', 'talk', 'taobao', 'target', 'tatamotors',
  'tatar', 'tattoo', 'tax', 'taxi', 'tc', 'tci', 'td', 'tdk', 'team', 'tech',
  'technology', 'tel', 'temasek', 'tennis', 'teva', 'tf', 'tg', 'th', 'thd', 'theater',
  'theatre', 'tiaa', 'tickets', 'tienda', 'tips', 'tires', 'tirol', 'tj', 'tjmaxx', 'tjx',
  'tk', 'tkmaxx', 'tl', 'tm', 'tmall', 'tn', 'to', 'today', 'tokyo', 'tools',
  'top', 'toray', 'toshiba', 'total', 'tours', 'town', 'toyota', 'toys', 'tr', 'trade',
  'trading', 'training', 'travel', 'travelers', 'travelersinsurance', 'trust', 'trv', 'tt', 'tube', 'tui',
  'tunes', 'tushu', 'tv', 'tvs', 'tw', 'tz', 'ua', 'ubank', 'ubs', 'ug',
  'uk', 'unicom', 'university', 'uno', 'uol', 'ups', 'us', 'uy', 'uz', 'va',
  'vacations', 'vana', 'vanguard', 'vc', 've', 'vegas', 'ventures', 'verisign', 'versicherung', 'vet',
  'vg', 'vi', 'viajes', 'video', 'vig', 'viking', 'villas', 'vin', 'vip', 'virgin',
  'visa', 'vision', 'viva', 'vivo', 'vlaanderen', 'vn', 'vodka', 'volvo', 'vote', 'voting',
  'voto', 'voyage', 'vu', 'wales', 'walmart', 'walter', 'wang', 'wanggou', 'watch', 'watches',
  'weather', 'weatherchannel', 'web', 'webcam', 'weber', 'website', 'wed', 'wedding', 'weibo', 'weir',
  'wf', 'whoswho', 'wien', 'wiki', 'williamhill', 'win', 'windows', 'wine', 'winners', 'wme',
  'woodside', 'work', 'works', 'world', 'wow', 'ws', 'wtc', 'wtf', 'xbox', 'xerox',
  'xin', 'xn--11b4c3d', 'xn--1ck2e1b', 'xn--1qqw23a', 'xn--2scrj9c', 'xn--30rr7y', 'xn--3bst00m', 'xn--3ds443g', 'xn--3e0b707e', 'xn--3hcrj9c',
  'xn--3pxu8k', 'xn--42c2d9a', 'xn--45br5cyl', 'xn--45brj9c', 'xn--45q11c', 'xn--4dbrk0ce', 'xn--4gbrim', 'xn--54b7fta0cc', 'xn--55qw42g', 'xn--55qx5d',
  'xn--5su34j936bgsg', 'xn--5tzm5g', 'xn--6frz82g', 'xn--6qq986b3xl', 'xn--80adxhks', 'xn--80ao21a', 'xn--80aqecdr1a', 'xn--80asehdb', 'xn--80aswg', 'xn--8y0a063a',
  'xn--90a3ac', 'xn--90ae', 'xn--90ais', 'xn--9dbq2a', 'xn--9et52u', 'xn--9krt00a', 'xn--b4w605ferd', 'xn--bck1b9a5dre4c', 'xn--c1avg', 'xn--c2br7g',
  'xn--cck2b3b', 'xn--cckwcxetd', 'xn--cg4bki', 'xn--clchc0ea0b2g2a9gcd', 'xn--czr694b', 'xn--czrs0t', 'xn--czru2d', 'xn--d1acj3b', 'xn--d1alf', 'xn--e1a4c',
  'xn--eckvdtc9d', 'xn--efvy88h', 'xn--fct429k', 'xn--fhbei', 'xn--fiq228c5hs', 'xn--fiq64b', 'xn--fiqs8s', 'xn--fiqz9s', 'xn--fjq720a', 'xn--flw351e',
  'xn--fpcrj9c3d', 'xn--fzc2c9e2c', 'xn--fzys8d69uvgm', 'xn--g2xx48c', 'xn--gckr3f0f', 'xn--gecrj9c', 'xn--gk3at1e', 'xn--h2breg3eve', 'xn--h2brj9c', 'xn--h2brj9c8c',
  'xn--hxt814e', 'xn--i1b6b1a6a2e', 'xn--imr513n', 'xn--io0a7i', 'xn--j1aef', 'xn--j1amh', 'xn--j6w193g', 'xn--jlq480n2rg', 'xn--jvr189m', 'xn--kcrx77d1x4a',
  'xn--kprw13d', 'xn--kpry57d', 'xn--kput3i', 'xn--l1acc', 'xn--lgbbat1ad8j', 'xn--mgb9awbf', 'xn--mgba3a3ejt', 'xn--mgba3a4f16a', 'xn--mgba7c0bbn0a', 'xn--mgbaam7a8h',
  'xn--mgbab2bd', 'xn--mgbah1a3hjkrd', 'xn--mgbai9azgqp6j', 'xn--mgbayh7gpa', 'xn--mgbbh1a', 'xn--mgbbh1a71e', 'xn--mgbc0a9azcg', 'xn--mgbca7dzdo', 'xn--mgbcpq6gpa1a', 'xn--mgberp4a5d4ar',
  'xn--mgbgu82a', 'xn--mgbi4ecexp', 'xn--mgbpl2fh', 'xn--mgbt3dhd', 'xn--mgbtx2b', 'xn--mgbx4cd0ab', 'xn--mix891f', 'xn--mk1bu44c', 'xn--mxtq1m', 'xn--ngbc5azd',
  'xn--ngbe9e0a', 'xn--ngbrx', 'xn--node', 'xn--nqv7f', 'xn--nqv7fs00ema', 'xn--nyqy26a', 'xn--o3cw4h', 'xn--ogbpf8fl', 'xn--otu796d', 'xn--p1acf',
  'xn--p1ai', 'xn--pgbs0dh', 'xn--pssy2u', 'xn--q7ce6a', 'xn--q9jyb4c', 'xn--qcka1pmc', 'xn--qxa6a', 'xn--qxam', 'xn--rhqv96g', 'xn--rovu88b',
  'xn--rvc1e0am3e', 'xn--s9brj9c', 'xn--ses554g', 'xn--t60b56a', 'xn--tckwe', 'xn--tiq49xqyj', 'xn--unup4y', 'xn--vermgensberater-ctb', 'xn--vermgensberatung-pwb', 'xn--vhquv',
  'xn--vuq861b', 'xn--w4r85el8fhu5dnra', 'xn--w4rs40l', 'xn--wgbh1c', 'xn--wgbl6a', 'xn--xhq521b', 'xn--xkc2al3hye2a', 'xn--xkc2dl3a5ee0h', 'xn--y9a3aq', 'xn--yfro4i67o',
  'xn--ygbi2ammx', 'xn--zfr164b', 'xxx', 'xyz', 'yachts', 'yahoo', 'yamaxun', 'yandex', 'ye', 'yodobashi',
  'yoga', 'yokohama', 'you', 'youtube', 'yt', 'yun', 'za', 'zappos', 'zara', 'zero',
  'zip', 'zm', 'zone', 'zuerich', 'zw'
]);

/**
 * Names that are not in the root zone but are reserved or conventional for PRIVATE networks
 * (RFC 2606, RFC 6761, RFC 6762, RFC 7686, RFC 9476 and common router/AD defaults). Signal 18
 * never treats these as fake: a home NAS or an office mail server legitimately sends from them.
 * This list cannot be complete (the PR #39 review found 30+ more in use, e.g. .lab, .intern,
 * .novalocal) - which is why Signal 18 is a Spam-folder corroborator only and needs a fake
 * unsubscribe host too, never an inbox rule.
 */
const PRIVATE_TLDS = Object.freeze([
  'local', 'localhost', 'localdomain', 'lan', 'home', 'corp', 'internal', 'intranet',
  'private', 'test', 'example', 'invalid', 'onion', 'alt'
]);


/**
 * Shared sending services (v6.112.0): one host carries many unrelated senders, so mail the user
 * filed from ONE tenant must never vouch for another. Read only by labelHistoryRefused(), together
 * with FREE_MAIL_DOMAINS, THROWAWAY_TENANT_DOMAINS and BLACKLIST_REFUSED_HOSTS, matched as host
 * suffixes. The PR #41 review found 77 Reading threads from mail.beehiiv.com spread over several
 * unrelated newsletters.
 */
const SHARED_SENDER_HOSTS = Object.freeze([
  'beehiiv.com', 'convertkit-mail.com', 'convertkit-mail2.com', 'kit.com', 'ck.page',
  'customeriomail.com', 'rsgsv.net', 'list-manage.com', 'cmail19.com', 'cmail20.com',
  'createsend.com', 'mlsend.com', 'mailerlite.com', 'ghost.io', 'buttondown.email', 'aweber.com',
  'acems1.com', 'intercom-mail.com', 'mailjet.com', 'e2ma.net', 'flodesk.com', 'getresponse.com',
  'klaviyomail.com', 'brevosend.com', 'sendinblue.com', 'mandrillapp.com', 'sparkpostmail.com',
  'postmarkapp.com', 'exacttarget.com', 'mktomail.com'
]);

/**
 * Finance publishers whose pitches stay deletable by Rule 14 even if the user filed some of
 * their mail (owner's call, 2026-11-24, like the Agora-family stance): label history never counts.
 * onlineinvestingdaily.com: one mill issue ("Americans Are Not Prepared for What's Coming") is
 * filed under Misc, one filing short of earning history (PR #41 review round 3).
 */
const LABEL_HISTORY_REFUSED_DOMAINS = Object.freeze(['foolsubs.com', 'fool.com', 'stockhouse.com',
  'onlineinvestingdaily.com']);
