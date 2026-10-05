/**
 * Patterns.gs — Every detection constant except the clickbait list.
 *
 * Body-scan patterns (crypto, fear, Unicode obfuscation), From-field patterns,
 * bulk-service fingerprints, the impersonation and callback-phishing vocabulary,
 * and the domain lists the link-graph and free-mail signals match against.
 *
 * These are the growth axis of the whole system: a missed spam usually ends as
 * a new entry here rather than new logic. The Python test harness parses these
 * arrays out of the source at import time, so they are never duplicated in the
 * tests — reformatting them can break that parser.
 *
 * Apps Script concatenates every .gs file in sources.json into ONE global
 * scope. These are not modules: nothing is imported, and every function here
 * is a global visible to all other files.
 */

/**
 * Body-only crypto scam patterns — high-confidence terms that almost never
 * appear in legitimate email bodies. Each match increments clickbaitCount.
 * @const {Array<RegExp>}
 */
const BODY_CRYPTO_PATTERNS = Object.freeze([
  /\bairdrop\b/i,                    // Crypto token airdrop
  /\bconnect\s+(your\s+)?wallet\b/i, // "Connect your wallet" — wallet drainer
  /\bhardware\s+wallet\b/i,          // Hardware wallet phishing lure (Ledger/Trezor drainer)
  // Wallet/firmware "manual update" lure. "device" deliberately excluded —
  // legit Apple/Google/IT mail uses "update your device" routinely. Gating
  // on wallet/firmware/Ledger/Trezor keeps this crypto-scoped.
  /\b(?:manually\s+)?update\s+(?:your\s+)?(?:hardware\s+)?(?:wallet|firmware|ledger|trezor)\b/i
]);

/**
 * Body-only fear patterns — phishing-specific phrases that read as fear in
 * email body copy. Separate from FEAR_PATTERNS (which checks subject + from)
 * because legitimate transactional senders write fear-adjacent phrases in the
 * subject all the time ("Security alert", "Action required") but the
 * conditional-future framing "X could be compromised if Y" is a phishing
 * fingerprint — legit security alerts say "X was compromised" (definitive,
 * past tense), not "X could be compromised" (conditional, pressure tactic).
 * Each match increments clickbaitCount (same semantics as BODY_CRYPTO_PATTERNS).
 * @const {Array<RegExp>}
 */
const BODY_FEAR_PATTERNS = Object.freeze([
  /\b(?:access|account|wallet|funds|assets|identity|device)\s+(?:could|may|might)\s+be\s+compromised\b/i
]);

/**
 * Body-only reward-survey scam disclaimers (v6.66.0).
 *
 * The "free kit for completing a survey" scam impersonates a brand (MyChart,
 * Costco, a carrier) and then disclaims it in the footer, for legal cover:
 * "This website is not affiliated with MyChart ... makes no claim about
 * trademark rights" / "Participation ... does not guarantee any prize". A real
 * brand never disclaims itself, so the disclaimer IS the fingerprint — and it
 * survives the sender, subject and landing-page rotation the campaign relies on.
 *
 * One match → +1 clickbaitCount, break after the first: every pattern here
 * detects the same template, so counting them independently would inflate
 * the score (same reasoning as BODY_UNICODE_PATTERNS).
 * @const {Array<RegExp>}
 */
const BODY_SURVEY_SCAM_PATTERNS = Object.freeze([
  /\bnot\s+affiliated\s+with\b[\s\S]{0,120}?\bmakes?\s+no\s+claim\b/i,
  /\bdoes\s+not\s+guarantee\s+(?:any|a)\s+(?:prize|reward|gift)\b/i
]);

/**
 * A well-formed RFC 5322 Date header value (v6.66.0, Signal 2f).
 *
 * Every real mail server writes this; a spam mailer with an unfilled template
 * variable does not. The MyChart survey scam sent "_smtpDate . 646048175" and
 * "Sun, 20 Sep 2026 16:38:48 +0200 . 646048175" — a bug in the campaign's own
 * tooling, invisible to it, and present in every wave. All 84 fixtures' Date
 * headers were checked against this: only the two scams fail it.
 *
 * Deliberately lenient where real servers vary (optional weekday, 1-digit
 * hour, optional seconds, named or numeric zone, a trailing "(UTC)" comment)
 * and strict only about garbage. Linear: every repeat is bounded or separated
 * by a required character, and the input is capped at 200 chars.
 * @const {RegExp}
 */
const RFC5322_DATE_PATTERN = /^(?:[A-Za-z]{3},\s*)?\d{1,2}\s+[A-Za-z]{3}\s+\d{2,4}\s+\d{1,2}:\d{2}(?::\d{2})?\s*(?:[+-]\d{4}|[A-Za-z]{1,5})?(?:\s*\([^)]*\))?\s*$/;

/**
 * Unicode obfuscation patterns checked against the email body.
 * Mirrors the four Unicode ranges in CLICKBAIT_PATTERNS (subject+from coverage) —
 * update both constants if extending. Separate body check is needed because
 * spammers hide obfuscated text inside HTML (e.g. "Сⅼіϲkhеrе" in a body anchor
 * tag) while keeping the subject clean to evade subject-level filters.
 * One match → +1 clickbaitCount (break after first hit — all four detect the
 * same evasion technique, not independent signals).
 * @const {Array<RegExp>}
 */
const BODY_UNICODE_PATTERNS = Object.freeze([
  /[Ѐ-ӿ]/, // Cyrillic lookalikes: "Еlоn" with Cyrillic Е, о
  /[Ͱ-Ͽ]/, // Greek lookalikes: "Βanks" with Greek Β
  /[＀-￯]/, // Fullwidth chars: "＄2 Bill" — never legit in English
  /\uD835/           // Mathematical alphanumeric surrogate (𝗔𝗺𝗮𝘇𝗼𝗻)
]);

/**
 * Fear-mongering patterns — boolean signal, first match wins.
 * Checked against subject + from concatenated.
 * @const {Array<RegExp>}
 */
const FEAR_PATTERNS = Object.freeze([
  // Government fear: IRS/NSA/FBI + threat/revelation verb
  /\b(IRS|NSA|FBI|CIA|government|federal)\b.*(warn|hiding|secret|spy|track|audit|investigation|admission|reveal|expose|confiscat)/i,

  // Financial fear: bank/money terms + seizure/theft/loss
  /\b(banks?|bank account|credit card|social security|identity|savings|cash|money)\b.*(seize|steal|stolen|hacked|freeze|frozen|close|closed|warning|alert|confiscat|take|taking|lost)/i,

  // Health fear: medical terms + danger verbs
  /\b(blood thinner|medication|drug|vaccine|doctor|FDA|health crisis|at risk)\b.*(warning|danger|deadly|killing|risk|avoid|corrupt)/i,

  // Standalone urgency words: "WARNING", "ALERT", "BREAKING"
  /\b(warning|alert|urgent|breaking|exposed|banned|stopped)\b/i,

  // "STOP using/taking/putting" imperative pattern
  /\bSTOP (using|taking|doing|buying|putting|eating|drinking)\b/i
]);

/**
 * Bulk email service fingerprints — substring matches against raw email headers.
 * These strings appear in Received/Return-Path headers when the email was routed
 * through Amazon SES, SendGrid, or Mailchimp. Legitimate direct senders won't have them.
 * @const {Array<string>}
 */
const BULK_EMAIL_FINGERPRINTS = Object.freeze([
  'amazonses.com', // Amazon Simple Email Service — used by many bulk senders
  'x-ses-',        // Amazon SES custom header prefix
  'sendgrid.net',  // SendGrid relay fingerprint
  'mcsv.net',      // Mailchimp sending infrastructure
  'iterable.com'   // Iterable marketing platform — appears in CDN/tracking URLs in body HTML (not headers)
]);

/**
 * Marketing sender format patterns — checked against From field only.
 * Detects spammy sender formatting. First match wins.
 * @const {Array<RegExp>}
 */
const MARKETING_PATTERNS = Object.freeze([
  /\|\s*[A-Z]/,                                                                        // "Name | Org" pipe separator
  /\s+at\s+[A-Z]/i,                                                                    // "Name at Organization"
  /\b(investment|trading|wealth|profit|finance|insider|market)\s*(tools?|pro|tips?|alert)/i, // Spammy business names
  /grow@with\./i,                                                                       // Suspicious email pattern
  /@[a-z]\.[a-z]+\.(com|net)/i                                                          // Subdomain pattern: @F.FinanceInsiderPro.com
]);

/**
 * Subject patterns that are exclusively used by cloud document-sharing services.
 * A legitimate match comes ONLY from the service's own sending infrastructure.
 * Any other sender using these subjects is impersonating the service (phishing).
 * @const {Array<RegExp>}
 */
const IMPERSONATION_SUBJECT_PATTERNS = Object.freeze([
  /\bdocument shared with you\b/i,               // Google Docs share notification subject
  /\binvited you to (edit|view|comment)\b/i,      // Google Docs access invitation
  /\bshared a (file|document|folder) with you\b/i // Google Drive / OneDrive share notification
]);

/**
 * Brands whose support/billing mail is impersonated by callback scams.
 *
 * These are consumer security, payment and marketplace brands — the ones a
 * fake renewal notice leans on, because "your antivirus auto-renews today"
 * creates urgency about money the recipient believes they already spend.
 *
 * Matched as plain substrings against lowercased subject+body, so keep entries
 * lowercase. No brand here bills from a consumer free-mail address, so naming
 * one from a gmail.com address is always a misrepresentation — including the
 * Google products: gmail.com is Google's domain, but Google Workspace never
 * invoices from a personal @gmail.com account.
 *
 * The Google/Microsoft subscription and antivirus entries were added in v6.68.0
 * after the 2026-09-30 "Thank You for Your purchase #54123650" miss: the same
 * campaign as the Norton scam (free-mail sender, your own name as the display
 * name, two support numbers) swapped Norton for a $293 "Google Workspace" plan
 * and scored zero on everything because this list did not name it. A phishing
 * review dropped 'google one' (it matches "Google one-time code") and kept
 * venmo/zelle/ebay out: real person-to-person invoices name those. A list will
 * always trail the campaign by one brand — Signal 10 (selfNamedSender) is the
 * structural backstop that does not depend on it.
 * @const {Array<string>}
 */
const IMPERSONATED_SUPPORT_BRANDS = Object.freeze([
  'norton', 'mcafee', 'geek squad', 'best buy', 'paypal', 'lifelock',
  'windows defender', 'microsoft defender', 'applecare', 'apple care',
  'amazon prime', 'coinbase', 'quickbooks', 'avast', 'malwarebytes',
  'google workspace', 'microsoft 365', 'office 365',
  'bitdefender', 'kaspersky', 'webroot', 'totalav', 'trend micro'
]);

/**
 * North American phone number, the payload of a callback scam.
 *
 * Linear — no nested quantifiers, so it is not a ReDoS risk on the 64KB
 * scan window. Requires a separator between groups, so it does not match a
 * bare 10-digit run such as an order number.
 * @const {RegExp}
 */
const CALLBACK_PHONE_PATTERN =
  /(?:\+?1[\s.\-]?)?\(?\d{3}\)?[\s.\-]\d{3}[\s.\-]\d{4}/;

/**
 * A toll-free number written as one digit run: 18005550134, or what
 * deobfuscatePhoneText() leaves of "1 8 0 0 5 5 5 0 1 3 4". The separator
 * requirement of CALLBACK_PHONE_PATTERN exists so an order number cannot pass
 * for a phone number; a toll-free prefix is the stand-in for it here, and the
 * rest of Signal 9's conjunction still has to hold. Letters and '#' count as
 * part of the token on either side, so "order #8775551234" and an id inside a
 * URL ("id=a8445550123b") are not read as a phone number.
 * @const {RegExp}
 */
const TOLL_FREE_DIGIT_RUN = /(?<![0-9a-z#])1?8(?:00|33|44|55|66|77|88)[0-9]{7}(?![0-9a-z])/;

/**
 * Billing language. A fake invoice has to state what is being charged.
 * @const {Array<RegExp>}
 */
const BILLING_LANGUAGE_PATTERNS = Object.freeze([
  /\b(?:invoice|subscription|membership|order)\s+(?:no|number|id|date|summary|total)\b/i,
  /\b(?:auto[-\s]?renew(?:al|s|ed|ing)?|renewal amount|renewal date)\b/i,
  /\b(?:has been|will be|was)\s+(?:charged|debited|billed)\b/i,
  /\bpayment\s+(?:id|method|of)\b/i,
  /\b(?:refund|cancellation)\s+(?:request|department|team|amount|process)\b/i,
  /\btotal\s+(?:amount|due|charged)\b/i
]);

/**
 * Trusted sender domains for cloud document-sharing services.
 * Used with IMPERSONATION_SUBJECT_PATTERNS: if the subject matches a service
 * notification template and the sender is NOT from one of these domains, it's phishing.
 * @const {Array<string>}
 */
const CLOUD_SERVICE_DOMAINS = Object.freeze([
  'google.com',
  'googlemail.com',
  'microsoft.com',
  'office.com',
  'sharepoint.com',
  'dropbox.com',
  'box.com',
  'notion.so',
  'atlassian.net'
]);

/**
 * E-signature / document-workflow brands whose name inside a call-to-action
 * link implies a specific set of legitimate destination hosts.
 *
 * Used by Signal 7 (brand-mismatched CTA): a button reading "VIEW IN DOCUSIGN"
 * whose href points somewhere that is not DocuSign is a credential-harvest
 * lure. The brand name is in the button because it converts — it borrows trust
 * the sender has not earned.
 *
 * KEYS must be lowercase [a-z0-9] with no spaces or punctuation. Anchor link
 * text is normalized with /[^a-z0-9]+/g before matching, so "Adobe Sign"
 * is keyed as 'adobesign'. A key containing a space or capital could never
 * match anything. Enforced by a parser self-test in the Python harness.
 *
 * VALUES are bare registrable hostnames, compared with hostMatchesDomain()
 * (exact or dot-suffix) — never substring, which would accept both
 * "notdocusign.net" and "docusign.net.evil.com".
 *
 * Deliberately NOT included: a bare 'box' key (would match "inbox",
 * "box office"), or any brand whose name is a common English word.
 *
 * CONSTRAINT: this object body must contain no { or } characters. The Python
 * harness extracts it with a naive brace counter that does not skip strings
 * or comments, so a brace anywhere inside would truncate the parse.
 *
 * @const {Object<string, Array<string>>}
 */
const BRAND_CTA_DOMAINS = Object.freeze({
  docusign:    Object.freeze(['docusign.net', 'docusign.com', 'docusign.eu', 'docusign.co.uk']),
  adobesign:   Object.freeze(['adobesign.com', 'echosign.com', 'adobe.com', 'acrobat.com']),
  echosign:    Object.freeze(['adobesign.com', 'echosign.com', 'adobe.com', 'acrobat.com']),
  hellosign:   Object.freeze(['hellosign.com', 'dropboxsign.com', 'dropbox.com']),
  dropboxsign: Object.freeze(['dropboxsign.com', 'hellosign.com', 'dropbox.com']),
  pandadoc:    Object.freeze(['pandadoc.com', 'pandadoc.net']),
  // 'signnow' deliberately REMOVED. Anchor text is normalized by stripping
  // non-alphanumerics, so the ordinary button label "Sign Now" collapses to
  // "signnow" and matched this key. That fired Rule 7 on legitimate
  // e-signature and HR buttons ("Sign Now" -> app.ironcladapp.com,
  // "Please review and sign now" -> acme.bamboohr.com). Per the key contract
  // above, brands whose name is a common English phrase cannot be matched this
  // way. Same reasoning already excludes a bare 'box' key.
  smartsheet:  Object.freeze(['smartsheet.com']),
  egnyte:      Object.freeze(['egnyte.com']),
  sharepoint:  Object.freeze(['sharepoint.com', 'microsoft.com', 'office.com', 'office365.com', 'microsoftonline.com']),
  onedrive:    Object.freeze(['onedrive.com', 'onedrive.live.com', 'live.com', 'microsoft.com', 'sharepoint.com']),
  googledrive: Object.freeze(['google.com', 'googleusercontent.com']),
  googledocs:  Object.freeze(['google.com', 'googleusercontent.com'])
});

/**
 * Click-tracking, link-wrapping and security-rewrite hosts.
 *
 * A brand CTA pointing at one of these is UNVERIFIABLE, not malicious — the
 * real destination is hidden behind the redirector. Signal 7 therefore
 * ABSTAINS on these rather than firing. This abstention is load-bearing:
 * without it, a legitimate invoice whose "View in DocuSign" button is wrapped
 * by SendGrid click-tracking is a false positive (proven by ablation against
 * tests/ham_examples/Invoice ready to sign via click tracker.eml).
 *
 * Fail open, not closed: an unknown destination is not evidence of phishing.
 *
 * @const {Array<string>}
 */
const LINK_WRAPPER_DOMAINS = Object.freeze([
  // Email service providers' click tracking
  'sendgrid.net', 'awstrack.me', 'amazonses.com', 'list-manage.com',
  'mailchimp.com', 'mcusercontent.com', 'hubspotlinks.com', 'hs-sites.com',
  'mktoresp.com', 'mktomail.com', 'marketo.com', 'pardot.com', 'go.pardot.com',
  'exacttarget.com', 'exct.net', 'klclick.com', 'klclick1.com',
  'klaviyomail.com', 'sendinblue.com', 'brevo.com', 'brevosend.com',
  'mailgun.org', 'mandrillapp.com', 'sparkpostmail.com', 'postmarkapp.com',
  'resend.com', 'resend.dev', 'iterable.com', 'salesforce.com',
  // Security / gateway link rewriters (appear on inbound mail the user wants)
  'urldefense.com', 'urldefense.proofpoint.com',
  'safelinks.protection.outlook.com', 'mimecast.com', 'mimecastprotect.com',
  'linkprotect.cudasvc.com', 'barracudanetworks.com', 'clicktime.symantec.com',
  // Generic shorteners
  'bit.ly', 't.co', 'lnkd.in', 'hubs.ly', 'ow.ly', 'buff.ly', 'tinyurl.com',
  'rebrand.ly', 'goo.gl'
]);

/**
 * Leftmost-label heuristic for customer-CNAMEd tracker hosts.
 *
 * Senders commonly CNAME their own subdomain onto an ESP's click tracker, so
 * the wrapper appears as "click.acme.com" or "links.acme.com" rather than a
 * host in LINK_WRAPPER_DOMAINS. Treated the same way: abstain, do not fire.
 *
 * @const {Array<string>}
 */
const TRACKER_LABELS = Object.freeze([
  'click', 'clicks', 'ct', 'trk', 'track', 'tracking', 'link', 'links',
  'lnk', 'url', 'go', 'redirect', 'r', 'e', 'em', 't'
]);

/**
 * Verbs that make an anchor a call to action rather than prose.
 *
 * Signal 7 requires one of these alongside the brand name. Without it, the
 * footer sentence "About DocuSign — sign documents electronically" in a
 * GENUINE DocuSign email matches the brand and fires a false positive, as does
 * any news article mentioning the company. A lure needs a button the victim
 * clicks; prose does not.
 *
 * @const {RegExp}
 */
/**
 * Consumer free-mail providers. A sender here has no domain reputation to
 * stake, which is why spam uses them; it is also where most real people are,
 * so this is only ever used as one half of a two-part test.
 * @const {Array<string>}
 */
const FREE_MAIL_DOMAINS = Object.freeze([
  'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.uk', 'ymail.com',
  'hotmail.com', 'hotmail.co.uk', 'outlook.com', 'live.com', 'msn.com',
  'aol.com', 'proton.me', 'protonmail.com', 'icloud.com', 'me.com',
  'mail.com', 'gmx.com', 'gmx.net', 'zoho.com', 'yandex.com',
  // Regional variants, added v6.69.0 (the v6.68.0 phishing review listed them
  // as callback-scam senders this list did not recognise). qq.com and 163.com
  // were deliberately left out: their addresses are numeric BY DESIGN, so
  // Signal 8 would call every one machine-generated — a STRONG corroborator.
  'hotmail.ca', 'hotmail.fr', 'live.ca', 'live.co.uk', 'outlook.fr',
  'yahoo.ca', 'yahoo.fr', 'yahoo.co.in', 'rocketmail.com',
  'gmx.de', 'web.de', 'mail.ru'
]);

/**
 * Free-to-create tenant domains that callback scams send from. Unlike
 * FREE_MAIL_DOMAINS these are NOT used by Signal 8: a Microsoft 365 tenant's
 * default domain (contoso123.onmicrosoft.com) routinely has machine-looking
 * names, so "machine-generated sender" would mean nothing there. They count
 * only for Signals 9 and 10, where the sender is impersonating a brand or the
 * recipient — something a real tenant has no reason to do.
 * @const {Array<string>}
 */
const THROWAWAY_TENANT_DOMAINS = Object.freeze([
  'onmicrosoft.com'
]);

/**
 * Local parts that look machine-generated rather than chosen by a person.
 *
 * Two shapes, both deliberately narrow:
 *   letters, 3+ digits, THEN MORE LETTERS  -> raju47326yu, amit83920xk
 *   5+ consecutive digits                  -> pooja1029384, mailer99281
 *
 * The trailing-letters requirement is what makes the first safe: "john1985"
 * and "clark.kent1938" are how humans write a birth year and do NOT match.
 * Measured against 42 realistic personal and service addresses (jane.doe,
 * mike_92, tom99, jd1990, no-reply, jobalerts-noreply, dse_NA3...) with zero
 * matches, and 6/6 on spam-shaped ones.
 *
 * @const {Array<RegExp>}
 */
const RANDOM_LOCAL_PART_PATTERNS = Object.freeze([
  /^[a-z]{2,}\d{3,}[a-z]{1,6}$/i,
  /^[a-z.\-_]*\d{5,}[a-z.\-_]*$/i
]);

const CTA_VERB_PATTERN = /\b(view|open|review|sign|access|continue|download|proceed|complete|retrieve|verify|confirm)\b/i;
