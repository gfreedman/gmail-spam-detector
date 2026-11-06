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
  /\bshared a (?:new )?(file|document|folder) with you\b/i // Google Drive / OneDrive share notification ("shared a new document with you" since v6.92.0)
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
 *
 * One line, and [0-9] rather than \d (identical in JS), so the Python harness
 * loads it with _load_single_regex() instead of keeping a hand-copied
 * duplicate — Python's \d would also match Arabic-Indic digits.
 * @const {RegExp}
 */
const CALLBACK_PHONE_PATTERN = /(?:\+?1[\s.\-]?)?\(?[0-9]{3}\)?[\s.\-][0-9]{3}[\s.\-][0-9]{4}/;

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

/**
 * Lure wording for Signal 11: a "message waiting" pretext in a calendar
 * invite's EVENT TITLE (the subject after Google's marker), never the
 * description — vendors and recruiters mention voicemail in passing. Only
 * ever read for mail that is ALSO a real calendar invite carrying Google's own
 * "Invitation from an unknown sender" marker and an off-domain link.
 *
 * Added v6.71.0 after "New Voice Message Notification Received" arrived as a
 * Google Calendar invite from a compromised Workspace account, its "Listen to
 * voicemail" link wrapped in google.com/url and pointing at the typosquat
 * strykertraiilers.com.
 * @const {Array<RegExp>}
 */
const CALENDAR_LURE_PATTERNS = Object.freeze([
  /\bvoice[- ]?mails?\b/i,
  /\bvoice[- ]?(?:message|note|memo|recording)s?\b/i,
  /\baudio (?:message|recording)s?\b/i,
  /\bfax(?:ed)? (?:message|document)s?\b/i
]);

/**
 * Link destinations that are NOT a payload in a calendar invite: the parts of
 * Google that Calendar's own template links (NOT all of google.com — Docs,
 * Sites, Drive and Forms host phishing pages too), schema.org markup, and the
 * meeting and booking services an organiser legitimately links. Taken from the
 * user's real invites: a Meet invite links calendar., meet., support.,
 * www.google.com, tel.meet (dial-in numbers) and calendly.com.
 * @const {Array<string>}
 */
const CALENDAR_SAFE_LINK_DOMAINS = Object.freeze([
  'calendar.google.com', 'meet.google.com', 'support.google.com', 'www.google.com',
  'tel.meet', 'schema.org',
  'zoom.us', 'zoom.com', 'zoomgov.com', 'teams.microsoft.com', 'teams.live.com',
  'webex.com', 'gotomeeting.com', 'calendly.com'
]);

/**
 * Separator characters that split a From display name into "<headline> -
 * <brand>" for Signal 12 (headlineFromName). Signal 12 requires a space on
 * both sides, so hyphenated words ("Pre-IPO", "Jean-Luc") never split; the
 * spaces are added there because the test harness's string-array parser
 * rejects entries containing whitespace. The bullet is absent on purpose:
 * Signal 1c already scores it, and the From name earns one weak point at most.
 * @const {Array<string>}
 */
const HEADLINE_NAME_SEPARATORS = Object.freeze([
  '-', '|', '–', '—'
]);

/**
 * The five patterns of Signal 14 (sponsoredAdTemplate), IN THIS ORDER: an ad
 * disclaimer, the ad network's unsubscribe sentence, an ad-network block
 * heading, and the credit line each teaser carries. Patterns rather than
 * literals (v6.83.0): the same network reworded its disclaimer from "This is an
 * advertisement" to "This is a paid advertisement" and the literal missed it.
 *
 * Run against normalizeAdText() output (Text.gs: entities, NFKC, lower-case,
 * lookalike and dash folds, zero-width strip, spaces collapsed), so they
 * carry no /i flag and no \b (JS \b is ASCII-only and Python's is not, so the
 * mirror would disagree on non-ASCII neighbours). The disclaimer is strict
 * about its tail (v6.83.0 review): the long form refuses a following letter,
 * digit, hyphen or " blocker"; the SHORT form "ad" must END its clause (a
 * following . ! : , ; ) or the end of the text), so "this is an ad-free
 * edition", "an ad blocker tip" and "an ad hoc group" are not disclaimers. The
 * heading and credit accept a hyphen for the space (text is hyphen-folded).
 * NO CAPTURE GROUPS, ever: Signal 14 counts matches with String.split(), which
 * splices captured text into its result and would corrupt every count (a test
 * asserts it). No quantifier is nested, so each scan is linear.
 *
 * Index 4 (v6.85.0) is the credit label for the STRICT shape only: "sponsored by"
 * OR "ad by". The same mill reworded its credits from "Sponsored by <name>" to
 * "Ad by <name>" and kept everything else, including the advertiser sentence, so
 * the strict shape (which that sentence guards) must accept the new label. It is
 * deliberately NOT used by the relay shape, which has no such sentence: three
 * "Ad by Fidelity" credits in a finance newsletter on a relay sender would
 * otherwise convict (reproduced in review). "promoted by" is left out for the
 * same reason (ordinary English: local-paper and event digests). The lookbehind
 * sits on "ad" ONLY: it blocks word-internal matches ("bad by", "head by") and a
 * leading hyphen. It is NOT on "sponsored", which keeps matching exactly as index
 * 3 does, including when two credits are glued together in the tags-deleted view
 * ("...Aasponsored by B"); a pinned test needs that. Valid in V8 and in Python's
 * re, no capture group. Index 3 stays the tight "sponsored by", for the relay shape.
 *
 * Signal 14 fires on EITHER of two shapes (see there): the strict one needs all
 * patterns 0, 1, 2 and 4; the relay one drops the advertiser sentence (pattern 1) and uses pattern 3 for its credits, but needs the
 * brand-on-an-ESP-relay sender shape. The sentence is what editorial sponsor
 * blocks lack: Morning-Brew-style newsletters carry a heading, credits and even
 * a disclaimer, but none says "promotional messages from this advertiser".
 * Measured against the user's whole mailbox (2026-10-23/24): no kept message
 * contained the disclaimer, the block heading, or both, other than the misses.
 * @const {Array<RegExp>}
 */
const SPONSORED_AD_PATTERNS = Object.freeze([
  /this is an? (?:paid |sponsored )?(?:advertisement(?![a-z0-9-]| blocker)|ad(?= ?[.!:,;)]| ?$))/,
  /(?:promotional|marketing|advertising) (?:messages?|emails?) from (?:this|the) (?:advertiser|sponsor)/,
  /sponsored[ -](?:content|stories)/,
  /sponsored[ -]by/,
  /(?:sponsored|(?<![a-z0-9-])ad)[ -]by/
]);

/**
 * SHADOW OBSERVER data (v6.91.0) - LOG-ONLY, read by observeShadow() in Thread.gs and
 * by nothing that decides a verdict. Six theme families a finance-ad mill stacks in one
 * email. Reviewed 2026-10-28 (L7, reformed-spammer, first-principles): counting themes
 * is wording-bound and the families overlap ordinary finance news ("$10 trillion",
 * "executive order"), so this must NOT convict until real-mailbox data says otherwise.
 *
 * Every pattern is bounded: no unbounded gap, no nested quantifier, no \b (JS \b is
 * ASCII-only; Python's is not), so a scan is linear at the 100 KB input cap. Run
 * against normalizeAdText() output plus the extra strip in observeShadow().
 * @const {Object<string, RegExp>}
 */
const SHADOW_THEME_PATTERNS = Object.freeze({
  moneyFear:  /(?:your|if you (?:have|own|hold)(?: an?)?) (?:401 ?\(?k\)?|ira|retirement|savings|pension|nest egg|social security|brokerage|portfolio)/,
  authority:  /executive order|new law|federal reserve|treasury|white house|supreme court|congress|(?:^|[ ,.])the fed(?:[ ,.]|$)/,
  suppressed: /(?:left|kept|leave|leaving|keep|keeping) (?:[a-z]{1,12} ){0,3}(?:off|out of) (?:the )?(?:front page|headlines|news)|(?:don|doesn)['\u2019]?t want you to (?:know|see)|do not want you to (?:know|see)|won['\u2019]?t tell you|mainstream media|cover-?up|banned|censor/,
  deadline:   /before (?:we|they|it|this|midnight|tonight)(?: [a-z]{1,12}){0,3} (?:take|taken|pull|pulled|remove|removed|delete|deleted|shut|down|ends?|expires?)|(?:expires?|ends?) (?:tonight|today|soon|friday|at midnight)|last chance|take (?:it|this) down|act (?:now|fast|today)/,
  scale:      /\$ ?\d{1,3}(?:\.\d{1,2})? ?(?:trillion|billion)|\d{1,3}(?:,\d{3}){0,2} million (?:people|americans|accounts|investors|workers)/,
  upside:     /(?:^|[^a-z0-9])\d{1,3}x(?:[^a-z0-9]|$)|millionaire|skyrocket|explode|life-?changing|windfall/
});

/**
 * REPEATED-LINK observer threshold (v6.96.0) - LOG-ONLY, read by observeShadow() in
 * Thread.gs. One URL repeated this many times in a bulk-service mail from a sender the
 * owner has no history with. Panel 2026-11-04: 6 (5 touches multi-CTA text mail);
 * counting is exact-URL AND host+path, so a per-link token in the query cannot dodge it.
 * @const {number}
 */
const SHADOW_CTA_REPEAT_MIN = 6;

/**
 * Footer postal addresses seen on 4+ spam fixtures across several brand domains
 * (one street address behind five sender domains - the cheap-to-match,
 * costly-to-change tell). Normalised: lower-case, letters and digits, single spaces.
 * Registered-agent addresses (Wilmington 9th St, 222 Delaware St New Castle, and
 * 1607 Capitol Ave Cheyenne, which this very mill prints as its own) are LEFT OUT
 * on purpose: thousands of legitimate firms share them.
 *
 * DECISION DATA since v6.98.0: Signal 16 (millFooterAddress, Rule 13, DELETES after the Drive archive)
 * reads this list, and observeShadow() still tags `postal=` from it. It was
 * log-only through v6.97.0 and the Macro View Digest miss (v6.97.0) was tagged
 * `postal=fwy` seven minutes after it arrived while nothing acted on the tag.
 * Adding an address is a data line, but it ships through a release (the list is
 * source, not a Script Property). A tenant that later moves into one of these
 * buildings inherits the tell, so review the list when a deletion looks wrong (Raw Log: Rule 13).
 * REVIEW DATE: every entry was recorded 2026-10 and last reviewed 2026-11-06 against
 * the fixtures (each hit appears with the same city/state tail shown below). The
 * 5005 entry carries its suite ("suite 350") because 5005 LBJ Freeway is a
 * multi-tenant tower: every mill fixture prints that suite, a legitimate tenant of
 * another suite does not match (panel, 2026-11-06). 74 E Glenwood Ave (Smyrna DE) and
 * 200 Broadway Blvd NE (Albuquerque) are mail-drop addresses shared by many small
 * firms; they stay because every fixture hit is a mill, but they are the entries
 * most likely to need removing.
 * @const {Array<string>}
 */
const MILL_POSTAL_NEEDLES = Object.freeze([
  '200 broadway blvd ne albuquerque',
  '74 e glenwood ave smyrna',
  '111 e atlantic ave suite 200 delray beach',
  '5005 lyndon b johnson fwy suite 350'
]);

/**
 * DOCUMENT-LURE SHADOW data (v6.92.0) - LOG-ONLY, read by docLureHost() in LinkGraph.gs
 * and observeShadow() in Thread.gs; nothing that decides a verdict reads it.
 *
 * A "X shared a document with you" notice whose only button ("VIEW PDF ONLINE") names no
 * brand, so Signal 7 cannot see it, and which links to a host unrelated to the sender.
 * Reviewed 2026-11-04 (L7 security): the same shape is what a CPA, law firm or realtor
 * on a white-label portal sends legitimately, so this must NOT convict until the log
 * shows real mail. Bounded: no unbounded gap, no nested quantifier.
 * Run against subject + the first 2000 chars of plain text, zero-width characters
 * stripped.
 * @const {Array<RegExp>}
 */
const DOC_LURE_PATTERNS = Object.freeze([
  /(?:shared|sent)[^.\n]{0,40}(?:document|file|folder|pdf)[^.\n]{0,20}with you/i,
  /has sent you an? (?:document|pdf|file)/i,
  /(?:^|[^a-z])estmt(?:[^a-z]|$)/i
]);

/**
 * A button that says "view the document" without naming a brand. Tested against the
 * anchor text with every non-alphanumeric stripped, so "VIEW PDF ONLINE", "View-PDF"
 * and zero-width padding all collapse. Whole-string match, <= 40 characters: a
 * sentence is not a button. A noun is REQUIRED; bare "online" is not one.
 * @const {RegExp}
 */
const DOC_LURE_CTA_PATTERN = /^(?:view|open|download|access|review)(?:the|your|this)?(?:pdf|document|file|statement)(?:online)?$/;

/**
 * Registrable roots of services that legitimately send "view your document" mail from
 * one domain and link to another (portals, accounting, e-sign, transfer). Either the
 * sender or the link landing on one of these abstains. Matched with hostMatchesDomain().
 * @const {Array<string>}
 */
const DOC_LURE_TRUSTED_ROOTS = Object.freeze([
  'xero.com', 'intuit.com', 'quickbooks.com', 'stripe.com', 'squareup.com', 'paypal.com',
  'freshbooks.com', 'waveapps.com', 'bill.com', 'taxdome.com', 'smartvault.com',
  'sharefile.com', 'liscio.me', 'canopytax.com', 'karbonhq.com', 'clio.com', 'mycase.com',
  'dotloop.com', 'skyslope.com', 'zoho.com', 'zohosign.com', 'wetransfer.com', 'we.tl',
  'icloud.com', 'apple.com', 'adobe.com', 'adobesign.com', 'docusign.net', 'docusign.com',
  'dropboxsign.com', 'pandadoc.com', 'canva.com', 'figma.com', 'slack.com', 'hubspot.com',
  'docsend.com', 'google.com', 'googleusercontent.com', 'microsoft.com', 'office.com',
  'sharepoint.com', 'live.com', 'onedrive.com', 'dropbox.com', 'box.com'
]);

const CTA_VERB_PATTERN = /\b(view|open|review|sign|access|continue|download|proceed|complete|retrieve|verify|confirm)\b/i;


/**
 * FINANCE-PITCH SCORE TABLE (v6.99.0) - read by Signal 17 (pitchScore, Rule 14) through
 * bayesTokens() / bayesScore() in Text.gs. NOT hand-written: `python3 scripts/train_bayes.py`
 * regenerates the block below from tests/spam_examples + scam_examples (spam) and
 * tests/ham_examples (ham). A miss is therefore DATA (add the .eml, rerun, commit), not a
 * new pattern and a hand-tuned release. Each weight is 10 x the smoothed natural-log
 * odds of "spam", a POSITIVE integer (ham-leaning words are not stored, so appended words
 * cannot lower a score) so JS and the Python mirror score identically; the message score
 * is the sum of the 20 largest weights among its tokens.
 * `python3 scripts/train_bayes.py --holdout 2026-10-23` is the acceptance test: train only
 * on mail dated before the cut, score the later mail. LIMIT: the ham is mostly synthetic;
 * exportHamScores() (Maintenance.gs) measures the real kept mail from inside Gmail.
 * Keys are [a-z0-9_.-] only (the Python loader depends on it).
 */
// ===== BAYES TABLE (generated by scripts/train_bayes.py; do not edit by hand) BEGIN =====
let BAYES_RULE_ENABLED = true;
const BAYES_QUARANTINE_SCORE = 550;
const BAYES_TOP_K = 20;
const BAYES_TABLE = Object.freeze({
  'address': 27,
  'advertisement': 26,
  'albuquerque': 25,
  'already': 31,
  'america': 31,
  'american': 30,
  'americans': 29,
  'around': 26,
  'attention': 29,
  'ave': 28,
  'banks': 26,
  'behalf': 29,
  'behind': 29,
  'believe': 31,
  'blvd': 25,
  'broadway': 25,
  'brought': 30,
  'but': 27,
  'button': 29,
  'coming': 27,
  'companies': 26,
  'company': 33,
  'compensation': 27,
  'content': 31,
  'control': 27,
  'could': 38,
  'direct': 27,
  'distribution': 26,
  'dollar': 30,
  'down': 27,
  'driving': 25,
  'editor': 29,
  'education': 25,
  'finance': 30,
  'forms': 30,
  'global': 25,
  'good': 27,
  'government': 30,
  'had': 26,
  'hidden': 28,
  'high': 29,
  'his': 25,
  'holding': 25,
  'images': 26,
  'inflation': 27,
  'informational': 25,
  'inside': 27,
  'interest': 27,
  'investing': 31,
  'investment': 30,
  'investors': 31,
  'issues': 25,
  'known': 27,
  'legal': 25,
  'llc': 41,
  'long': 28,
  'longer': 28,
  'mail': 29,
  'mailto': 36,
  'make': 32,
  'making': 25,
  'markets': 32,
  'model': 25,
  'move': 27,
  'musk': 25,
  'nearly': 26,
  'offering': 25,
  'once': 27,
  'operator': 29,
  'opportunities': 26,
  'opportunity': 28,
  'owner': 29,
  'part': 30,
  'people': 27,
  'permission': 31,
  'physical': 26,
  'point': 25,
  'potential': 26,
  'president': 26,
  'provide': 27,
  'public': 27,
  'quietly': 26,
  'ratings': 26,
  'real': 26,
  'really': 25,
  'reproduction': 28,
  'risks': 27,
  'seen': 27,
  'services': 32,
  'set': 26,
  'shift': 25,
  'shocking': 26,
  'simply': 25,
  'some': 28,
  'sometimes': 25,
  'special': 28,
  'ste': 25,
  'tech': 27,
  'technologies': 32,
  'technology': 26,
  'terratrance': 25,
  'those': 25,
  'took': 25,
  'trade': 29,
  'traffic': 27,
  'trump': 31,
  'turning': 26,
  'unique': 28,
  'usa': 25,
  'used': 27,
  'users': 25,
  'valuable': 25,
  'war': 25,
  'wealth': 27,
  'weiss': 27,
  'whitelist': 25,
  'wilmington': 29,
  'wish': 27,
  'work': 27,
  'world': 31,
  'worth': 27,
});
// ===== BAYES TABLE END =====
