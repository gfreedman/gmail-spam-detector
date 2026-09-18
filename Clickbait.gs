

// =============================================================================
// Normalization
// =============================================================================

/**
 * Matches RFC 2822 quoted display names: `"Name" <email@domain>`
 *
 * The email standard allows display names to be wrapped in quotes. This regex
 * strips them so pattern matching always sees: `Name <email@domain>`
 *
 * Capture groups:
 *   $1 — display name content (handles escaped chars like \")
 *   $2 — the <email@address> portion
 *
 * Usage: from.replace(RFC2822_QUOTED_NAME, '$1$2')
 *
 * @const {RegExp}
 */
const RFC2822_QUOTED_NAME = /^"((?:[^"\\]|\\.)*)"(\s*<[^>]*>)$/;


// =============================================================================
// Detection Patterns
//
// Defined at module level so RegExp objects are compiled once, not on every
// call to analyzeMessage(). Each array is frozen to prevent accidental mutation.
// =============================================================================

// ── ReDoS safety analysis ────────────────────────────────────────────────────
// All patterns below (and in BODY_CRYPTO_PATTERNS, FEAR_PATTERNS, etc.) are
// checked against inputs that have been truncated to LIMITS.maxInputChars
// (100KB) by sanitizeInput(). Within that bound:
//
//   No nested quantifiers: no pattern uses constructs like /(a+)+/ or /(ab*)+/
//   that cause exponential backtracking. All quantifiers operate on single-width
//   atoms, character classes, or fixed-length alternations.
//
//   Alternation groups like /(foo|bar|baz)/ are anchored with \b or surrounded
//   by literal characters, preventing catastrophic backtracking on near-misses.
//   Example: /\b(warning|alert|urgent)\b/i fails immediately at a word boundary
//   rather than exploring all alternation paths on a mismatch.
//
//   Unicode range patterns like /[\u0400-\u04FF]/ scan linearly — O(n) with
//   no backtracking. They are always standalone character classes.
//
//   Estimated worst-case runtime: 100KB × ~50 patterns × ~1μs/KB ≈ 5ms/email.
//   This is well within the Apps Script 6-minute per-trigger budget even at
//   the maximum 50-email-per-run limit.
//
// The anchor scan (extractAnchors, used by Signal 7) is a SEPARATE cost class
// that this analysis does not cover, because it does not live in these pattern
// arrays and runs against the untruncated HTML body.
// It is bounded independently and deliberately:
//
//   It does NOT use a paired-tag regex. /<a[^>]*>([\s\S]*?)<\/a>/g is
//   polynomial in (anchor count × document length): an <a> with no closing
//   </a> — which mail clients tolerate, so attackers can emit them freely —
//   makes the engine scan to end-of-document before failing. 900 unclosed
//   anchors in a 4MB body is ~3e9 character steps, tens of seconds. Instead
//   the open tag is matched with a bounded regex and the close is found with
//   String.indexOf(), a native linear scan with no backtracking.
//
//   Every quantifier in the anchor and href patterns is explicitly bounded
//   ({0,2000}), so a malformed tag missing its '>' cannot walk the document.
//
//   Three LIMITS cap the work: maxHtmlScanChars (256KB scanned — this is the
//   real bound now that the untruncated body is passed in),
//   maxAnchorsScanned (300 anchors), maxAnchorTextChars (2KB per anchor).
//   Measured: 900 unclosed anchors in 5ms; a 500KB body in under 1ms.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Clickbait / sensationalism patterns — checked against subject + from concatenated.
 *
 * Each pattern targets a CATEGORY of spam tactic, not a specific phrase.
 * Example: the "shock words" pattern catches "shocking", "stunning", "bizarre", etc.
 * Spammers rotate specific words constantly, but they can't change their tactics —
 * sensationalism is how they make money. We detect the tactic, not the words.
 *
 * Each matching pattern increments clickbaitCount independently, which feeds:
 *   - Rule 2: bulk + 2+ clickbait patterns → spam
 *   - Rule 4: 3+ clickbait patterns (even without bulk email) → spam
 *
 * @const {Array<RegExp>}
 */
const CLICKBAIT_PATTERNS = Object.freeze([
  // --- Sensationalist language ---

  // Shock/sensation adjectives: "shocking admission", "bizarre discovery"
  /\b(shocking|stunning|bizarre|mysterious|secret|hidden|leaked|exposed|forbidden|bombshell)\b/i,

  // Terrifying/alarming adjectives (often stuffed into From display names)
  /\b(terrifying|alarming|devastating|horrifying|frightening|chilling|disturbing)\b/i,

  // Curiosity gap: mystery word + visual/media word ("secret photo", "leaked footage")
  /(strange|secret|hidden|mysterious|shocking|bizarre|unusual|leaked).*(picture|photo|image|video|camera|footage|document)/i,

  // Urgency + sensationalism: "breaking news", "urgent warning"
  /(breaking|urgent|warning|alert|stop|exposed|banned).*(news|truth|secret|scandal|exposed|revealed)/i,

  // Financial fear-mongering: market/money word + crisis word
  /(market|stock|economy|dollar|gold|bitcoin|investment|crypto).*(crash|collapse|shift|crisis|warning|alert|plunge|tank|dying)/i,

  // "Caught" visual-proof framing: "caught on camera", "caught red-handed"
  /caught (on|doing|in|red-handed)/i,

  // Transformation clickbait: "this changes everything", "what stunned everyone"
  /(what|this).*(changes everything|stunned everyone|shocked|amazed|surprised)/i,

  // --- Celebrity / political name-dropping ---

  // Celebrity credibility theft: "RFK Jr Issues Warning", "Musk Exposes", "MAHA report"
  // MAHA = "Make America Healthy Again" — RFK Jr.'s health initiative, used to brand health spam
  /\b(RFK|MAHA|Trump|Biden|Musk|Elon|Kennedy|Obama|Fauci|Gates)\b.*(warning|says|reveals|exposes|issues|predicts|warns|showed|shows|report)\b/i,

  // Political legitimization: "Trump approved/signed/backed [product]"
  // Spammers use political figures to give fake authority to financial pitches
  /\b(Trump|Biden|Obama|Musk|Kennedy|RFK)\b.*(approved|signed|backed|endorsed|directed|ordered|mandated)/i,

  // Celebrity merchandise/collectible scams: "Trump Coin", "Biden Medal"
  /\b(Trump|Biden|Obama|Kennedy)\b.*(coin|bill|medal|card|stamp|legacy|commemorat|collect|mint|gold|silver)/i,

  // --- Demographic and temporal targeting ---

  // Age-based fear: "Seniors Most At Risk", "If you're over 60"
  /\b(seniors?|elderly|retirees?|boomers?|over \d{2}|born before|age \d{2})\b.*(risk|warning|alert|danger|affected|target)/i,

  // Year-based urgency: current year + threat word for fake timeliness
  /\b202[4-9]\b.*(warning|alert|prediction|forecast|crisis)/i,

  // Conspiracy/hiding: "what they don't want you to know"
  /(what|who).*(hiding|don't want you|truth|they won't tell)/i,

  // Suppression conspiracy: "watch before this gets buried/removed/deleted"
  // Classic spam tactic — false urgency implying authority is hiding the content
  /\b(watch|read|see)\b.*(before this|before it).*(buried|removed|deleted|censored|banned|taken down)/i,

  // Impending doom framing: "What's Coming", "Not Prepared for what's ahead"
  /\bwhat.s (coming|ahead)\b|\bnot prepared\b/i,

  // --- Violence and military sensationalism ---

  // Military/war clickbait: "declared war", "bombing", "invasion", "attacking our"
  /\b(declared war|bombed|bombing|attacks?|attacking|attacked|destroyed|invasion)\b/i,

  // --- Financial hype ---

  // Pre-IPO investment solicitation: always spam in bulk email
  /\bpre-?ipo\b/i,

  // Stock price hype: "$5 a share", "$0.85 per share", "$0.72/share", "penny stock"
  /\$\d+(\.\d+)?(?:\s+(?:a|per)\s+|[\s\/]+)?share|\bpenny stock\b/i,

  // Watch/see curiosity gap: "watch what happened", "see this"
  /\b(watch|see)\s+(what|this|the moment)/i,

  // --- Structural / formatting indicators ---

  /【.*】/,           // Japanese-style brackets (spammer formatting tactic)
  /\[.{3,}[?!]\]/,    // Square brackets with punctuation: [Like This?]
  /💼|📸|⏯️|🚨|⚠️|📰|💰|⚡|🔐/,  // Sensationalist emoji cluster (🔐 = phishing "security notice" decoration)
  /\?\?\?|!!!/,       // Triple punctuation (urgency tactic)
  /\u2026|\.{3,}/,    // Ellipsis dramatic pause (Unicode … or ASCII ...)
  /\bWATCH\b.*\?$/i,  // "WATCH ...?" clickbait structure

  // --- Unicode obfuscation (filter evasion) ---

  /[\u0400-\u04FF]/,  // Cyrillic lookalikes: "Еlоn" with Cyrillic Е, о
  /[\u0370-\u03FF]/,  // Greek lookalikes: "Βanks" with Greek Β
  /[\uFF00-\uFFEF]/,  // Fullwidth chars: "＄2 Bill" — never legit in English
  // JS strings are UTF-16. Mathematical alphanumeric chars (U+1D400–U+1D7FF,
  // e.g. "𝗔𝗺𝗮𝘇𝗼𝗻") are encoded as surrogate pairs whose high surrogate is
  // always \uD835. Matching it catches all math bold/italic chars in one shot.
  // (Python uses \U0001D400-\U0001D7FF instead — same coverage, different encoding model.)
  /\uD835/,

  // --- Topic-specific spam categories ---

  // Jobs/employment fear: "jobs disappeared", "layoffs"
  /\b(jobs?|employment).*(disappeared|vanished|never existed|fake|fraud|layoffs?)/i,

  // Bank/branch closing fear: "banks closing", "ATMs shutting down"
  /\b(banks?|branch|branches|ATMs?).*(clos|shut|disappear|eliminat)/i,

  // Building/institution emoji (banks, hospitals, government)
  /🏦|🏥|🏛️|🏢/,

  // Collectible/commemorative scams: "limited edition", "rare coin"
  /\b(minted|commemorat|collector'?s?|limited edition|rare coin|gold.?plated|silver.?plated)\b/i,

  // Bullet-point date format: "• January 29 •" (newsletter spam tactic)
  /•\s*(January|February|March|April|May|June|July|August|September|October|November|December)\b/i,

  // Pipe-date subject format: "| February 23" (same tactic, pipe variant)
  /\|\s*(January|February|March|April|May|June|July|August|September|October|November|December)\b/i,

  // Bracket-date subject format: "[March 09]" — same tactic, bracket variant
  /\[\s*(January|February|March|April|May|June|July|August|September|October|November|December)\b/i,

  // Dash-date subject format: "- Mar 11, 2026" — same tactic, dash variant with abbreviated months
  /[-]\s*(Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\b/i,

  // Historical atrocity clickbait: Nazi/Holocaust references as engagement bait
  /\b(nazi|hitler|auschwitz|gestapo|mengele|third reich)\b/i,

  // Health condition anxiety triggers: "blood sugar", "brain fog"
  /\b(fatigue|insomnia|inflammation|blood sugar|cholesterol|blood pressure|joint pain|brain fog|belly fat)\b/i,

  // Numbered-threat framing: "#1 danger", "#1 killer", "the #1 cause of"
  // Common in health/diet spam — e.g. "This Toxic Vegetable Is The #1 Danger In Your Diet"
  /#\s*1\s*(danger|killer|risk|threat|cause|reason|enemy|mistake)/i,

  // Financial scam products: gift cards, tax liens, instant approval
  /\b(gift card|tax lien|tax sale|foreclosure list|pre-?approved|instant approval|no annual fee)\b/i,

  // "Now you can see/watch" exclusive access clickbait
  /\bnow you can (see|watch|view|get)\b/i,

  // Unicode punctuation obfuscation (lookalike slash characters)
  // U+2215 DIVISION SLASH, U+2044 FRACTION SLASH, U+29F8 BIG SOLIDUS
  /[\u2215\u2044\u29F8]/,

  // Financial product solicitation: "0% APR", "balance transfer"
  /\b(0\s*%\s*(interest|apr)|balance transfer|transfer your.*(balance|debt))\b/i,

  // Crypto quantity notation: "5000.00 $CLAW", "100 $USDT" — airdrop/ICO spam
  // Legitimate financial email writes "$5000", not "5000 $TICKER"
  /\b\d+(?:\.\d+)?\s+\$[A-Z]{4,}\b/,

  // Income opportunity lures: "second income", "passive income", "extra income"
  // Classic financial spam framing — promises of easy additional money
  /\b(second|extra|side|passive|additional|supplemental)\s+income\b/i,

  // Political looting narrative: "America was ripped off", "looted for decades"
  // Combines populist outrage framing with financial pitches (tariff rebate checks, etc.)
  /\b(ripped off|looted|robbed|bilked)\b/i,

  // Payback / revenge framing: "payback time" — common in political-financial scam emails
  // alongside looting narrative framing; both patterns fire independently
  /\bpayback time\b/i
]);
