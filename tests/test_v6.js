#!/usr/bin/env node
/**
 * Test script for SpamDetector v6.7
 * Tests all spam examples against the detection patterns
 */

const fs = require('fs');
const path = require('path');

// Clickbait patterns (same as SpamDetector.gs v6.7)
const clickbaitPatterns = [
  // v6.7: Added "bombshell"
  /\b(shocking|stunning|bizarre|mysterious|secret|hidden|leaked|exposed|forbidden|bombshell)\b/i,
  /\b(terrifying|alarming|devastating|horrifying|frightening|chilling|disturbing)\b/i,
  /(strange|secret|hidden|mysterious|shocking|bizarre|unusual|leaked).*(picture|photo|image|video|camera|footage|document)/i,
  /(breaking|urgent|warning|alert|stop|exposed|banned).*(news|truth|secret|scandal|exposed|revealed)/i,
  /(market|stock|economy|dollar|gold|bitcoin|investment|crypto).*(crash|collapse|shift|crisis|warning|alert|plunge|tank)/i,
  /caught (on|doing|in|red-handed)/i,
  /(what|this).*(changes everything|stunned everyone|shocked|amazed|surprised)/i,
  // v6.7: Added "showed|shows"
  /\b(RFK|Trump|Biden|Musk|Elon|Kennedy|Obama|Fauci|Gates)\b.*(warning|says|reveals|exposes|issues|predicts|warns|showed|shows)/i,
  // v6.2: Celebrity merchandise/collectible scam
  /\b(Trump|Biden|Obama|Kennedy)\b.*(coin|bill|medal|card|stamp|legacy|commemorat|collect|mint|gold|silver)/i,
  /\b(seniors?|elderly|retirees?|boomers?|over \d{2}|born before|age \d{2})\b.*(risk|warning|alert|danger|affected|target)/i,
  /\b202[4-9]\b.*(warning|alert|prediction|forecast|crisis)/i,
  // v6.0: Conspiracy/hiding pattern
  /(what|who).*(hiding|don't want you|truth|they won't tell)/i,
  // v6.0: Military/war sensationalism
  /\b(declared war|bombed|bombing|attack|attacked|destroyed|invasion)\b/i,
  // v6.0: Stock price hype
  /\$\d+(\.\d+)?\s*(a\s+)?share|\bpenny stock\b/i,
  // v6.0: Watch/see curiosity gap
  /\b(watch|see)\s+(what|this|the moment)/i,
  // Structural indicators
  /【.*】/,
  /\[.{3,}[?!]\]/,
  /💼|📸|⏯️|🚨|⚠️|📰|💰|⚡/,
  /\?\?\?|!!!/,
  /\bWATCH\b.*\?$/i,
  // v6.0: Cyrillic obfuscation
  /[\u0400-\u04FF]/,
  // v6.1: Greek obfuscation
  /[\u0370-\u03FF]/,
  // v6.2: Fullwidth obfuscation
  /[\uFF00-\uFFEF]/,
  // v6.0: Jobs/employment fear
  /\b(jobs?|employment).*(disappeared|vanished|never existed|fake|fraud|layoffs?)/i,
  // v6.1: Bank/branch closing fear
  /\b(banks?|branch|branches|ATMs?).*(clos|shut|disappear|eliminat)/i,
  // v6.1: Building/institution emoji
  /🏦|🏥|🏛️|🏢/,
  // v6.2: Collectible/commemorative scam category
  /\b(minted|commemorat|collector'?s?|limited edition|rare coin|gold.?plated|silver.?plated)\b/i,
  // v6.7: Mathematical Unicode obfuscation (𝗔𝗺𝗮𝘇𝗼𝗻 instead of Amazon)
  /\uD835/,
  // v6.7: Bullet-point date format (• January 29 •)
  /•\s*(January|February|March|April|May|June|July|August|September|October|November|December)\b/i,
  // v6.7: Historical atrocity clickbait
  /\b(nazi|hitler|auschwitz|gestapo|mengele|third reich)\b/i,
  // v6.7: Health condition clickbait words
  /\b(fatigue|insomnia|inflammation|blood sugar|cholesterol|blood pressure|joint pain|brain fog|belly fat)\b/i,
  // v6.7: Financial scam product categories
  /\b(gift card|tax lien|tax sale|foreclosure list|pre-?approved|instant approval|no annual fee)\b/i,
  // v6.7: "Now you can see/watch" exclusive access clickbait
  /\bnow you can (see|watch|view|get)\b/i
];

// v6.0 Fear patterns (same as SpamDetector.gs)
const fearPatterns = [
  /\b(IRS|NSA|FBI|CIA|government|federal)\b.*(warn|hiding|secret|spy|track|audit|investigation|admission|reveal|expose|confiscat)/i,
  /\b(banks?|bank account|credit card|social security|identity|savings|cash|money)\b.*(seize|steal|stolen|hacked|freeze|frozen|close|closed|warning|alert|confiscat|take|taking|lost)/i,
  /\b(blood thinner|medication|drug|vaccine|doctor|FDA|health crisis|at risk)\b.*(warning|danger|deadly|killing|risk|avoid|corrupt)/i,
  /\b(warning|alert|urgent|breaking|exposed|banned|stopped)\b/i,
  /\bSTOP (using|taking|doing|buying)\b/i
];

// Marketing format patterns (v6.0 expanded)
const marketingPatterns = [
  /["|,]\s*[A-Z]/i,
  /\s+at\s+[A-Z]/i,
  /\|\s*/,
  /\b(investment|trading|wealth|profit|finance|insider|market)\s*(tools?|pro|tips?|alert)/i,
  /grow@with\./i,
  /@[a-z]\.[a-z]+\.(com|net)/i
];

/**
 * Decode RFC 2047 encoded-word (=?charset?encoding?text?=)
 * Properly handles multi-byte UTF-8 sequences in Q-encoding
 */
function decodeRfc2047(str)
{
  if (!str) return '';
  return str.replace(/=\?([^?]+)\?([BQ])\?(.*?)\?=/gi, (match, charset, encoding, text) =>
  {
    if (encoding.toUpperCase() === 'B')
    {
      // Base64 encoding
      return Buffer.from(text, 'base64').toString('utf-8');
    }
    // Q-encoding: collect raw bytes, then decode as UTF-8
    const decoded = text.replace(/_/g, ' ');
    const bytes = [];
    let i = 0;
    while (i < decoded.length)
    {
      if (decoded[i] === '=' && i + 2 < decoded.length)
      {
        bytes.push(parseInt(decoded.substring(i + 1, i + 3), 16));
        i += 3;
      }
      else
      {
        bytes.push(decoded.charCodeAt(i));
        i++;
      }
    }
    return Buffer.from(bytes).toString('utf-8');
  });
}

function parseEml(content)
{
  const lines = content.split('\n');
  let subject = '';
  let from = '';
  let hasAmazonSES = content.toLowerCase().includes('amazonses.com') ||
                     content.toLowerCase().includes('sendgrid.net');

  // Parse headers with continuation line support (lines starting with whitespace)
  let currentHeader = '';
  let currentValue = '';

  for (const line of lines)
  {
    // Empty line = end of headers
    if (line.trim() === '') break;

    // Continuation line (starts with whitespace)
    if (/^\s/.test(line) && currentHeader)
    {
      currentValue += ' ' + line.trim();
    }
    else
    {
      // Save previous header
      if (currentHeader === 'subject') subject = currentValue;
      if (currentHeader === 'from') from = currentValue;

      // Parse new header
      const colonIdx = line.indexOf(':');
      if (colonIdx > 0)
      {
        currentHeader = line.substring(0, colonIdx).toLowerCase();
        currentValue = line.substring(colonIdx + 1).trim();
      }
    }
  }
  // Save last header
  if (currentHeader === 'subject') subject = currentValue;
  if (currentHeader === 'from') from = currentValue;

  // Decode RFC 2047 encoded words
  subject = decodeRfc2047(subject);
  from = decodeRfc2047(from);

  return { subject, from, hasAmazonSES };
}

function analyzeEmail(subject, from, hasAmazonSES)
{
  const signals = {
    bulkEmailService: hasAmazonSES,
    clickbaitCount: 0,
    fearMongering: false,
    marketingFormat: false,
    matchedPatterns: []
  };

  const textToCheck = subject + ' ' + from;

  // Check clickbait patterns
  for (let i = 0; i < clickbaitPatterns.length; i++)
  {
    if (clickbaitPatterns[i].test(textToCheck))
    {
      signals.clickbaitCount++;
      signals.matchedPatterns.push(`clickbait[${i}]: ${clickbaitPatterns[i]}`);
    }
  }

  // Check fear patterns
  for (let i = 0; i < fearPatterns.length; i++)
  {
    if (fearPatterns[i].test(textToCheck))
    {
      signals.fearMongering = true;
      signals.matchedPatterns.push(`fear[${i}]: ${fearPatterns[i]}`);
      break;
    }
  }

  // Check marketing format (v6.0: multiple patterns)
  for (let i = 0; i < marketingPatterns.length; i++)
  {
    if (marketingPatterns[i].test(from))
    {
      signals.marketingFormat = true;
      signals.matchedPatterns.push('marketing format');
      break;
    }
  }

  // Decision logic
  let isSpam = false;
  let rule = '';

  if (signals.bulkEmailService && signals.clickbaitCount >= 2)
  {
    isSpam = true;
    rule = 'RULE 1: Bulk + 2+ clickbait';
  }
  else
  {
    let behaviorCount = 0;
    if (signals.clickbaitCount >= 1) behaviorCount++;
    if (signals.fearMongering) behaviorCount++;
    if (signals.marketingFormat) behaviorCount++;

    if (signals.bulkEmailService && behaviorCount >= 2)
    {
      isSpam = true;
      rule = 'RULE 2: Bulk + 2+ behaviors';
    }
    else if (signals.bulkEmailService && signals.marketingFormat &&
               (signals.clickbaitCount >= 1 || signals.fearMongering))
    {
      isSpam = true;
      rule = 'RULE 3: Bulk + marketing + warning';
    }
    else if (signals.clickbaitCount >= 3)
    {
      isSpam = true;
      rule = 'RULE 4: Extreme clickbait';
    }
  }

  return { signals, isSpam, rule };
}

// Main test
const spamDir = path.join(__dirname, 'spam_examples');
const files = fs.readdirSync(spamDir).filter(f => f.endsWith('.eml'));

console.log('='.repeat(80));
console.log('SpamDetector v6.7 Test Results');
console.log('='.repeat(80));
console.log(`Testing ${files.length} spam examples...\n`);

let passed = 0;
let failed = 0;
const failures = [];

for (const file of files)
{
  const content = fs.readFileSync(path.join(spamDir, file), 'utf-8');
  const { subject, from, hasAmazonSES } = parseEml(content);
  const { signals, isSpam, rule } = analyzeEmail(subject, from, hasAmazonSES);

  if (isSpam)
  {
    passed++;
    console.log(`✅ PASS: ${file.substring(0, 60)}...`);
    console.log(`   Subject: ${subject.substring(0, 60)}`);
    console.log(`   Rule: ${rule}`);
    console.log(`   Signals: bulk=${signals.bulkEmailService}, clickbait=${signals.clickbaitCount}, fear=${signals.fearMongering}, marketing=${signals.marketingFormat}`);
    console.log('');
  }
  else
  {
    failed++;
    failures.push({ file, subject, from, signals });
    console.log(`❌ FAIL: ${file}`);
    console.log(`   Subject: ${subject}`);
    console.log(`   From: ${from}`);
    console.log(`   Signals: bulk=${signals.bulkEmailService}, clickbait=${signals.clickbaitCount}, fear=${signals.fearMongering}, marketing=${signals.marketingFormat}`);
    console.log(`   Matched: ${signals.matchedPatterns.join(', ') || 'NONE'}`);
    console.log('');
  }
}

console.log('='.repeat(80));
console.log('SUMMARY');
console.log('='.repeat(80));
console.log(`Total: ${files.length}`);
console.log(`Passed: ${passed} (${(passed/files.length*100).toFixed(1)}%)`);
console.log(`Failed: ${failed} (${(failed/files.length*100).toFixed(1)}%)`);

if (failures.length > 0)
{
  console.log('\n❌ FAILURES:');
  for (const f of failures)
  {
    console.log(`  - ${f.file}`);
    console.log(`    Subject: ${f.subject}`);
  }
  process.exit(1);
}
else
{
  console.log('\n🎉 ALL SPAM DETECTED SUCCESSFULLY!');
  process.exit(0);
}
