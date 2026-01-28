#!/usr/bin/env node
/**
 * Test script for SpamDetector v6.0
 * Tests all spam examples against the new detection patterns
 */

const fs = require('fs');
const path = require('path');

// v6.0 Clickbait patterns (same as SpamDetector.gs)
const clickbaitPatterns = [
  /\b(shocking|stunning|bizarre|mysterious|secret|hidden|leaked|exposed|forbidden)\b/i,
  /\b(terrifying|alarming|devastating|horrifying|frightening|chilling|disturbing)\b/i,
  /(strange|secret|hidden|mysterious|shocking|bizarre|unusual|leaked).*(picture|photo|image|video|camera|footage|document)/i,
  /(breaking|urgent|warning|alert|stop|exposed|banned).*(news|truth|secret|scandal|exposed|revealed)/i,
  /(market|stock|economy|dollar|gold|bitcoin|investment|crypto).*(crash|collapse|shift|crisis|warning|alert|plunge|tank)/i,
  /caught (on|doing|in|red-handed)/i,
  /(what|this).*(changes everything|stunned everyone|shocked|amazed|surprised)/i,
  /\b(RFK|Trump|Biden|Musk|Elon|Kennedy|Obama|Fauci|Gates)\b.*(warning|says|reveals|exposes|issues|predicts|warns)/i,
  /\b(seniors?|elderly|retirees?|boomers?|over \d{2}|born before|age \d{2})\b.*(risk|warning|alert|danger|affected|target)/i,
  /\b202[4-9]\b.*(warning|alert|prediction|forecast|crisis)/i,
  /【.*】/,
  /\[.{3,}[?!]\]/,
  /[💼📸⏯️🚨⚠️📰💰]/,
  /\?\?\?|!!!/,
  /\bWATCH\b.*\?$/i
];

// v6.0 Fear patterns (same as SpamDetector.gs)
const fearPatterns = [
  /\b(IRS|NSA|FBI|CIA|government|federal)\b.*(warn|hiding|secret|spy|track|audit|investigation|admission|reveal|expose|confiscat)/i,
  /\b(banks?|bank account|credit card|social security|identity|savings|cash|money)\b.*(seize|steal|stolen|hacked|freeze|frozen|close|closed|warning|alert|confiscat|take|taking|lost)/i,
  /\b(blood thinner|medication|drug|vaccine|doctor|FDA|health crisis|at risk)\b.*(warning|danger|deadly|killing|risk|avoid|corrupt)/i,
  /\b(warning|alert|urgent|breaking|exposed|banned|stopped)\b/i,
  /\bSTOP (using|taking|doing|buying)\b/i
];

// Marketing format pattern
const marketingPattern = /["|,]\s*[A-Z]|(\s+at\s+[A-Z])|\|\s*/i;

function parseEml(content) {
  const lines = content.split('\n');
  let subject = '';
  let from = '';
  let hasAmazonSES = content.toLowerCase().includes('amazonses.com') ||
                     content.toLowerCase().includes('sendgrid.net');

  for (const line of lines) {
    if (line.toLowerCase().startsWith('subject:')) {
      // Handle multi-line encoded subjects
      subject = line.substring(8).trim();
      // Decode UTF-8 encoded subjects
      subject = subject.replace(/=\?UTF-8\?Q\?(.*?)\?=/gi, (match, p1) => {
        return p1.replace(/=([0-9A-F]{2})/gi, (m, hex) =>
          String.fromCharCode(parseInt(hex, 16))
        ).replace(/_/g, ' ');
      });
    }
    if (line.toLowerCase().startsWith('from:')) {
      from = line.substring(5).trim();
      // Decode UTF-8 encoded from
      from = from.replace(/=\?UTF-8\?Q\?(.*?)\?=/gi, (match, p1) => {
        return p1.replace(/=([0-9A-F]{2})/gi, (m, hex) =>
          String.fromCharCode(parseInt(hex, 16))
        ).replace(/_/g, ' ');
      });
    }
  }

  return { subject, from, hasAmazonSES };
}

function analyzeEmail(subject, from, hasAmazonSES) {
  const signals = {
    bulkEmailService: hasAmazonSES,
    clickbaitCount: 0,
    fearMongering: false,
    marketingFormat: false,
    matchedPatterns: []
  };

  const textToCheck = subject + ' ' + from;

  // Check clickbait patterns
  for (let i = 0; i < clickbaitPatterns.length; i++) {
    if (clickbaitPatterns[i].test(textToCheck)) {
      signals.clickbaitCount++;
      signals.matchedPatterns.push(`clickbait[${i}]: ${clickbaitPatterns[i]}`);
    }
  }

  // Check fear patterns
  for (let i = 0; i < fearPatterns.length; i++) {
    if (fearPatterns[i].test(textToCheck)) {
      signals.fearMongering = true;
      signals.matchedPatterns.push(`fear[${i}]: ${fearPatterns[i]}`);
      break;
    }
  }

  // Check marketing format
  if (marketingPattern.test(from)) {
    signals.marketingFormat = true;
    signals.matchedPatterns.push('marketing format');
  }

  // Decision logic
  let isSpam = false;
  let rule = '';

  if (signals.bulkEmailService && signals.clickbaitCount >= 2) {
    isSpam = true;
    rule = 'RULE 1: Bulk + 2+ clickbait';
  } else {
    let behaviorCount = 0;
    if (signals.clickbaitCount >= 1) behaviorCount++;
    if (signals.fearMongering) behaviorCount++;
    if (signals.marketingFormat) behaviorCount++;

    if (signals.bulkEmailService && behaviorCount >= 2) {
      isSpam = true;
      rule = 'RULE 2: Bulk + 2+ behaviors';
    } else if (signals.bulkEmailService && signals.marketingFormat &&
               (signals.clickbaitCount >= 1 || signals.fearMongering)) {
      isSpam = true;
      rule = 'RULE 3: Bulk + marketing + warning';
    } else if (signals.clickbaitCount >= 3) {
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
console.log('SpamDetector v6.0 Test Results');
console.log('='.repeat(80));
console.log(`Testing ${files.length} spam examples...\n`);

let passed = 0;
let failed = 0;
const failures = [];

for (const file of files) {
  const content = fs.readFileSync(path.join(spamDir, file), 'utf-8');
  const { subject, from, hasAmazonSES } = parseEml(content);
  const { signals, isSpam, rule } = analyzeEmail(subject, from, hasAmazonSES);

  if (isSpam) {
    passed++;
    console.log(`✅ PASS: ${file.substring(0, 60)}...`);
    console.log(`   Subject: ${subject.substring(0, 60)}`);
    console.log(`   Rule: ${rule}`);
    console.log(`   Signals: bulk=${signals.bulkEmailService}, clickbait=${signals.clickbaitCount}, fear=${signals.fearMongering}, marketing=${signals.marketingFormat}`);
    console.log('');
  } else {
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

if (failures.length > 0) {
  console.log('\n❌ FAILURES:');
  for (const f of failures) {
    console.log(`  - ${f.file}`);
    console.log(`    Subject: ${f.subject}`);
  }
  process.exit(1);
} else {
  console.log('\n🎉 ALL SPAM DETECTED SUCCESSFULLY!');
  process.exit(0);
}
