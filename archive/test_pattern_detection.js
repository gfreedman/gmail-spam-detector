#!/usr/bin/env node
/**
 * Test the pattern-based spam detection logic
 * This simulates the Google Apps Script logic in Node.js
 */

function detectSpam(email) {
  const subject = email.subject || '';
  const from = email.from || '';
  const headers = email.headers || '';

  // Pattern detection
  const signals = {
    bulkEmailService: false,
    clickbaitCount: 0,
    fearMongering: false,
    marketingFormat: false
  };

  // SIGNAL 1: Bulk email service
  if (headers.toLowerCase().includes('amazonses.com') ||
      headers.toLowerCase().includes('x-ses-') ||
      headers.toLowerCase().includes('sendgrid.net')) {
    signals.bulkEmailService = true;
  }

  // SIGNAL 2: Clickbait patterns
  const clickbaitPatterns = [
    /caught on camera/i,
    /warning:|exposed:|alert:/i,
    /(what|this).*(changes everything|stunned everyone)/i,
    /【.*】/,
    /💼|📸|⏯️/,
    /\?\?\?|!!!/
  ];

  clickbaitPatterns.forEach(pattern => {
    if (pattern.test(subject)) {
      signals.clickbaitCount++;
    }
  });

  // SIGNAL 3: Fear-mongering
  const fearKeywords = [
    'WARNING', 'EXPOSED', 'STOP Using', 'Blood Thinner Warning',
    'IRS', 'NSA', 'Bank Account', 'Government Hiding'
  ];

  fearKeywords.forEach(keyword => {
    if (subject.toUpperCase().includes(keyword.toUpperCase())) {
      signals.fearMongering = true;
    }
  });

  // SIGNAL 4: Marketing format
  if (/["|,]\s*[A-Z]/.test(from)) {
    signals.marketingFormat = true;
  }

  // DECISION LOGIC
  // RULE 1: Bulk email + 2+ clickbait
  if (signals.bulkEmailService && signals.clickbaitCount >= 2) {
    return { isSpam: true, reason: 'Bulk email + clickbait', signals };
  }

  // RULE 2: Bulk email + 2+ spam behaviors
  let spamBehaviorCount = 0;
  if (signals.clickbaitCount >= 2) spamBehaviorCount++;
  if (signals.fearMongering) spamBehaviorCount++;
  if (signals.marketingFormat) spamBehaviorCount++;

  if (signals.bulkEmailService && spamBehaviorCount >= 2) {
    return { isSpam: true, reason: `Bulk email + ${spamBehaviorCount} behaviors`, signals };
  }

  // RULE 3: Extreme clickbait
  if (signals.clickbaitCount >= 3) {
    return { isSpam: true, reason: 'Extreme clickbait', signals };
  }

  return { isSpam: false, reason: 'Insufficient signals', signals };
}

// TEST CASES

console.log('='='.repeat(80));
console.log('SPAM EXAMPLES (Should all be detected)');
console.log('='.repeat(80));

const spamExamples = [
  {
    subject: 'WARNING: NSA Spied on Millions -【January 11, 2026】',
    from: 'Tony Snyder | BJ <daily@bjj.budgetingjournals.com>',
    headers: 'Return-Path: <0100019baeb95031@amazonses.com>'
  },
  {
    subject: '📸 Caught on Camera: Russian Drones Hit Poland',
    from: '"Russian Drones, Smart Investment Tools" <grow@smartinvestmenttools.com>',
    headers: 'X-SES-Outgoing: 2026.01.11'
  },
  {
    subject: 'Tesla Caught THIS on Camera — and It Changes Everything',
    from: 'Tesla driving footage - Tony | BJ <daily@bjj.com>',
    headers: 'amazonses.com'
  }
];

spamExamples.forEach((email, i) => {
  const result = detectSpam(email);
  const status = result.isSpam ? '✅ SPAM' : '❌ MISS';
  console.log(`\n${status} #${i + 1}`);
  console.log(`  Subject: ${email.subject.substring(0, 60)}`);
  console.log(`  Reason: ${result.reason}`);
  console.log(`  Signals: SES=${result.signals.bulkEmailService}, Clickbait=${result.signals.clickbaitCount}, Fear=${result.signals.fearMongering}, Marketing=${result.signals.marketingFormat}`);
});

console.log('\n' + '='.repeat(80));
console.log('LEGITIMATE EXAMPLES (Should NOT be detected)');
console.log('='.repeat(80));

const hamExamples = [
  {
    subject: 'Your order has shipped',
    from: 'Amazon <no-reply@amazon.com>',
    headers: 'Return-Path: <bounce@amazon.com>'
  },
  {
    subject: 'Weekly Newsletter - Product Updates',
    from: 'Company Newsletter <newsletter@company.com>',
    headers: 'X-SES-Outgoing: 2026.01.11'  // Uses SES but not spammy
  },
  {
    subject: 'I want to connect',
    from: 'John Doe <invitations@linkedin.com>',
    headers: 'Return-Path: <bounce@linkedin.com>'
  },
  {
    subject: 'Your claim has been received',
    from: 'Insurance Co <eob@insurance.com>',
    headers: 'Return-Path: <bounce@insurance.com>'
  }
];

hamExamples.forEach((email, i) => {
  const result = detectSpam(email);
  const status = result.isSpam ? '❌ FALSE POSITIVE' : '✅ OK';
  console.log(`\n${status} #${i + 1}`);
  console.log(`  Subject: ${email.subject.substring(0, 60)}`);
  console.log(`  Reason: ${result.reason}`);
  console.log(`  Signals: SES=${result.signals.bulkEmailService}, Clickbait=${result.signals.clickbaitCount}, Fear=${result.signals.fearMongering}, Marketing=${result.signals.marketingFormat}`);
});

console.log('\n' + '='.repeat(80));
