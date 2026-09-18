

// =============================================================================
// Setup and Initialization
// =============================================================================

/**
 * One-time setup function — run manually to authorize the script and
 * initialize Script Properties with default domain lists.
 *
 * After running, set up a time-driven trigger:
 *   Triggers > Add Trigger > processInbox > Time-driven > Every 10 minutes
 *
 * @throws {Error} If configuration validation or label creation fails.
 */
function setup()
{
  try
  {
    logInfo('Setting up spam detector...');

    // Validate configuration before proceeding
    validateConfig();

    // Create the "SpamChecked" label for tracking processed emails
    getOrCreateLabel(CONFIG.processedLabel);

    // Write default whitelist/blacklist to Script Properties (if not already set)
    initializeScriptProperties();

    logInfo('Setup complete! Now:');
    logInfo('  1. Run setupLogging() to enable spam intelligence logging (Drive + Sheets).');
    logInfo('  2. Set up a time-based trigger: Triggers > Add Trigger > processInbox > Time-driven > Every 10 minutes');
  }
  catch (error)
  {
    logError('Setup failed: ' + error.toString());
    throw error;
  }
}

/**
 * Initialize Script Properties with default whitelist and blacklist.
 *
 * Only writes defaults if the properties don't exist yet — subsequent calls
 * are no-ops. This preserves any manual additions made via addToWhitelist()
 * or addToBlacklist() after initial setup.
 */
function initializeScriptProperties()
{
  const props = PropertiesService.getScriptProperties();

  // Initialize whitelist if not yet created
  if (!props.getProperty('LEGITIMATE_DOMAINS'))
  {
    const defaultWhitelist = Array.from(DEFAULT_DOMAINS.legitimate);
    props.setProperty('LEGITIMATE_DOMAINS', JSON.stringify(defaultWhitelist));
    logInfo('Initialized whitelist with ' + defaultWhitelist.length + ' domains');
  }

  // Initialize blacklist if not yet created
  if (!props.getProperty('SUSPICIOUS_DOMAINS'))
  {
    const defaultBlacklist = Array.from(DEFAULT_DOMAINS.suspicious);
    props.setProperty('SUSPICIOUS_DOMAINS', JSON.stringify(defaultBlacklist));
    logInfo('Initialized blacklist with ' + defaultBlacklist.length + ' domains');
  }
}
