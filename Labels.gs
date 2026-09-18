

// =============================================================================
// Label Management
// =============================================================================

/**
 * Get or create a Gmail label by name.
 *
 * Used to manage the "SpamChecked" label that tracks which emails have
 * already been processed. Creates the label on first run.
 *
 * @param {string} labelName - Name of the label to get or create.
 * @return {GmailLabel} The Gmail label object.
 * @throws {Error} If label creation fails (e.g., auth issue).
 */
function getOrCreateLabel(labelName)
{
  try
  {
    let label = GmailApp.getUserLabelByName(labelName);
    if (!label)
    {
      label = GmailApp.createLabel(labelName);
      logInfo('Created new label: ' + labelName);
    }
    return label;
  }
  catch (error)
  {
    logError('Error getting/creating label: ' + error.toString());
    throw error;
  }
}


// =============================================================================
// Configuration Validation
// =============================================================================

/**
 * Validate all CONFIG values are within acceptable ranges.
 *
 * Called at the start of processInbox() to fail fast before doing any work.
 * Catches misconfiguration that could cause silent misbehavior (e.g.,
 * maxEmailsPerRun of 0 would process nothing without any error).
 *
 * @throws {Error} If any configuration value is out of range.
 */
function validateConfig()
{
  if (CONFIG.maxEmailsPerRun < 1 || CONFIG.maxEmailsPerRun > LIMITS.maxAllowedEmailsPerRun)
  {
    throw new Error('Invalid maxEmailsPerRun: must be between 1 and ' + LIMITS.maxAllowedEmailsPerRun);
  }

  if (CONFIG.daysToCheck < 0 || CONFIG.daysToCheck > LIMITS.maxAllowedDaysToCheck)
  {
    throw new Error('Invalid daysToCheck: must be between 0 and ' + LIMITS.maxAllowedDaysToCheck);
  }

  if (!CONFIG.processedLabel || CONFIG.processedLabel.length === 0)
  {
    throw new Error('Invalid processedLabel: must not be empty');
  }
}
