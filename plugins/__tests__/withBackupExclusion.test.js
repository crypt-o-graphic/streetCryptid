/* global describe, it, expect */
const { RES_XML } = require('../withBackupExclusion');

/**
 * Every rule set has to name every location store, because each one is consulted on its own:
 * API ≤ 30 reads `sc_backup_rules`, API 31+ reads the two sections of `sc_data_extraction_rules`
 * for cloud backup and device transfer separately. A rule missing from one of the three is a
 * backup path that still carries the history.
 *
 * `file/SQLite` is the one that was missing: expo-sqlite keeps every database under
 * `filesDir/SQLite`, not `databases/`, so the social, exploration and telemetry-journal
 * databases all went to the cloud while `databases/` was excluded.
 */
const REQUIRED = [
  '<exclude domain="sharedpref" path="SecureStore.xml" />',
  '<exclude domain="file" path="streetcryptid" />',
  '<exclude domain="file" path="SQLite" />',
];

function section(xml, tag) {
  const match = xml.match(new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`));
  if (!match) throw new Error(`no <${tag}> section`);
  return match[1];
}

describe('withBackupExclusion rules', () => {
  const sets = {
    'full-backup-content': section(RES_XML.sc_backup_rules, 'full-backup-content'),
    'cloud-backup': section(RES_XML.sc_data_extraction_rules, 'cloud-backup'),
    'device-transfer': section(RES_XML.sc_data_extraction_rules, 'device-transfer'),
  };

  for (const [name, body] of Object.entries(sets)) {
    it.each(REQUIRED)(`${name} excludes %s`, (rule) => {
      expect(body).toContain(rule);
    });
  }
});
