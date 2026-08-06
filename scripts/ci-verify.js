'use strict';

// Required status check for backport pull requests.
//
// Re-runs the same real exploit the remediation agent ran locally, against the
// component as it exists in this pull request. The build fails unless the
// traversal is genuinely blocked. Nothing here trusts the agent — it trusts
// the proof.

const path = require('path');
const { runExploit } = require(path.join(__dirname, '..', 'lib', 'exploit'));

const PINNED_DESCRIBE = 'archive-utils v3.13 (pinned)';

function line(ok, label, detail) {
  const mark = ok ? 'PASS' : 'FAIL';
  console.log('  [' + mark + '] ' + label + (detail ? ' — ' + detail : ''));
  return ok;
}

(async () => {
  console.log('');
  console.log('CVE-2007-4559 backport verification');
  console.log('===================================');
  console.log('');

  let vulnerable;
  let candidate;
  try {
    vulnerable = require(path.join(__dirname, '..', 'lib', 'vulnerable-ref'));
  } catch (e) {
    console.error('Could not load lib/vulnerable-ref.js: ' + e.message);
    process.exit(1);
  }
  try {
    candidate = require(path.join(__dirname, '..', 'lib', 'component'));
  } catch (e) {
    line(false, 'Component compiles', e.message);
    console.log('');
    console.log('Verification failed. Nothing ships.');
    process.exit(1);
  }

  const results = [];

  results.push(line(true, 'Component compiles'));

  // Control: the known-vulnerable reference must still escape, otherwise the
  // exploit itself is broken and every other result is meaningless.
  const before = await runExploit(vulnerable.extract);
  results.push(
    line(
      before.escaped === true,
      'Exploit fires against the pre-patch reference',
      'escaped=' + before.escaped
    )
  );

  // Signature integrity.
  const sigOk =
    typeof candidate.extract === 'function' &&
    candidate.extract.length === 2 &&
    typeof candidate.describe === 'function';
  results.push(line(sigOk, 'Function signature unchanged'));

  // Unrelated code untouched.
  let describeOk = false;
  try {
    describeOk = candidate.describe() === PINNED_DESCRIBE;
  } catch (_) {
    describeOk = false;
  }
  results.push(
    line(describeOk, 'Unrelated code untouched', 'describe() still returns the pinned string')
  );

  // The real check.
  const after = sigOk
    ? await runExploit(candidate.extract)
    : { escaped: true, error: 'extract() not callable' };
  results.push(
    line(
      after.escaped === false,
      'Exploit blocked after patch',
      after.error
        ? 'rejected with: ' + after.error
        : 'escaped=' + after.escaped
    )
  );

  console.log('');
  const passed = results.every(Boolean);
  if (passed) {
    console.log('All checks passed — the traversal is blocked and nothing else changed.');
    process.exit(0);
  }
  console.log('Verification failed. This pull request must not be merged.');
  process.exit(1);
})().catch((e) => {
  console.error('Verification crashed: ' + (e && e.stack ? e.stack : e));
  process.exit(1);
});
