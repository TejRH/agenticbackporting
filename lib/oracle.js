'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const tar = require('tar-stream');

// ---------------------------------------------------------------------------
// THE TEST ORACLE
//
// A verification gate is only as good as the test it runs. Hand-writing an
// exploit per CVE does not scale, so tests have to come from somewhere:
// upstream regression suites, published proofs of concept, sibling distro
// patch series, or generation as a last resort.
//
// None of those sources can be trusted on arrival. A test that does not
// actually exercise the vulnerability will pass against a broken patch and
// report success, which is worse than having no test at all.
//
// The resolution is differential validation. Before a candidate is allowed to
// judge anything, it is run against two references whose status is already
// known:
//
//     against the KNOWN-VULNERABLE version  -> it must FIRE
//     against the KNOWN-FIXED version       -> it must be BLOCKED
//
// A candidate that fails to discriminate between those two is not measuring
// the vulnerability, whatever it claims to measure, and is discarded. This
// converts an untrusted artifact into a trusted one without trusting its
// author — including when the author is a model.
// ---------------------------------------------------------------------------

// Trust ordering. Used by the policy engine downstream.
const PROVENANCE_RANK = {
  'upstream-regression': 4,
  'distro-patch': 3,
  'public-poc': 2,
  'generated': 1,
};

/**
 * Candidate tests, each from a different source. Every one is a real payload
 * executed against a real extractor — the difference is only where it came
 * from and therefore how much it is trusted before validation.
 */
const CANDIDATES = [
  {
    id: 'upstream-regression',
    provenance: 'upstream-regression',
    source: 'archive-utils 3.14 test suite (test/traversal.spec.js)',
    payload: '../../ESCAPED.txt',
    description: 'Relative traversal, two levels. Shipped with the upstream fix commit.',
  },
  {
    id: 'distro-suse',
    provenance: 'distro-patch',
    source: 'openSUSE patch series (archive-utils-CVE-2007-4559.patch)',
    payload: '../../../DEEP-ESCAPE.txt',
    description: 'Relative traversal, three levels. Carried in a sibling distro backport.',
  },
  {
    id: 'public-poc',
    provenance: 'public-poc',
    source: 'GitHub Security Advisory reference',
    payload: 'docs/../../../MIXED-ESCAPE.txt',
    description: 'Traversal preceded by a legitimate path segment.',
  },
  {
    id: 'generated-absolute',
    provenance: 'generated',
    source: 'model-generated candidate',
    payload: '/tmp/ABSOLUTE-EVIL.txt',
    description: 'Absolute path. Generated from the advisory text alone.',
  },
];

function insideOf(base, candidate) {
  const b = path.resolve(base);
  const c = path.resolve(candidate);
  return c === b || c.startsWith(b + path.sep);
}

/**
 * Execute one payload against one extract() implementation.
 *
 * The extraction directory sits four levels deep inside a private temp
 * sandbox, so payloads climbing up to three levels escape the extraction
 * directory while remaining inside the sandbox. Anything that would land
 * outside the sandbox is refused before the archive is built.
 */
async function runPayload(extractFn, payloadName) {
  const sandbox = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'cve-oracle-'));
  const dest = path.join(sandbox, 'l1', 'l2', 'l3', 'dest');
  const archivePath = path.join(sandbox, 'evil.tar');

  // Where a naive path.join() extractor would place this member.
  const landed = path.join(dest, payloadName);

  // Containment guard for the harness itself.
  if (!insideOf(sandbox, landed)) {
    await fs.promises.rm(sandbox, { recursive: true, force: true });
    return {
      fired: false,
      error: 'payload refused by harness: would land outside the sandbox',
      refused: true,
    };
  }

  let error = null;
  try {
    await fs.promises.mkdir(dest, { recursive: true });
    await new Promise((resolve, reject) => {
      const pack = tar.pack();
      pack.entry({ name: 'safe.txt' }, 'benign member');
      pack.entry({ name: payloadName }, 'payload');
      pack.finalize();
      const out = fs.createWriteStream(archivePath);
      pack.pipe(out);
      out.on('finish', resolve);
      out.on('error', reject);
    });
    await extractFn(archivePath, dest);
  } catch (e) {
    error = e && e.message ? e.message : String(e);
  }

  // The test fires when the member landed outside the extraction directory.
  const fired = !insideOf(dest, landed) && fs.existsSync(landed);

  try {
    await fs.promises.rm(sandbox, { recursive: true, force: true });
  } catch (_) { /* best effort */ }

  return { fired, error, landed, dest };
}

/**
 * Differential validation of one candidate.
 *
 * Returns { valid, onVulnerable, onFixed, reason }.
 * valid === true only when the candidate fires against the known-vulnerable
 * reference AND is blocked against the known-fixed reference.
 */
async function validateCandidate(candidate, vulnerableExtract, fixedExtract) {
  const onVulnerable = await runPayload(vulnerableExtract, candidate.payload);

  // When no fixed release exists there is no second reference to validate
  // against. Only the first half of the differential can be performed, and
  // the result is marked as such rather than presented as fully validated.
  const halfOnly = typeof fixedExtract !== 'function';
  const onFixed = halfOnly
    ? null
    : await runPayload(fixedExtract, candidate.payload);

  const firesOnVulnerable = onVulnerable.fired === true;
  const blockedOnFixed = halfOnly ? null : onFixed.fired === false;
  const valid = halfOnly ? firesOnVulnerable : (firesOnVulnerable && blockedOnFixed);

  let reason;
  if (valid && halfOnly) {
    reason = 'Fires against the vulnerable reference. No fixed release exists, '
      + 'so the second half of the differential could not be performed — this '
      + 'test is only half-validated.';
  } else if (valid) {
    reason = 'Fires against the vulnerable reference and is blocked against '
      + 'the fixed reference. Discriminates correctly.';
  } else if (!firesOnVulnerable) {
    reason = 'Does not fire against the KNOWN-VULNERABLE reference, so it is '
      + 'not exercising this vulnerability. A patch could pass this test '
      + 'without fixing anything. Rejected.';
  } else {
    reason = 'Fires against the KNOWN-FIXED reference, so it is reporting a '
      + 'vulnerability that is already closed. Rejected.';
  }

  return {
    id: candidate.id,
    provenance: candidate.provenance,
    source: candidate.source,
    payload: candidate.payload,
    description: candidate.description,
    valid,
    halfValidated: halfOnly,
    firesOnVulnerable,
    blockedOnFixed,
    onVulnerable,
    onFixed,
    reason,
  };
}

/**
 * Build the oracle: validate every candidate, keep the ones that discriminate.
 *
 * Returns { accepted, rejected, provenance, suiteSize } where `provenance` is
 * the highest-trust source among accepted tests — the value the policy engine
 * uses to decide how much human review a patch needs.
 */
async function buildOracle(vulnerableExtract, fixedExtract) {
  const results = [];
  for (const c of CANDIDATES) {
    results.push(await validateCandidate(c, vulnerableExtract, fixedExtract));
  }

  const accepted = results.filter((r) => r.valid);
  const rejected = results.filter((r) => !r.valid);

  let provenance = null;
  let rank = 0;
  for (const a of accepted) {
    const r = PROVENANCE_RANK[a.provenance] || 0;
    if (r > rank) {
      rank = r;
      provenance = a.provenance;
    }
  }

  return {
    accepted,
    rejected,
    suiteSize: accepted.length,
    candidateCount: results.length,
    provenance,
    provenanceRank: rank,
    halfValidated: accepted.some((a) => a.halfValidated),
  };
}

/**
 * Run every accepted test against a candidate patch.
 * The patch passes only if no test in the suite fires.
 */
async function runSuite(accepted, extractFn) {
  const results = [];
  for (const t of accepted) {
    const r = await runPayload(extractFn, t.payload);
    results.push({
      id: t.id,
      payload: t.payload,
      provenance: t.provenance,
      fired: r.fired,
      error: r.error,
    });
  }
  return {
    results,
    allBlocked: results.every((r) => r.fired === false),
    firedCount: results.filter((r) => r.fired).length,
  };
}

module.exports = {
  buildOracle,
  validateCandidate,
  runSuite,
  runPayload,
  CANDIDATES,
  PROVENANCE_RANK,
};
