# archive-utils (pinned v3.13)

Demo repository for the agentic CVE backport pipeline.

The `release-3.13` branch holds a component with a known path-traversal vulnerability (CVE-2007-4559, CWE-22). The remediation agent opens pull requests against it.

Every pull request runs `scripts/ci-verify.js`, which executes a real exploit against the component and fails the build unless the traversal is blocked.
