# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| Latest 2.x minor release | Yes |
| Previous 2.x minor release | Security fixes for 90 days after the next minor release |
| Earlier releases | No |

See the [versioning policy](docs/dev/guides/versioning.md).

## Reporting a vulnerability

Do not open a public issue. Report privately through GitHub's **Report a
vulnerability** button on the repository's Security tab (private vulnerability
reporting).

Please include:

- the affected version or commit, and the configuration if relevant;
- the steps to reproduce, or a proof of concept;
- the impact as you understand it: which account, token or data is at risk,
  and what an attacker needs first.

## What happens next

| Step | Target |
|------|--------|
| Acknowledgement | 3 business days |
| Triage and severity assessment | 7 days |
| Fix for a critical or high severity issue | 30 days |
| Fix for a medium or low severity issue | Next release |

We keep you informed along the way, agree on a disclosure date with you (90
days after the report at the latest, earlier once a fix is released), and credit
you in the release notes unless you prefer otherwise.

## Scope

In scope: the code of this repository, its deployment files and documented
configurations, and the verifier packages in `crates/verifier` and
`clients/js/verifier`.

Out of scope: vulnerabilities of dependencies (report them upstream; tell us if
auth-api is affected in a way the advisory does not cover), volumetric denial of
service, social engineering, findings that require an attacker with code
execution on the host or access to the secrets store, and missing hardening of a
deployment that ignores the production checks.

## Safe harbour

Research carried out in good faith within this policy, on your own deployment,
without accessing other people's data or degrading a service others rely on, is
welcome: we will not pursue it.

The [security model](docs/dev/security-model.md) and
[threat model](docs/dev/threat-model.md) describe what auth-api protects and the
risks it accepts.
