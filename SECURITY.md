# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | Yes       |
| 0.2.x   | Yes       |
| 0.1.x   | Security fixes only |

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email security reports to the maintainers (replace with your preferred contact), including:

1. Description of the issue
2. Steps to reproduce
3. Affected package and version
4. Impact assessment (if known)

We aim to acknowledge reports within 72 hours and ship fixes as quickly as possible.

## Advisory process (dry run)

1. Triage severity (critical / high / medium / low)
2. Patch on a private branch; add regression tests
3. Publish fixed release + GitHub Security Advisory
4. Credit reporters who opt in

## Safe harbor

We welcome good-faith security research against this library. Avoid:

- Testing against production systems that are not yours
- Accessing or modifying data that is not yours
- Denial-of-service attacks against third parties

## Disclosure

Once a fix is released, we will publish a security advisory and credit reporters who wish to be named.
