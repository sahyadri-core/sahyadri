# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Sahyadri, please report it responsibly.

**DO NOT** open a public GitHub issue for security vulnerabilities.

### How to Report

1. Email: sahyadricore@gmail.com
2. Include: Description, Steps to reproduce, Impact assessment, Suggested fix (if any)

### What We Commit To

- Acknowledge receipt within 48 hours
- Initial assessment within 7 days
- Fix timeline communicated within 14 days
- Credit in release notes (unless anonymity requested)

## Supported Versions

| Version | Status       |
|---------|-------------|
| v0.1.x  | Active dev  |

## Scope

- Consensus bugs (double-spend, chain reorg attacks)
- Cryptographic weaknesses (Dilithium3, MemoryLoop PoW)
- Network layer attacks (P2P, RPC)
- Account model exploits (nonce replay, balance overflow)
- DID/VC system vulnerabilities

## Disclosure Policy

We follow Responsible Disclosure:
1. Report received
2. Triage and assessment
3. Fix development
4. Coordinated disclosure (we agree on timeline)
5. Public disclosure after fix is deployed
