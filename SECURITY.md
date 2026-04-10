# Security Policy

This document outlines the security practices and vulnerability reporting procedures for Socrates Blade.

---

## Supported Versions

The following versions of Socrates Blade are currently supported with security updates:

| Version | Supported          |
| ------- | ----------------- |
| 3.2.x   | :white_check_mark: |
| 3.1.x   | :x:           |
| 3.0.x   | :x:           |

---

## Reporting a Vulnerability

### How to Report

If you discover a security vulnerability in Socrates Blade, please report it responsibly:

1. **Do NOT** create a public GitHub issue for security vulnerabilities
2. Email the maintainers privately instead
3. Include as much detail as possible

### What to Include

When reporting a vulnerability, please include:

- Type of vulnerability
- Full paths of source file(s) related to the vulnerability
- Location of the affected code (line numbers)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact assessment

### Response Time

We aim to acknowledge vulnerability reports within **48 hours** and provide a timeline for fixes.

---

## Security Best Practices

### For Users

- **Only test systems you own or have written permission to test**
- Review local laws before use
- Do not use on production systems without proper authorization
- Follow responsible disclosure practices
- Keep your installation updated

### For Contributors

- Never commit secrets, keys, or credentials
- Sanitize all inputs and outputs
- Use parameterized queries to prevent SQL injection
- Validate and sanitize user input
- Follow secure coding practices

---

## Security Updates

When security updates are released:

1. A security advisory will be published on GitHub
2. Users will be notified to update
3. The vulnerability details will be disclosed after fixes are available

---

## Scope

Socrates Blade is a security testing tool designed for authorized security testing only.

**Intended Use:**
- Security audits of own applications
- Penetration testing with proper authorization
- Vulnerability assessment

**Not Intended For:**
- Unauthorized access to third-party systems
- Malicious purposes
- Attacking systems without permission

---

## Credit

We believe in crediting researchers who responsibly disclose vulnerabilities. If you would like to be credited, include your name and preferred contact in the report.

---

## Contact

For security-related matters, please contact the maintainers through GitHub's private vulnerability reporting.

---

**Last Updated**: April 2026
**Maintained by**: Malang PHP User Group