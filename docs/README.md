# OWASP Security Documentation

This documentation covers detailed analysis of OWASP Top 20 vulnerabilities, with specific focus on ASP.NET Core mitigation strategies using our solution's domain models.

## Structure

Each vulnerability is documented in its own markdown file with the following sections:
1. Overview
2. Technical Details
3. OWASP Mitigation Guidelines
4. ASP.NET Core Specific Mitigations
5. Sample Test Payloads

## Vulnerabilities Covered

1. [Broken Access Control](./vulnerabilities/01-broken-access-control.md)
2. [Cryptographic Failures](./vulnerabilities/02-cryptographic-failures.md)
3. [Injection](./vulnerabilities/03-injection.md)
4. [Insecure Design](./vulnerabilities/04-insecure-design.md)
5. [Security Misconfiguration](./vulnerabilities/05-security-misconfiguration.md)
6. [Vulnerable and Outdated Components](./vulnerabilities/06-vulnerable-outdated-components.md)
7. [Identification and Authentication Failures](./vulnerabilities/07-identification-authentication-failures.md)
8. [Software and Data Integrity Failures](./vulnerabilities/08-software-data-integrity-failures.md)
9. [Security Logging and Monitoring Failures](./vulnerabilities/09-security-logging-monitoring-failures.md)
10. [Server-Side Request Forgery (SSRF)](./vulnerabilities/10-ssrf.md)
11. [XML External Entities (XXE)](./vulnerabilities/11-xxe.md)
12. [Cross-Site Scripting (XSS)](./vulnerabilities/12-xss.md)
13. [Insecure Deserialization](./vulnerabilities/13-insecure-deserialization.md)
14. [Using Components with Known Vulnerabilities](./vulnerabilities/14-known-vulnerabilities.md)
15. [Insufficient Logging & Monitoring](./vulnerabilities/15-insufficient-logging-monitoring.md)
16. [API Security Misconfiguration](./vulnerabilities/16-api-security-misconfiguration.md)
17. [Cross-Site Request Forgery (CSRF)](./vulnerabilities/17-csrf.md)
18. [Security Through Obscurity](./vulnerabilities/18-security-through-obscurity.md)
19. [Insufficient Rate Limiting](./vulnerabilities/19-insufficient-rate-limiting.md)
20. [Mass Assignment](./vulnerabilities/20-mass-assignment.md)

## Contributing

When adding new examples or updating existing ones, please ensure to:
1. Follow the established document structure
2. Include practical examples using our solution's domain models
3. Keep the ASP.NET Core specific mitigations up to date
4. Include verifiable test cases
