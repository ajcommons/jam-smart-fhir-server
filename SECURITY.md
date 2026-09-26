# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x (current) | ✅ Yes |
| < 0.2 | ❌ No |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub Issues.**

To report a vulnerability, email **security@ajcommons.org** with:

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested remediation (optional)

You will receive an acknowledgement within **48 hours** and a resolution timeline within **5 business days**.

Once a fix is available, we will:
1. Release a patched version
2. Credit you in the release notes (unless you prefer to remain anonymous)
3. Publish a GitHub Security Advisory

## Scope

This policy covers the `smart-auth-server` and `smart-client` modules in this repository.

**In scope:**
- Authentication bypass
- Token forgery or scope escalation
- SMART launch context injection
- XSS / CSRF on admin or portal pages
- Secrets leakage via logs or API responses

**Out of scope:**
- Vulnerabilities in HAPI FHIR JPA Server (report to https://github.com/hapifhir/hapi-fhir)
- Vulnerabilities in Spring Authorization Server (report to https://spring.io/security)
- Issues requiring physical access to the server

## Security Design Notes

Key security decisions documented for reviewers:

- **PKCE (S256)** is required for all public clients — client secrets are not supported for browser clients
- **XFF / IP extraction** — only `getRemoteAddr()` is trusted; `X-Forwarded-For` is rewritten by `ForwardedHeaderFilter` before filters run
- **RSA key** — prod requires a PKCS12 keystore via env var; server fails to start without one on `prod` profile
- **Admin bootstrap** — `AdminBootstrapInitializer` only runs on `prod` profile and only if the admin account doesn't already exist
- **Launch tokens** — single-use, 5-minute TTL, atomic mark-used via JPQL UPDATE
- **Rate limiting** — Bucket4j per-IP on login (10 req/min) and token endpoint (20 req/min)
