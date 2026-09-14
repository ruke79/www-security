# www-security

> 🌐 [日本語](README.md) · [한국어](README.ko.md) · [English](README.en.md)

A collection of projects for web-security and penetration-testing (web pentest)
training.

> ⚠️ **These are intentionally vulnerable educational projects.** Some endpoints
> (`/api/lab/**`) are reachable without authentication and are built so that
> real attacks — SQL injection, XSS, SSRF, command injection, SSTI, and more —
> actually work. **Run them only in a local or otherwise controlled training
> environment, and never deploy them to the public internet or a shared
> server.**

## Projects

### [api-security-lab](api-security-lab/)

A Spring Boot 3.4.1 / Spring Security 6.4 / Spring Authorization Server demo
project based on the book *"Advanced API Security: Securing APIs with OAuth 2.0,
OpenID Connect, JWS, and JWE"*. Each chapter is implemented as an independently
testable group of REST endpoints.

Topics covered:

- HTTP Basic / Digest authentication
- Mutual TLS authentication (mTLS)
- OAuth 2.0 Authorization Code (PKCE) / Client Credentials flows
- Sender-constrained tokens (DPoP, RFC 9449)
- OAuth 2.0 profiles (token introspection/revocation, JWT Bearer grant)
- User-Managed Access (UMA) 2.0
- Federation via external IdP integration

For detailed run instructions and the chapter-by-chapter endpoint map, see the
[project README](api-security-lab/README.md).

For the vulnerability scenarios prepared for pentest practice (reproduction
steps, root causes, and mitigations), see
[VULNERABILITY-SCENARIOS.md](api-security-lab/VULNERABILITY-SCENARIOS.md).

For a detailed chapter-by-chapter summary (in Korean) of *Advanced API
Security*, the book this demo is based on, see
[BOOK-SUMMARY.md](api-security-lab/BOOK-SUMMARY.md).

For a hands-on guide that reproduces the 10 API security patterns from Chapter
14 of the book using the demo endpoints, see
[PATTERNS.md](api-security-lab/PATTERNS.md).

For a real-world usage guide describing how each mechanism/vulnerability is used
in practice ("situation → how it applies → common mistakes," including in-depth
IDOR and mTLS sections), see [USE-CASES.md](api-security-lab/USE-CASES.md).

## License

The **source code** in this repository is distributed under the
[MIT License](LICENSE).

Note, however, that summary documents such as `BOOK-SUMMARY.md` are study notes
summarizing the content of the original book *"Advanced API Security: Securing
APIs with OAuth 2.0, OpenID Connect, JWS, and JWE"* (Prabath Siriwardena,
Apress); **the copyright of the original book belongs to its author/publisher.**
The MIT License applies only to the code written for this project and does not
affect the copyright of the original work summarized in those documents.
