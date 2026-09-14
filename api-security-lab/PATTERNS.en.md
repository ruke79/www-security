# API Security Patterns - Reproduction Guide (Chapter 14 → Demo mapping)

> 🌐 [한국어](PATTERNS.md) · [English](PATTERNS.en.md) · [日本語](PATTERNS.ja.md)

This document shows how to reproduce the ten practical API-security solution
patterns from **Chapter 14, "Patterns and Practices"** of *Advanced API
Security*, using the endpoints of this demo project (`api-security-lab`).
Each pattern is a **composition** of the mechanisms built in earlier chapters.

> Start the app first. By default only plain HTTP on 19080 is opened (mTLS is
> off). Only pattern 1 (mTLS) needs port 8443 + certificates, enabled with
> `MTLS_ENABLED=true`.
>
> ```bash
> # Most patterns (2-10): just run (19080). On a port clash, use APP_PORT.
> mvn spring-boot:run
> #   APP_PORT=29080 mvn spring-boot:run
>
> # For pattern 1 (mTLS): generate certs, then enable mTLS
> ./certs/generate-certs.sh
> MTLS_ENABLED=true mvn spring-boot:run
> ```
>
> The commands below were verified against a running app. The book's scenario
> descriptions are summarized, and the demo is a simplified, concept-first
> implementation (not for production).

## Pattern → demo mapping at a glance

| # | Pattern | Core mechanism | Demo implementation |
|---|---|---|---|
| 1 | Direct Auth + Trusted Subsystem | web app calls the backend API over mTLS | `ch4` (mTLS, 8443) |
| 2 | SSO + Delegated Access Control | SAML token → OAuth access token exchange | `ch11` (assertion → jwt-bearer grant) |
| 3 | SSO + Integrated Windows Auth | IdP protected by IWA (auto sign-in) | `ch11` + explanation |
| 4 | Identity Proxy + Delegated | internal IdP brokers trust with an external IdP | `ch11` (external IdP federation) |
| 5 | Delegated Access Control + JWT | ID token (JWT) → access token exchange | `ch12` + `ch11` jwt-bearer |
| 6 | Nonrepudiation + JWS | JWS-sign with user's private key + JWE-encrypt | `ch13` (JWS→JWE) |
| 7 | Chained Access Delegation | token exchange on API→API calls | `ch9b` (chain grant) |
| 8 | Trusted Master Access Delegation | self-explanatory JWT from master + introspection | `ch9`/`ch9b` |
| 9 | Resource STS + Delegated | SAML token exchange via interceptor/STS | `ch5` (broker) + `ch11` |
| 10 | Delegated Access Control + Hidden Credentials | credentials never sent (MAC token) | `ch8` (DPoP, MAC replacement) |

---

## Pattern 1 — Direct Authentication with the Trusted Subsystem

**Book scenario**: a web app behind the firewall authenticates the user, then
calls backend APIs as a trusted subsystem. The API is protected with **mTLS**.

**Demo** (`ch4`): an mTLS endpoint reachable only with a valid client certificate.

```bash
./certs/generate-certs.sh                 # once (creates key/truststores)
MTLS_ENABLED=true mvn spring-boot:run      # enable the mTLS connector on 8443 (off by default)
# if 8443 is busy: MTLS_ENABLED=true MTLS_PORT=18443 mvn spring-boot:run

# With a trusted client cert → 200 + certificate Subject DN
curl -k --cert certs/client-cert.pem --key certs/client-key.pem \
     https://localhost:8443/api/ch4/whoami

# Without a client cert → rejected
curl -k https://localhost:8443/api/ch4/whoami
```

**Key point**: the user is authenticated at the web app (the trusted subsystem),
not at the backend API; the web app↔API leg establishes trust via mutual TLS.

---

## Pattern 2 — Single Sign-On with the Delegated Access Control

**Book scenario**: after logging in at a SAML 2.0 IdP, the received SAML token
is exchanged for an OAuth access token via the **SAML grant type** to reach
backend APIs (no refresh token; the access token's lifetime stays within the
SAML token's).

**Demo** (`ch11`): instead of SAML/XML tooling, the same trust model is realized
with the **JWT bearer grant (RFC 7523)** — an external IdP signs an assertion,
and our authorization server issues its own access token.

```bash
# 1. Get an assertion signed by the external IdP ("Foo Inc.") (stands in for a SAML assertion)
ASSERTION=$(curl -s "http://localhost:19080/api/ch11/external-idp/assertion?user=alice@foo-inc.example" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['assertion'])")

# 2. Exchange it for our authorization server's access token via the jwt-bearer grant
TOKEN=$(curl -s -u demo-jwtbearer-client:jwtbearer-secret -X POST http://localhost:19080/oauth2/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \
  -d assertion="$ASSERTION" -d scope=ch11.read \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# 3. Access the backend API with the exchanged token
curl -H "Authorization: Bearer $TOKEN" http://localhost:19080/api/ch11/resource
```

**Key point**: user credentials are never handed to the web app — only the
IdP-signed assertion is trusted (the same out-of-band trust as the book's SAML
grant type).

---

## Pattern 3 — Single Sign-On with Integrated Windows Authentication

**Book scenario**: same as pattern 2, but if the user is already logged into a
Windows domain, the IdP is protected with **IWA** so they authenticate
automatically without entering credentials. Only the IdP's auth method changes
to IWA; the rest of the flow (SAML → access token exchange) is identical.

**Demo**: IWA (Kerberos/SPNEGO) needs a Windows domain, so it is out of scope
for this demo. **The flow itself is identical to pattern 2** — use pattern 2's
commands and understand that "only the IdP's authentication method is swapped
for IWA."

---

## Pattern 4 — Identity Proxy with the Delegated Access Control

**Book scenario**: not only your own employees but also trusted partner
employees access the APIs. Internal apps **trust only their own domain's IdP**,
and the internal IdP brokers trust with the external IdP (converting protocols
if needed).

**Demo** (`ch11`): "Foo Inc." is an **independent external IdP** we don't
control, signing assertions with its own RSA key. Our authorization server is
explicitly configured (`ExternalIdpConfig`) to trust that external IdP, so it
accepts an external user's assertion and issues its own token — that is identity
proxy brokering.

```bash
# Mint an assertion for a partner-company user identity → our AS trusts it and issues a token
ASSERTION=$(curl -s "http://localhost:19080/api/ch11/external-idp/assertion?user=bob@partner.example" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['assertion'])")
TOKEN=$(curl -s -u demo-jwtbearer-client:jwtbearer-secret -X POST http://localhost:19080/oauth2/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \
  -d assertion="$ASSERTION" -d scope=ch11.read \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
curl -H "Authorization: Bearer $TOKEN" http://localhost:19080/api/ch11/resource
```

> ⚠️ The security pitfall of this flow (arbitrary external-IdP assertion issuance
> + missing audience validation → identity impersonation) is covered in
> [`VULNERABILITY-SCENARIOS.md`](VULNERABILITY-SCENARIOS.md) scenario 6.

---

## Pattern 5 — Delegated Access Control with the JSON Web Token

**Book scenario**: an **ID token (JWT)** obtained by logging in at an OpenID
Connect IdP is exchanged for an access token via the **JWT bearer grant** when
the OIDC server and the authorization server differ.

**Demo** (`ch12` + `ch11`): `ch12` issues/validates the OIDC ID token, and
`ch11` provides the jwt-bearer grant that exchanges a JWT for an access token.

```bash
# 1. Issue an OIDC ID token (an assertion of an authenticated user's identity)
IDT=$(curl -s -X POST http://localhost:19080/api/ch12/id-token/issue -H 'Content-Type: application/json' \
  -d '{"subject":"alice@foo.com","clientId":"demo-client","nonce":"n-123"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['id_token'])")

# 2. Validate the ID token (signature + iss + aud + nonce)
curl -s -X POST http://localhost:19080/api/ch12/id-token/validate -H 'Content-Type: application/json' \
  -d "{\"idToken\":\"$IDT\",\"expectedClientId\":\"demo-client\",\"expectedNonce\":\"n-123\"}"
```

> **A precise nuance in the demo**: `ch12`'s ID token is signed with **our
> authorization server's key**, whereas `ch11`'s jwt-bearer grant is configured
> to verify assertions signed with the **external IdP's key**. So "exchange the
> ID token directly via jwt-bearer" only holds when the two servers share a
> domain/key (the book's own Note makes the same point: if the OIDC server and
> the AS are the same, the exchange is unnecessary to begin with). For the
> different-domain scenario, reproduce with the external-IdP assertion flow of
> patterns 2/4.

---

## Pattern 6 — Nonrepudiation with the JSON Web Signature

**Book scenario**: where nonrepudiation is mandatory (e.g. financial APIs). The
institution issues a key pair per user and keeps only the public certificate.
Every API call is **JWS-signed with the user's private key** and then
**JWE-encrypted with the institution's public key** (sign first, then encrypt,
for legal acceptability).

**Demo** (`ch13`): reproduces JWS sign/verify and JWE encrypt/decrypt.

```bash
# 1. Sign a payload with the user's private key (JWS, RS256) — the core of nonrepudiation
JWS=$(curl -s -X POST http://localhost:19080/api/ch13/jws/rsa/sign -H 'Content-Type: application/json' \
  -d '{"subject":"customer-42","issuer":"mobile-app"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['jws'])")

# 2. Verify the signature (receiver: confirm it is a trusted issuer's signature → unforgeable proof)
curl -s -X POST http://localhost:19080/api/ch13/jws/rsa/verify -H 'Content-Type: application/json' \
  -d "{\"jwt\":\"$JWS\"}"

# 3. If confidentiality is also needed, encrypt with JWE (RSA-OAEP-256 + A128GCM, compact = 5 parts)
#    Follow the book's rule: "sign first → then encrypt".
JWE=$(curl -s -X POST http://localhost:19080/api/ch13/jwe/encrypt -H 'Content-Type: application/json' \
  -d '{"subject":"customer-42"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['jwe'])")
curl -s -X POST http://localhost:19080/api/ch13/jwe/decrypt -H 'Content-Type: application/json' \
  -d "{\"jwt\":\"$JWE\"}"
```

**Key point**: signing proves "who did it" unforgeably (nonrepudiation);
encryption keeps third parties from reading it (confidentiality). Different
goals; when combined, sign first.

---

## Pattern 7 — Chained Access Delegation

**Book scenario**: a mobile app calls the Water API, and the Water API in turn
calls the MyHealth API on the user's behalf. Because of audience restriction the
received token can't be forwarded as-is, so a new token is obtained via the
**Chain Grant Type**.

**Demo** (`ch9b`): exchanges the original access token for a new token with a
narrower (or equal) scope. No refresh token is issued.

```bash
# 1. Client obtains a token for the first API
TOKEN=$(curl -s -u demo-service-client:service-secret -X POST http://localhost:19080/oauth2/token \
  -d grant_type=client_credentials -d scope='ch7.read ch7.write' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# 2. The first API chain-exchanges the token to call the second API (narrower scope + different audience)
curl -s -X POST http://localhost:19080/api/ch9b/chain/token -H 'Content-Type: application/json' \
  -d "{\"oauthToken\":\"$TOKEN\",\"scope\":\"ch7.read\",\"audience\":\"myhealth-api\"}"

# 3. Trying to escalate to a scope not in the original → rejected
curl -s -X POST http://localhost:19080/api/ch9b/chain/token -H 'Content-Type: application/json' \
  -d "{\"oauthToken\":\"$TOKEN\",\"scope\":\"admin.super\"}"   # -> invalid_scope
```

**Key point**: the exchanged token has only a **subset** of the original scope,
and with no refresh token you must present the original token again to re-chain.

---

## Pattern 8 — Trusted Master Access Delegation

**Book scenario**: each department has its own authorization server plus a
central (master) authorization server. A **self-explanatory JWT (with iss)**
issued by the master can access any department's API. The department's
authorization server checks the issuer from the JWT header, queries the master's
**introspection** endpoint for the token's status/scope, and then authorizes
(via a XACML PDP if needed).

**Demo** (`ch9`/`ch9b`): reproduces the part that uses standard introspection to
check "which server issued it and is it still valid."

```bash
# The master (= our authorization server) issues a JWT access token
TOKEN=$(curl -s -u demo-service-client:service-secret -X POST http://localhost:19080/oauth2/token \
  -d grant_type=client_credentials -d scope=ch7.read \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# The department AS validates the token via the master's introspection (active/scope/client_id/aud)
curl -s -u demo-service-client:service-secret -X POST http://localhost:19080/oauth2/introspect \
  -d "token=$TOKEN"
```

**Key point**: the department AS can decide access from the introspection
response's `active`/`scope`/`aud` (the book builds a XACML request from this and
queries a PDP). Because the token is a JWT, the `iss` claim immediately
identifies the issuer.

---

## Pattern 9 — Resource STS with the Delegated Access Control

**Book scenario**: add security without changing the client or the API. Place
interceptors (PEPs) on both sides; a SAML token issued by the client-region STS
is exchanged (WS-Trust) by the API-region STS, and finally exchanged for an
access token via the **SAML grant type**.

**Demo** (`ch5` broker + `ch11`): WS-Trust/SOAP STS is out of scope, but the core
**token exchange** is reproduced with `ch5`'s brokered delegation, and the
**assertion → access token** step with `ch11`.

```bash
# (a) ch5 brokered delegation: exchange the original token for a different audience/narrower scope (≈ STS token exchange)
LTOKEN=$(curl -s -u lucidchart-client:lucidchart-secret -X POST http://localhost:19080/oauth2/token \
  -d grant_type=client_credentials -d scope='ch5.read ch5.write' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
curl -s -H "Authorization: Bearer $LTOKEN" -X POST http://localhost:19080/api/ch5/broker/exchange \
  -H 'Content-Type: application/json' -d '{"audience":"api-region-sts","scope":["ch5.read"]}'

# (b) ch11: finally exchange an (external-IdP-signed) assertion for an access token → access the API
#     same flow as pattern 2 above
```

**Key point**: when crossing multiple trust domains, the core idea is to
"repeatedly exchange the token for one the target region understands."

---

## Pattern 10 — Delegated Access Control with Hidden Credentials

**Book scenario**: when credentials must not travel over the wire. Use HTTP
Digest or **OAuth 2.0 MAC tokens**. MAC tokens are better because they can be
issued per-API and revoked individually.

**Demo** (`ch8`): instead of the abandoned MAC Token Profile, reproduces
"proof-of-possession without sending the token secret over the wire" with the
modern standard **DPoP (RFC 9449)**.

```bash
# 1. Generate a demo key pair (privateJwk is taken as a string by the server, so wrap it with json.dumps)
KEYS=$(curl -s -X POST http://localhost:19080/api/ch8/dpop/keypair)
PRIVATE_JWK=$(echo "$KEYS" | python3 -c "import sys,json;print(json.dumps(json.load(sys.stdin)['privateJwk']))")

# 2. Sign a DPoP proof for the token request
PROOF=$(curl -s -X POST http://localhost:19080/api/ch8/dpop/proof -H 'Content-Type: application/json' \
  -d "{\"privateJwk\": $PRIVATE_JWK, \"htm\":\"POST\", \"htu\":\"http://localhost:19080/api/ch8/dpop/token\"}" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['proof'])")

# 3. Obtain a DPoP-bound access token
TOKEN=$(curl -s -X POST http://localhost:19080/api/ch8/dpop/token -H "DPoP: $PROOF" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# 4. Sign a new proof (ath binding) for the resource request, then present token + proof together
PROOF2=$(curl -s -X POST http://localhost:19080/api/ch8/dpop/proof -H 'Content-Type: application/json' \
  -d "{\"privateJwk\": $PRIVATE_JWK, \"htm\":\"GET\", \"htu\":\"http://localhost:19080/api/ch8/protected/resource\", \"accessToken\":\"$TOKEN\"}" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['proof'])")
curl -H "Authorization: Bearer $TOKEN" -H "DPoP: $PROOF2" http://localhost:19080/api/ch8/protected/resource
```

**Key point**: unlike a bearer token, even if the token is stolen it is unusable
**without the private key** to produce a valid proof (= a modern realization of
"hidden credentials").

---

## See also

- Per-chapter detailed summary: [`BOOK-SUMMARY.md`](BOOK-SUMMARY.md) (Korean)
- Reproducible vulnerability scenarios: [`VULNERABILITY-SCENARIOS.en.md`](VULNERABILITY-SCENARIOS.en.md)
- Per-chapter endpoints / how to run: [`README.md`](README.md)
