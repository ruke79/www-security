# Advanced API Security - Companion Demo

A single Spring Boot 3.4.1 / Spring Security 6.4 / Spring Authorization Server
project implementing each chapter of **"Advanced API Security: Securing APIs
with OAuth 2.0, OpenID Connect, JWS, and JWE"** as its own, independently
testable group of REST endpoints.

> **A note on how this was built:** this project was written in a sandboxed
> environment with no outbound network access for compiling/running Maven, so
> it could **not** be compile-tested or run locally before being handed to
> you. Every non-trivial Spring / Spring Authorization Server / Nimbus
> JOSE+JWT API used here was cross-checked against official docs/Javadoc
> during development, but you should expect that you may need to fix a
> handful of small issues (an import, a method signature that shifted
> between minor versions, etc.) when you first build it. Start with
> `mvn -q compile` and work through anything it reports.

> **Pentest training**: see [VULNERABILITY-SCENARIOS.md](VULNERABILITY-SCENARIOS.md)
> for a set of concrete, reproducible attack scenarios (rate-limit bypass,
> Digest replay, mTLS trust escalation, token-exchange audience confusion,
> federated-identity impersonation, UMA authorization bypass) derived from
> this codebase, each with root cause and remediation notes.

> **Book summary (Korean)**: see [BOOK-SUMMARY.md](BOOK-SUMMARY.md) for a
> detailed chapter-by-chapter Korean summary of the book this project is based
> on. Note that chapters 7-10 of the source PDFs contained no body text, so
> those chapters are supplemented from standard knowledge and marked as such.

## Chapter -> endpoint map

| Chapter | Topic | Base path |
|---|---|---|
| 2 | Security by Design | `/api/ch2/**` |
| 3 | HTTP Basic / Digest Authentication | `/api/ch3/basic/**`, `/api/ch3/digest/**` |
| 4 | Mutual Authentication with TLS | `/api/ch4/**` (port **8443**, client cert required) |
| 5 | Identity Delegation | `/api/ch5/**` |
| 7 | OAuth 2.0 (core) | `/oauth2/**`, `/api/ch7/**` |
| 8 | Sender-constrained tokens | `/api/ch8/**` (DPoP, RFC 9449 - modern replacement for the deprecated OAuth MAC Token Profile) |
| 9 | OAuth 2.0 Profiles | `/oauth2/introspect`, `/oauth2/revoke`, `/api/ch9/**` |
| 10 | User-Managed Access (UMA) 2.0 | `/api/ch10/**` |
| 11 | Federation | `/api/ch11/**` |

Only OAuth 2.0-era mechanisms are implemented (no OAuth 1.0 or the
proprietary pre-2.0 schemes Chapter 5 surveys historically, like Google
ClientLogin/AuthSub, Flickr Auth, or Yahoo BBAuth).

### Deliberate design substitutions

- **Chapter 8** covers the OAuth 2.0 MAC Token Profile, which never left
  draft status and was formally abandoned. This project implements the
  concept it was reaching for - sender-constrained (not just bearer) access
  tokens - using **DPoP (RFC 9449)**, the mechanism that actually became a
  standard for this purpose.
- **Chapter 11**'s example is federation via a **SAML 2.0 Bearer Assertion**.
  Since SAML/XML tooling was out of scope for this project, the identical
  trust pattern (RFC 7523, "JWT Profile for OAuth 2.0 Client Authentication
  and Authorization Grants") is used instead: a JSON assertion in place of
  a SAML XML assertion, signed by a completely independent external IdP key
  pair, presented to our Authorization Server's token endpoint via a custom
  `urn:ietf:params:oauth:grant-type:jwt-bearer` grant. This same grant is
  also Chapter 9's example of a modern, non-default OAuth 2.0 profile.

## Build & run

```bash
# 1. Generate the TLS key material needed for Chapter 4 (run once, from the project root)
./certs/generate-certs.sh

# 2. Build and run
mvn spring-boot:run
```

The app listens on `http://localhost:8080` (plain) and, for Chapter 4 only,
`https://localhost:8443` (mTLS).

Demo user accounts (HTTP Basic / Digest / the Authorization Server's own
login page):

| Username | Password | Role |
|---|---|---|
| `admin` | `admin123` | ADMIN |
| `alice` | `alice123` | USER |

Chapter 3's Digest variant additionally has `prabath` / `prabath123` (ADMIN)
in its own separate user store, matching the book's example.

Registered OAuth2 clients (Chapters 5/7/9/11):

| client_id | secret | grant type(s) | scopes |
|---|---|---|---|
| `demo-authcode-client` | *(public, no secret)* | authorization_code + PKCE, refresh_token | `ch7.read ch7.write` |
| `demo-service-client` | `service-secret` | client_credentials | `ch7.read ch7.write` |
| `lucidchart-client` | `lucidchart-secret` | client_credentials | `ch5.read ch5.write` |
| `demo-jwtbearer-client` | `jwtbearer-secret` | `urn:ietf:params:oauth:grant-type:jwt-bearer` | `ch9.read ch11.read` |

---

## Chapter 2 - Security by Design

```bash
# Open endpoint - no auth
curl http://localhost:8080/api/ch2/public

# Register a new user (BCrypt-hashed, salted storage)
curl -X POST http://localhost:8080/api/ch2/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"bob","password":"bobpassword"}'

# Admin-only resource via the PDP - PERMIT for admin, DENY for alice
curl -u admin:admin123 http://localhost:8080/api/ch2/admin-resource
curl -u alice:alice123 http://localhost:8080/api/ch2/admin-resource   # expect 403

# Hammer the rate limiter (default: 20 burst, 5/sec refill) to see a 429
for i in $(seq 1 30); do curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/api/ch2/public; done
```

## Chapter 3 - HTTP Basic / Digest Authentication

```bash
# --- Basic ---
curl -u admin:admin123 http://localhost:8080/api/ch3/basic/recipe
curl -u alice:alice123 -X POST http://localhost:8080/api/ch3/basic/recipe \
  -H 'Content-Type: application/json' -d '{"name":"x","ingredients":"y","directions":"z"}'   # expect 403 (USER can't POST)

# --- Digest --- (curl negotiates the challenge/response automatically with --digest)
curl --digest -u prabath:prabath123 http://localhost:8080/api/ch3/digest/recipe
curl --digest -u alice:alice123 http://localhost:8080/api/ch3/digest/recipe/10000
```

## Chapter 4 - Mutual Authentication with TLS

```bash
./certs/generate-certs.sh   # if you haven't already

curl -k --cert certs/client-cert.pem --key certs/client-key.pem \
     https://localhost:8443/api/ch4/whoami

# Without a client cert -> rejected
curl -k https://localhost:8443/api/ch4/whoami
```

## Chapter 5 - Identity Delegation

```bash
# 1. Get a token as the "lucidchart-client" (client_credentials, direct delegation)
TOKEN=$(curl -s -u lucidchart-client:lucidchart-secret -X POST http://localhost:8080/oauth2/token \
  -d grant_type=client_credentials -d scope='ch5.read ch5.write' | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# 2. Direct delegation: access foo-api/drive with the original token
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/ch5/foo-api/drive

# 3. Brokered delegation: exchange it for a narrower, snapfish-scoped token
EXCHANGED=$(curl -s -H "Authorization: Bearer $TOKEN" -X POST http://localhost:8080/api/ch5/broker/exchange \
  -H 'Content-Type: application/json' \
  -d '{"audience":"snapfish-api","scope":["ch5.read"]}' | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# 4. Use the EXCHANGED token against snapfish-api/print - the original token alone would be rejected here
curl -H "Authorization: Bearer $EXCHANGED" http://localhost:8080/api/ch5/snapfish-api/print
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/ch5/snapfish-api/print   # expect 403
```

## Chapter 7 - OAuth 2.0 (core)

```bash
# --- Client Credentials ---
curl -u demo-service-client:service-secret -X POST http://localhost:8080/oauth2/token \
  -d grant_type=client_credentials -d scope='ch7.read ch7.write'

TOKEN=$(curl -s -u demo-service-client:service-secret -X POST http://localhost:8080/oauth2/token \
  -d grant_type=client_credentials -d scope=ch7.read | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/ch7/resource

# --- Authorization Code + PKCE --- (needs one manual browser step to log in/consent)
python3 -c "
import base64, hashlib, secrets
verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode()
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
print('code_verifier :', verifier)
print('code_challenge:', challenge)
"
# Visit in a browser (log in as admin/admin123, then approve consent):
#   http://localhost:8080/oauth2/authorize?response_type=code&client_id=demo-authcode-client
#     &redirect_uri=http://127.0.0.1:8080/authorized&scope=ch7.read&code_challenge=<challenge>&code_challenge_method=S256
# You'll land on GET /authorized?code=... which echoes the exact curl command to
# exchange that code (using your code_verifier) at /oauth2/token.
```

## Chapter 8 - Sender-constrained tokens (DPoP, RFC 9449)

All of `/api/ch8/dpop/**` is **testing-convenience only** - it simulates, over
HTTP, steps a real DPoP client library would perform locally with its own
private key.

```bash
# 1. Generate a demo keypair
KEYS=$(curl -s -X POST http://localhost:8080/api/ch8/dpop/keypair)
PRIVATE_JWK=$(echo "$KEYS" | python3 -c "import sys,json;print(json.load(sys.stdin)['privateJwk'])")

# 2. Sign a DPoP proof for POST /api/ch8/dpop/token
PROOF=$(curl -s -X POST http://localhost:8080/api/ch8/dpop/proof -H 'Content-Type: application/json' \
  -d "{\"privateJwk\": $PRIVATE_JWK, \"htm\":\"POST\", \"htu\":\"http://localhost:8080/api/ch8/dpop/token\"}" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['proof'])")

# 3. Get a DPoP-bound access token
TOKEN=$(curl -s -X POST http://localhost:8080/api/ch8/dpop/token -H "DPoP: $PROOF" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# 4. Sign a NEW proof (fresh jti/iat) for the protected resource request, with 'ath' bound to TOKEN
PROOF2=$(curl -s -X POST http://localhost:8080/api/ch8/dpop/proof -H 'Content-Type: application/json' \
  -d "{\"privateJwk\": $PRIVATE_JWK, \"htm\":\"GET\", \"htu\":\"http://localhost:8080/api/ch8/protected/resource\", \"accessToken\":\"$TOKEN\"}" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['proof'])")

# 5. Call the protected resource with BOTH the access token and the matching DPoP proof
curl -H "Authorization: Bearer $TOKEN" -H "DPoP: $PROOF2" http://localhost:8080/api/ch8/protected/resource

# Replay the same proof, or use a different keypair -> rejected
curl -H "Authorization: Bearer $TOKEN" -H "DPoP: $PROOF2" http://localhost:8080/api/ch8/protected/resource   # expect 401 (jti replay)
```

## Chapter 9 - OAuth 2.0 Profiles

Introspection and revocation work against tokens from ANY grant this
Authorization Server issues, including the custom jwt-bearer grant below.
See Chapter 11 for how to obtain the `assertion` value used here.

```bash
ASSERTION=$(curl -s "http://localhost:8080/api/ch11/external-idp/assertion?user=alice@foo-inc.example" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['assertion'])")

TOKEN=$(curl -s -u demo-jwtbearer-client:jwtbearer-secret -X POST http://localhost:8080/oauth2/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer -d assertion="$ASSERTION" -d scope=ch9.read \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/ch9/resource

# Introspection (auto-provided by Spring Authorization Server)
curl -u demo-jwtbearer-client:jwtbearer-secret -X POST http://localhost:8080/oauth2/introspect -d token="$TOKEN"

# Revocation
curl -u demo-jwtbearer-client:jwtbearer-secret -X POST http://localhost:8080/oauth2/revoke -d token="$TOKEN"
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/ch9/resource   # still valid until it expires - JWTs aren't invalidated locally by revocation, only via introspection lookups
```

## Chapter 10 - User-Managed Access (UMA) 2.0

```bash
# 1. Request the resource with no token -> 401 + a permission ticket
curl -i http://localhost:8080/api/ch10/resource/photo-42

# 2. Exchange that ticket for an RPT (Requesting Party Token)
TICKET=<paste the "ticket" value from step 1>
RPT=$(curl -s -X POST http://localhost:8080/api/ch10/uma/token -H 'Content-Type: application/json' \
  -d "{\"grant_type\":\"urn:ietf:params:oauth:grant-type:uma-ticket\", \"ticket\":\"$TICKET\"}" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# 3. Retry with the RPT
curl -H "Authorization: Bearer $RPT" http://localhost:8080/api/ch10/resource/photo-42

# A ticket only works once
curl -X POST http://localhost:8080/api/ch10/uma/token -H 'Content-Type: application/json' \
  -d "{\"grant_type\":\"urn:ietf:params:oauth:grant-type:uma-ticket\", \"ticket\":\"$TICKET\"}"   # expect invalid_grant
```

## Chapter 11 - Federation

```bash
# 1. "Foo Inc." (an independent, simulated external IdP) mints a signed assertion about its own user
curl "http://localhost:8080/api/ch11/external-idp/assertion?user=alice@foo-inc.example"
# -> copy the "assertion" value (or the ready-made "howToUse" curl command) from the response

# 2. Our Authorization Server trusts that assertion via the jwt-bearer grant and issues its OWN token
ASSERTION=<paste the assertion value>
TOKEN=$(curl -s -u demo-jwtbearer-client:jwtbearer-secret -X POST http://localhost:8080/oauth2/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer -d assertion="$ASSERTION" -d scope=ch11.read \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/ch11/resource
```

---

## Project layout

```
src/main/java/com/example/apisecurity/
  ch2/    Security by Design (PDP, rate limiting, salted password storage)
  ch3/    HTTP Basic/Digest Authentication (shared Recipe API)
  ch4/    Mutual Authentication with TLS
  ch5/    Identity Delegation (direct + brokered/token-exchange)
  ch7/    OAuth 2.0 core (real Spring Authorization Server)
  ch8/    DPoP sender-constrained tokens
  ch9/    OAuth 2.0 Profiles + the custom JWT Bearer grant (RFC 7523)
  ch10/   User-Managed Access (UMA) 2.0
  ch11/   Federation (external IdP + the JWT Bearer grant from ch9)
  common/ Cross-chapter utilities (rate limiter)
  config/ All SecurityFilterChain / Authorization Server wiring
certs/    TLS key material generation script for Chapter 4
```

Multiple `@Order`-ed `SecurityFilterChain` beans route different URL
patterns to different authentication mechanisms (see the Javadoc on each
class under `config/` for the exact ordering and reasoning).
