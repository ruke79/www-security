# Use Cases

> 🌐 [한국어](USE-CASES.md) · [English](USE-CASES.en.md) · [日本語](USE-CASES.ja.md)

This document summarizes **how each mechanism and vulnerability scenario**
implemented in `api-security-lab` **is actually used in practice**. Each
entry follows the form "real-world situation → what in this project maps to it →
common mistakes."

- Defensive mechanisms: [BOOK-SUMMARY.md](BOOK-SUMMARY.md) (per-chapter book
  summaries), [PATTERNS.md](PATTERNS.md) (composition patterns)
- Attacks/vulnerabilities: [VULNERABILITY-SCENARIOS.md](VULNERABILITY-SCENARIOS.md)
  (reproduction and mitigation)

---

## The big picture: stitching the pieces into one service

Take a hypothetical money-transfer service, **PayFoo**, as an example. The
implemented pieces fit together like this.

```
[모바일 앱] --(1) OIDC 로그인(Authorization Code + PKCE)--> [인가 서버]
     |                                                         |
     |  (2) access token(scope: balance.read) 발급 <-----------+
     |
     +--(3) Bearer 토큰으로 잔액 조회--> [API 게이트웨이] --(4) 토큰 introspection--> [인가 서버]
                                              |
                                              +--(5) 라우팅--> [잔액 서비스] --(6) mTLS/Client Credentials--> [정산 서비스]
```

1. **OIDC + PKCE (ch12/ch7)** — authenticate the user, protect the public client
2. **Scope-based access token (ch7)** — delegate "permissions," not a password
3. **Bearer token (ch7)** — attached to every API call
4. **Introspection/Revocation (ch9)** — the gateway checks token validity and
   revocation
5. **Rate Limiting (ch2)** — per-plan quotas, abuse prevention
6. **mTLS / Client Credentials (ch4/ch7)** — trust between services

In other words, a real-world authentication/authorization architecture is a
**composition** of these pieces, and knowing when to pick each one is a design
skill.

---

## Part 1. Practical use of the defensive mechanisms

### OAuth 2.0 Authorization Code + PKCE (ch7)
- **Real-world situation**: when a web/mobile app must call APIs on the user's
  behalf (social login, in-house SSO). PKCE is the de facto standard for SPAs and
  mobile apps that cannot keep a secret.
- **Applications**: "Log in with Kakao/Google," a banking app calling account
  APIs on the user's behalf.
- **Common mistakes**: loose matching of `redirect_uri` (allowing a partial
  match) → token theft. Not applying PKCE to public clients. Still using the
  implicit grant (now discouraged).

### Client Credentials (ch7)
- **Real-world situation**: server↔server communication with no user involved
  (microservices, batch jobs, cron).
- **Applications**: an order service calling an inventory service, a nightly
  settlement batch.
- **Common mistakes**: not distinguishing the scope of human tokens from service
  tokens. Hardcoding the client secret into code/images.

### OIDC ID Token (ch12)
- **Real-world situation**: single sign-on (SSO) and the standard proof of "who
  this user is."
- **Applications**: logging into several in-house systems once, receiving a
  social-login profile.
- **Common mistakes**: omitting validation of the ID token's `aud`/`iss`/`nonce`/
  `exp`, misusing an ID token as an API access token (the principle: an ID token
  is "proof of authentication," an access token is "authorization").

### mTLS (ch4)
- **Real-world situation**: financial/B2B APIs, internal service-mesh
  communication, partner-only integrations.
- **Applications**: open banking, communication between Istio sidecars, payment
  gateway integrations.
- **Common mistakes**: conflating **certificate trust with administrator
  privileges** (→ scenario 4). Not checking certificate revocation (CRL/OCSP).
  No certificate-expiry monitoring.

### DPoP - sender-constrained token (ch8)
- **Real-world situation**: high-risk domains where token theft must not lead to
  reuse (fintech, open banking).
- **Applications**: mitigating the risk of bearer-token theft in public clients
  (SPAs).
- **Common mistakes**: keeping the `jti` replay cache only in the memory of a
  single instance (bypassable in a distributed environment). Skipping validation
  of the proof's `htu`/`htm`/`ath` bindings.

### Token Introspection·Revocation (ch9)
- **Real-world situation**: centralized token validation at an API gateway,
  immediate invalidation on logout/compromise.
- **Applications**: Kong/APISIX and the like doing introspection on every
  request, revoking all tokens on account takeover.
- **Common mistakes**: self-encoded (JWT) tokens **cannot reflect revocation
  through local validation alone** → this must be supplemented with short
  lifetimes + refresh. Leaving the introspection endpoint unprotected.

### UMA (ch10)
- **Real-world situation**: a user shares their own data with a third party
  **based on policy**.
- **Applications**: MyData, healthcare consent sharing, delegating document-
  sharing permissions.
- **Common mistakes**: treating ticket issuance as equivalent to granting access
  (skipping policy evaluation, → scenario 7).

### Federation / JWT·SAML Bearer (ch11)
- **Real-world situation**: when a merger/acquisition or partnership requires
  trusting users from an external organization.
- **Applications**: a partner company's employees accessing your APIs,
  enterprise-to-enterprise SSO.
- **Common mistakes**: inadequate validation of the external assertion's `iss`/
  `aud`/signature/expiry → identity impersonation (→ scenario 6). Not pinning the
  trusted parties (issuers) to a whitelist.

### JWT / JWS / JWE (ch13)
- **Real-world situation**: stateless authentication, passing claims between
  services, encrypted transport of sensitive information.
- **Applications**: the gateway passing user information it validated to
  downstream services via JWS, encrypting sensitive claims with JWE.
- **Common mistakes**: not pinning `alg` (→ scenario 15), a weak HMAC key,
  violating the "sign then encrypt" order, exposing sensitive information as
  plaintext when it was only signed.

### Rate Limiting (ch2)
- **Real-world situation**: API productization (per-plan quotas), mitigating
  brute force/DDoS.
- **Applications**: free 100 calls/day vs. paid unlimited, limiting login
  attempts.
- **Common mistakes**: identifying the client by a client-manipulable header
  (→ scenario 1), a single-instance in-memory counter (distributed bypass). For
  authenticated users, you also need to key on the user ID rather than the IP.

---

## Part 2. What the vulnerabilities mean in practice (pentest and secure coding)

The labs (#8–17) are the items that show up most often in real breaches and
bug bounties.

### IDOR / BOLA (#10) — #1 in OWASP API Security
- **Where**: every read/update API of the `/api/orders/{id}` variety.
- **In practice**: the login is legitimate, but a missing **object-ownership
  check** lets you read someone else's orders, medical records, or documents. A
  frequent cause of large personal-data breaches.
- **Check points**: increment/decrement the id by one, or access it with another
  account's resource id.

### SQL injection (#8)
- **Where**: login, search, filter, and sort parameters.
- **In practice**: authentication bypass, full DB dump. A prime target for the
  `sqlmap` automation tool.
- **Check points**: `'`, `' OR '1'='1`, `UNION SELECT`, time-delay (blind)
  payloads.

### SSRF (#12)
- **Where**: "take a URL and preview/fetch it / webhook" features.
- **In practice**: stealing internal-network or cloud-metadata resources that
  only the server can reach. The classic example is **Capital One (2019)** — a
  breach where SSRF was used to obtain AWS-metadata credentials, leaking over a
  hundred million records.
- **Check points**: try internal addresses like `http://169.254.169.254/`,
  `http://localhost:.../internal`.

### Mass Assignment (#11)
- **Where**: account-info editing, profile updates.
- **In practice**: slipping `{"role":"admin"}`/`{"isVerified":true}` into the
  request body to escalate privileges. Occurs when the whole request object is
  bound to the ORM.

### XSS (#9)
- **Where**: boards, comments, search results, profiles, and anywhere user input
  is shown on screen.
- **In practice**: session-cookie theft, admin-account takeover, phishing, worms.

### OS Command Injection (#14)
- **Where**: admin tools, network diagnostics (ping/nslookup), file conversion
  and image processing.
- **In practice**: full server takeover (RCE). Occurs when input is concatenated
  into a shell.

### Path Traversal (#13)
- **Where**: file download/upload, template/resource loading.
- **In practice**: using `../` to leak config files, secret keys, `/etc/passwd`.

### SSTI / expression injection (#16)
- **Where**: email/report templates, no-code and formula-input features.
- **In practice**: server-side expression evaluation → information disclosure or
  RCE. SpEL for Spring, otherwise Freemarker/Velocity/Jinja2 and the like.

### JWT alg:none · weak key (#15)
- **Where**: when the validation logic is self-implemented.
- **In practice**: forging an admin token, complete authentication bypass. The
  principle is "standard library + pinned alg + strong key."

### NoSQL injection (#17)
- **Where**: MongoDB-based login and search.
- **In practice**: injecting operators like `{"$ne":null}` to log in without a
  password.

---

## Part 3. Three ways to use this project in practice

1. **Developer onboarding / secure-coding training**
   - Call each lab's "vulnerable vs. safe" endpoints directly and compare. Feel
     for yourself why PreparedStatement, output encoding, ownership checks, and
     enforced input types are necessary.
   - Example: put the same payload into `search` (vulnerable) vs. `search-safe`
     (safe) and contrast the results.

2. **Red team / penetration-testing practice**
   - Use as a practice target for Burp Suite, `sqlmap`, and OWASP ZAP.
   - Example: automatically extract with UNION via
     `sqlmap -u "http://localhost:19080/api/lab/sqli/search?name=x"`, and detect
     XSS/SSRF with the ZAP scanner.

3. **CI security regression testing**
   - Turn "safe endpoints must block attack payloads" into automated tests so
     that if a defense breaks during refactoring, the build fails.
   - Example: verify that `' OR '1'='1` → `search-safe` returns 0 records, and
     that `verify-secure` rejects alg:none with a 401 (the reproduction commands
     in the docs become test cases as-is).

---

## Key takeaways

- **Authentication (who you are) alone is not enough; authorization (what you can
  do) is the real line of defense.** No matter how good the OAuth/OIDC you bolt
  on, it collapses if you miss object-level permissions like IDOR (#10) (which is
  why #1 in OWASP API is BOLA).
- **Don't self-implement security features — use vetted standards and libraries,
  and explicitly pin the algorithm and the trusted parties** (alg:none, weak
  keys, and unverified audiences are recurring mistakes).
- **Treat input strictly as data.** In SQL, OS commands, HTML, expressions, or
  query documents — anywhere user input becomes "code/structure," it becomes an
  injection. Parameter binding, output encoding, and type enforcement are the
  common solution.

---

# Appendix A. IDOR / BOLA deep dive

> Related implementation: [`lab/IdorLabController.java`](src/main/java/com/example/apisecurity/lab/IdorLabController.java),
> scenario [#10](VULNERABILITY-SCENARIOS.md)

## A.1 BOLA vs BFLA — what got missed

OWASP API Security divides authorization flaws into two kinds.

- **BOLA (Broken Object Level Authorization, API1)**: failing to check "does this
  caller have the right to access this **object** (order 1002)?" → reading
  someone else's order.
- **BFLA (Broken Function Level Authorization, API5)**: failing to check "does
  this caller have the right to invoke this **function** (the admin delete API)?"
  → a regular user calling an admin endpoint.

The lab's `orders` example is BOLA; ch2's PDP (admin-resource) and ch3's
role-based constraints are BFLA defenses. **You need both** — even if a caller
has endpoint-access rights (BFLA), you must also verify ownership of the objects
handled inside it (BOLA).

## A.2 A common misconception: "using UUIDs makes it safe"

Changing a sequential ID (`1001, 1002`) to a UUID makes **guessing harder but
leaves the vulnerability intact**. The essence of IDOR is not "predictability"
but **"not performing an authorization check on access."** UUIDs get exposed in
logs, referrers, shared links, and inside the app, so they are a mitigation, not
a defense. (That is why the safe endpoint of scenario #10 also **verifies
ownership** regardless of the id's form.)

## A.3 Where do you verify — the data-access layer, not the controller

Vulnerable code is usually "look it up, then return it":

```java
// 취약: id로 찾아서 그냥 반환 (소유권 미확인)
Order o = orderRepository.findById(id);
return o;
```

Three robust defensive patterns:

```java
// (1) 쿼리 자체에 소유자 조건을 박는다 - 가장 견고 (없으면 404)
Order o = orderRepository.findByIdAndOwner(id, currentUser)
        .orElseThrow(() -> new NotFoundException());

// (2) 메서드 보안으로 반환 객체를 사후 검증
@PostAuthorize("returnObject.owner == authentication.name")
public Order getOrder(String id) { ... }

// (3) 서비스 계층에서 명시적 소유권 확인 (lab의 orders-safe 방식)
if (!order.owner().equals(currentUser)) throw new ForbiddenException();
```

**The recommendation is (1)**: "404 if it doesn't exist" doesn't even reveal
whether the resource exists. Blocking in only one controller makes it easy to
miss when you add a new endpoint, so **pushing ownership down into the
repository/service layer** is the safe choice in practice.

## A.4 How to test it in the field (pentest)

1. Log in as account A, capture the resource list/detail, and collect the ids.
2. With account B's token, **try to access A's ids** (if sequential, ±1 fuzzing).
3. Use Burp Suite's **Autorize / Auth Analyzer** extensions to automatically
   compare "replay a high-privilege request with a low-privilege session → is the
   response a 200?"
4. Beyond reads, be sure to check **updates/deletes (PUT/DELETE)** and nested
   resources (`/orders/1002/items`) as well.

## A.5 Verify it yourself with the lab

```bash
# 취약: alice가 bob(1002)의 주문 열람
curl -s "http://localhost:19080/api/lab/idor/orders/1002?asUser=alice"
# 안전: 소유자 아니면 403
curl -s "http://localhost:19080/api/lab/idor/orders-safe/1002?asUser=alice"
```

> A note from practice: a substantial share of large personal-data breaches
> originate from BOLA. The misconception "I'm logged in, so it's safe" is the
> most dangerous one — authentication and object authorization are separate.

---

# Appendix B. mTLS (mutual TLS) deep dive

> Related implementation: [`config/MtlsSecurityConfig.java`](src/main/java/com/example/apisecurity/config/MtlsSecurityConfig.java),
> [`ch4/Ch4Controller.java`](src/main/java/com/example/apisecurity/ch4/Ch4Controller.java),
> scenario [#4](VULNERABILITY-SCENARIOS.md)

## B.1 One-way TLS vs mutual TLS

- **One-way TLS (ordinary HTTPS)**: only the client verifies the **server's**
  identity (the server certificate). The default for web browsing.
- **Mutual TLS (mTLS)**: in the handshake, **the server also requires a
  certificate from the client**, and the client signs with its private key
  (`CertificateVerify`) to prove its identity. Both sides verify each other.

From the handshake's point of view (ch4 summary): the server sends
`CertificateRequest` → the client sends its certificate chain →
`CertificateVerify` (signing the handshake messages so far with the client's
private key) → the server verifies with the client's public key + validates the
chain against a trusted CA in the truststore.

## B.2 The core principle: "trust (truststore) ≠ authorization (permissions)"

The lesson of scenario #4 is the point most often broken in practice. What mTLS
guarantees goes only as far as **"this certificate was signed by a CA we
trust."** **What the subject of that certificate is allowed to do (permissions)
must be decided separately.**

```java
// 취약(#4): 신뢰된 인증서면 CN 무관하게 전원 ROLE_ADMIN
return User.withUsername(cn).authorities("ROLE_ADMIN").build();

// 안전: 인증서의 Subject DN/SAN을 신원 저장소와 매핑해 실제 권한을 조회
UserDetails u = partnerDirectory.lookupByCertificateSubject(subjectDn); // 없으면 인증 실패
// -> 파트너 A의 서비스 계정은 ch5.read, 배치 계정은 ch5.write 처럼 개별 권한
```

From the Spring Security point of view, you extract the CN/SAN with `x509()`'s
`subjectPrincipalRegex`, then wire up a **`UserDetailsService` that maps that
value to a real directory (DB/LDAP)**. If you lump everything together as
"certificate = administrator" like the lab does, then the moment one certificate
is added to the truststore, everyone becomes an administrator.

## B.3 The certificate lifecycle — issuance, rotation, revocation, expiry

Half of real-world mTLS is certificate operations.

- **Issuance**: issue per-service/per-partner certificates via an internal CA
  (or Vault PKI, cert-manager).
- **Rotation**: auto-renew short-lived certificates (e.g. SPIFFE/SPIRE
  auto-rotates SVIDs on an hourly scale).
- **Revocation**: invalidate a leaked certificate via **CRL/OCSP**. This is a
  commonly missed part of mTLS — if you don't check revocation, a stolen
  certificate stays valid until it expires.
- **Expiry monitoring**: outages caused by certificate expiry are a frequent
  cause of major service disruptions.

## B.4 Real-world application examples

- **Open banking/payments**: the UK's OBIE, eIDAS QWAC, and others require mTLS.
  Client certificates identify the institution in bank-fintech API calls.
- **Service mesh**: Istio/Linkerd apply **automatic mTLS** between sidecars,
  securing inter-service identity and encryption with no application-code
  changes.
- **IoT/devices**: embed a certificate in each device to block unauthorized
  devices from connecting.
- **Zero-trust internal networks**: control inter-service access by "certificate
  identity" rather than "network location."

## B.5 Common pitfalls

- Forcing `clientAuth=required` globally on the connector, so that even health
  checks and static resources require a certificate (reduced availability). →
  Applying mTLS **only to specific paths** as in ch4 (optional verification +
  enforcement in a Spring Security filter) is more flexible.
- Not checking revocation (CRL/OCSP).
- Not separating certificate identity from permissions (#4).
- Bundling the private key into images/repositories (→ this project too excludes
  `certs/*.p12,*.pem` via `.gitignore` and generates them locally at runtime with
  `generate-certs.sh`).

## B.6 Verify it yourself with the lab

```bash
./certs/generate-certs.sh
MTLS_ENABLED=true mvn spring-boot:run
# 신뢰된 클라이언트 인증서 -> 200
curl -k --cert certs/client-cert.pem --key certs/client-key.pem https://localhost:8443/api/ch4/whoami
# 인증서 없음 -> 거부
curl -k https://localhost:8443/api/ch4/whoami
```
