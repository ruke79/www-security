# API 보안 패턴 재현 가이드 (Chapter 14 → 데모 매핑)

『Advanced API Security』 **14장 "Patterns and Practices"** 의 10가지 실무 API
보안 솔루션 패턴을, 이 데모 프로젝트(`advancedapisecuritydemo`)의 엔드포인트로
재현하는 방법을 정리한 문서입니다. 각 패턴은 앞선 장들의 구현을 **조합**해서
구성됩니다.

> 실행 전 앱을 먼저 띄우세요. 기본은 19080 평문 HTTP만 열립니다(mTLS는 off).
> 패턴 1(mTLS)만 8443 포트 + 인증서가 필요해 `MTLS_ENABLED=true`로 켜야 합니다.
>
> ```bash
> # 대부분의 패턴(2~10): 그냥 실행 (19080). 포트 충돌 시 APP_PORT로 변경
> mvn spring-boot:run
> #   APP_PORT=29080 mvn spring-boot:run
>
> # 패턴 1(mTLS)까지 실습: 인증서 생성 후 mTLS 켜기
> ./certs/generate-certs.sh
> MTLS_ENABLED=true mvn spring-boot:run
> ```
>
> 아래 명령들은 실제로 앱을 기동해 검증했습니다. 책의 시나리오 설명은
> 요약이며, 데모는 개념을 보여주기 위한 단순화 구현입니다(운영용 아님).

## 패턴 → 데모 매핑 한눈에 보기

| # | 패턴 | 핵심 메커니즘 | 데모 구현 |
|---|---|---|---|
| 1 | Direct Auth + Trusted Subsystem | 웹앱이 mTLS로 백엔드 API 호출 | `ch4` (mTLS, 8443) |
| 2 | SSO + Delegated Access Control | SAML 토큰 → OAuth access token 교환 | `ch11` (assertion → jwt-bearer grant) |
| 3 | SSO + Integrated Windows Auth | IdP를 IWA로 보호(자동 인증) | `ch11` + 개념 설명 |
| 4 | Identity Proxy + Delegated | 내부 IdP가 외부 IdP와 신뢰 브로커링 | `ch11` (외부 IdP federation) |
| 5 | Delegated Access Control + JWT | ID token(JWT) → access token 교환 | `ch12` + `ch11` jwt-bearer |
| 6 | Nonrepudiation + JWS | 사용자 개인키로 JWS 서명 + JWE 암호화 | `ch13` (JWS→JWE) |
| 7 | Chained Access Delegation | API→API 호출 시 토큰 교환 | `ch9b` (chain grant) |
| 8 | Trusted Master Access Delegation | master가 발급한 self-explanatory JWT + introspection | `ch9`/`ch9b` |
| 9 | Resource STS + Delegated | 인터셉터/STS로 SAML 토큰 교환 | `ch5`(broker) + `ch11` |
| 10 | Delegated Access Control + Hidden Credentials | 자격증명 미전송(MAC 토큰) | `ch8` (DPoP, MAC 대체) |

---

## 패턴 1 — Direct Authentication with the Trusted Subsystem

**책 시나리오**: 방화벽 안의 웹앱이 사용자를 인증한 뒤, 신뢰된 하위 시스템으로서
백엔드 API를 호출한다. API는 **mTLS**로 보호한다.

**데모 재현** (`ch4`): 클라이언트 인증서를 제시해야만 접근 가능한 mTLS 엔드포인트.

```bash
./certs/generate-certs.sh                 # 최초 1회 (키/트러스트스토어 생성)
MTLS_ENABLED=true mvn spring-boot:run      # mTLS 커넥터 8443 활성화 (기본은 off)
# 8443도 겹치면: MTLS_ENABLED=true MTLS_PORT=18443 mvn spring-boot:run

# 신뢰된 클라이언트 인증서로 접근 → 200 + 인증서 Subject DN
curl -k --cert certs/client-cert.pem --key certs/client-key.pem \
     https://localhost:8443/api/ch4/whoami

# 인증서 없이 접근 → 거부
curl -k https://localhost:8443/api/ch4/whoami
```

**관찰 포인트**: 사용자를 백엔드 API가 아니라 웹앱(=trusted subsystem)에서
인증하고, 웹앱↔API 구간은 TLS 상호 인증으로 신뢰를 확립한다.

---

## 패턴 2 — Single Sign-On with the Delegated Access Control

**책 시나리오**: SAML 2.0 IdP로 로그인한 뒤, 받은 SAML 토큰을 **SAML grant
type**으로 OAuth access token으로 교환해 백엔드 API에 접근한다(refresh token
없음, access token 수명은 SAML 토큰 수명 이내).

**데모 재현** (`ch11`): SAML/XML 툴링 대신 동일 신뢰 모델의 **JWT bearer
grant(RFC 7523)** 로 구현. 외부 IdP가 서명한 assertion → 우리 인가 서버가 자체
access token 발급.

```bash
# 1. 외부 IdP("Foo Inc.")가 서명한 assertion 획득 (SAML assertion에 대응)
ASSERTION=$(curl -s "http://localhost:19080/api/ch11/external-idp/assertion?user=alice@foo-inc.example" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['assertion'])")

# 2. jwt-bearer grant로 우리 인가 서버의 access token 교환
TOKEN=$(curl -s -u demo-jwtbearer-client:jwtbearer-secret -X POST http://localhost:19080/oauth2/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \
  -d assertion="$ASSERTION" -d scope=ch11.read \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# 3. 교환한 토큰으로 백엔드 API 접근
curl -H "Authorization: Bearer $TOKEN" http://localhost:19080/api/ch11/resource
```

**관찰 포인트**: 사용자 자격증명이 웹앱에 직접 전달되지 않는다 — IdP가 서명한
assertion만 신뢰한다. (책의 SAML grant type과 동일한 out-of-band 신뢰 확립.)

---

## 패턴 3 — Single Sign-On with Integrated Windows Authentication

**책 시나리오**: 패턴 2와 같으나, 사용자가 Windows 도메인에 이미 로그인돼 있으면
IdP를 **IWA**로 보호해 자격증명 입력 없이 자동 인증한다. IdP 인증 방식만
IWA로 바뀌고 나머지 흐름(SAML → access token 교환)은 동일하다.

**데모 재현**: IWA(Kerberos/SPNEGO)는 Windows 도메인 환경이 필요해 이 데모의
범위 밖입니다. **흐름 자체는 패턴 2와 동일**하므로, 패턴 2의 명령을 그대로
사용하고 "assertion을 발급하는 IdP의 인증 방식만 IWA로 교체된다"고 이해하면
됩니다.

---

## 패턴 4 — Identity Proxy with the Delegated Access Control

**책 시나리오**: 자사 직원뿐 아니라 신뢰 파트너사 직원도 접근한다. 내부 앱은
**자기 도메인의 IdP만 신뢰**하고, 내부 IdP가 외부 IdP와의 신뢰를
브로커링(필요 시 프로토콜 변환)한다.

**데모 재현** (`ch11`): "Foo Inc."는 우리가 통제하지 않는 **독립된 외부 IdP**로,
자체 RSA 키로 assertion을 서명한다. 우리 인가 서버는 그 외부 IdP를 신뢰하도록
명시적으로 설정(`ExternalIdpConfig`)돼 있어, 외부 사용자의 assertion을 받아
자체 토큰을 발급한다 — 이것이 곧 identity proxy 브로커링이다.

```bash
# 외부 파트너사 사용자 신원으로 assertion 발급 → 우리 인가 서버가 신뢰해 토큰 발급
ASSERTION=$(curl -s "http://localhost:19080/api/ch11/external-idp/assertion?user=bob@partner.example" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['assertion'])")
TOKEN=$(curl -s -u demo-jwtbearer-client:jwtbearer-secret -X POST http://localhost:19080/oauth2/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \
  -d assertion="$ASSERTION" -d scope=ch11.read \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
curl -H "Authorization: Bearer $TOKEN" http://localhost:19080/api/ch11/resource
```

> ⚠️ 이 흐름의 보안 함정(외부 IdP assertion을 임의 발급 + audience 미검증으로
> 인한 신원 사칭)은 [`VULNERABILITY-SCENARIOS.md`](VULNERABILITY-SCENARIOS.md)
> 시나리오 6에서 다룹니다.

---

## 패턴 5 — Delegated Access Control with the JSON Web Token

**책 시나리오**: OpenID Connect IdP로 로그인해 받은 **ID token(JWT)** 을,
OIDC 서버와 인가 서버가 다를 때 **JWT bearer grant**로 access token으로
교환한다.

**데모 재현** (`ch12` + `ch11`): OIDC ID token 발급/검증은 `ch12`가, JWT를
access token으로 교환하는 jwt-bearer grant는 `ch11`이 담당한다.

```bash
# 1. OIDC ID token 발급 (인증된 사용자 신원의 assertion)
IDT=$(curl -s -X POST http://localhost:19080/api/ch12/id-token/issue -H 'Content-Type: application/json' \
  -d '{"subject":"alice@foo.com","clientId":"demo-client","nonce":"n-123"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['id_token'])")

# 2. ID token 검증 (signature + iss + aud + nonce)
curl -s -X POST http://localhost:19080/api/ch12/id-token/validate -H 'Content-Type: application/json' \
  -d "{\"idToken\":\"$IDT\",\"expectedClientId\":\"demo-client\",\"expectedNonce\":\"n-123\"}"
```

> **데모상의 정확한 뉘앙스**: `ch12`의 ID token은 **우리 인가 서버의 키**로
> 서명됩니다. 반면 `ch11`의 jwt-bearer grant는 **외부 IdP 키**로 서명된
> assertion을 검증하도록 구성돼 있습니다. 따라서 "ID token을 그대로
> jwt-bearer로 교환"하려면 두 서버가 동일 도메인/키일 때만 성립합니다(책의
> Note도 동일하게 지적: OIDC 서버와 인가 서버가 같으면 애초에 교환이 불필요).
> 서로 다른 도메인 시나리오는 패턴 2/4의 외부 IdP assertion 흐름으로
> 재현하세요.

---

## 패턴 6 — Nonrepudiation with the JSON Web Signature

**책 시나리오**: 금융 API 등 부인 방지가 필수인 경우. 기관이 사용자별 키쌍을
발급하고 공개 인증서만 보관한다. 모든 API 호출을 **사용자 개인키로 JWS 서명**한
뒤 **기관 공개키로 JWE 암호화**한다(서명 먼저, 암호화 나중 — 법적 수용성).

**데모 재현** (`ch13`): JWS 서명·검증과 JWE 암호화·복호화를 각각 재현.

```bash
# 1. 사용자 개인키로 페이로드 서명 (JWS, RS256) — 부인 방지의 핵심
JWS=$(curl -s -X POST http://localhost:19080/api/ch13/jws/rsa/sign -H 'Content-Type: application/json' \
  -d '{"subject":"customer-42","issuer":"mobile-app"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['jws'])")

# 2. 서명 검증 (수신 측: 신뢰된 발급자 서명인지 확인 → 위조 불가 증명)
curl -s -X POST http://localhost:19080/api/ch13/jws/rsa/verify -H 'Content-Type: application/json' \
  -d "{\"jwt\":\"$JWS\"}"

# 3. 기밀성까지 필요하면 JWE로 암호화 (RSA-OAEP-256 + A128GCM, compact = 5부분)
#    책의 규칙: "서명 먼저 → 암호화" 순서를 따른다.
JWE=$(curl -s -X POST http://localhost:19080/api/ch13/jwe/encrypt -H 'Content-Type: application/json' \
  -d '{"subject":"customer-42"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['jwe'])")
curl -s -X POST http://localhost:19080/api/ch13/jwe/decrypt -H 'Content-Type: application/json' \
  -d "{\"jwt\":\"$JWE\"}"
```

**관찰 포인트**: 서명은 "누가 했는지"를 위조 불가하게 증명(부인 방지),
암호화는 "제3자가 못 읽게"(기밀성). 두 목적이 다르며 병용 시 서명이 먼저다.

---

## 패턴 7 — Chained Access Delegation

**책 시나리오**: 모바일 앱이 Water API를 호출하고, Water API가 다시 사용자를
대신해 MyHealth API를 호출한다. audience 제약 때문에 받은 토큰을 그대로
넘길 수 없으므로 **Chain Grant Type**으로 새 토큰을 교환한다.

**데모 재현** (`ch9b`): 원본 access token을 더 좁은(또는 동일) scope의 새 토큰으로
교환. refresh token은 발급되지 않는다.

```bash
# 1. 클라이언트가 첫 번째 API용 토큰 획득
TOKEN=$(curl -s -u demo-service-client:service-secret -X POST http://localhost:19080/oauth2/token \
  -d grant_type=client_credentials -d scope='ch7.read ch7.write' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# 2. 첫 번째 API가 두 번째 API 호출용으로 토큰을 chain 교환 (좁은 scope + 다른 audience)
curl -s -X POST http://localhost:19080/api/ch9b/chain/token -H 'Content-Type: application/json' \
  -d "{\"oauthToken\":\"$TOKEN\",\"scope\":\"ch7.read\",\"audience\":\"myhealth-api\"}"

# 3. 원본에 없던 scope로 상향 시도 → 거부
curl -s -X POST http://localhost:19080/api/ch9b/chain/token -H 'Content-Type: application/json' \
  -d "{\"oauthToken\":\"$TOKEN\",\"scope\":\"admin.super\"}"   # -> invalid_scope
```

**관찰 포인트**: 교환된 토큰은 원본 scope의 **부분집합**만 가지며, refresh
token이 없어 재교환하려면 원본 토큰을 다시 제시해야 한다.

---

## 패턴 8 — Trusted Master Access Delegation

**책 시나리오**: 부서마다 자체 인가 서버 + 중앙(master) 인가 서버가 있다.
master가 발급한 **self-explanatory JWT(iss 포함)** 로 어느 부서 API든 접근한다.
부서 인가 서버는 JWT 헤더에서 발급자를 확인하고, master의 **introspection**
엔드포인트로 토큰 상태·scope를 조회한 뒤 (필요 시 XACML PDP로) 인가한다.

**데모 재현** (`ch9`/`ch9b`): 표준 introspection으로 "어느 서버가 발급했고 아직
유효한지"를 확인하는 부분을 재현.

```bash
# master(=우리 인가 서버)가 JWT access token 발급
TOKEN=$(curl -s -u demo-service-client:service-secret -X POST http://localhost:19080/oauth2/token \
  -d grant_type=client_credentials -d scope=ch7.read \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# 부서 인가 서버가 master introspection으로 토큰 검증 (active/scope/client_id/aud)
curl -s -u demo-service-client:service-secret -X POST http://localhost:19080/oauth2/introspect \
  -d "token=$TOKEN"
```

**관찰 포인트**: introspection 응답의 `active`/`scope`/`aud`로 부서 인가 서버가
접근 여부를 결정할 수 있다(책에서는 이 응답으로 XACML 요청을 만들어 PDP에
질의). 토큰이 JWT라 `iss` 클레임으로 발급자를 즉시 식별할 수 있다.

---

## 패턴 9 — Resource STS with the Delegated Access Control

**책 시나리오**: 클라이언트·API를 변경하지 않고 보안을 추가한다. 양쪽에
인터셉터(PEP)를 두고, 클라이언트 지역 STS가 발급한 SAML 토큰을 API 지역 STS가
교환(WS-Trust)한 뒤, 최종적으로 **SAML grant type**으로 access token을
교환한다.

**데모 재현** (`ch5` broker + `ch11`): WS-Trust/SOAP STS는 범위 밖이지만, 핵심인
**토큰 교환(token exchange)** 은 `ch5`의 브로커드 위임으로, **assertion → access
token** 단계는 `ch11`로 재현한다.

```bash
# (a) ch5 브로커드 위임: 원본 토큰을 다른 audience/좁은 scope로 교환 (STS 토큰 교환에 대응)
LTOKEN=$(curl -s -u lucidchart-client:lucidchart-secret -X POST http://localhost:19080/oauth2/token \
  -d grant_type=client_credentials -d scope='ch5.read ch5.write' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
curl -s -H "Authorization: Bearer $LTOKEN" -X POST http://localhost:19080/api/ch5/broker/exchange \
  -H 'Content-Type: application/json' -d '{"audience":"api-region-sts","scope":["ch5.read"]}'

# (b) ch11: 최종적으로 (외부 IdP가 서명한) assertion을 access token으로 교환 → API 접근
#     위 패턴 2의 명령과 동일 흐름
```

**관찰 포인트**: 여러 신뢰 도메인을 넘나들 때 "토큰을 그 지역이 이해하는 다른
토큰으로 반복 교환"하는 것이 핵심 아이디어다.

---

## 패턴 10 — Delegated Access Control with Hidden Credentials

**책 시나리오**: 자격증명이 전송선을 타면 안 될 때. HTTP Digest 또는 **OAuth 2.0
MAC 토큰**을 쓴다. MAC 토큰은 API별 발급·개별 폐기가 가능해 더 우수하다.

**데모 재현** (`ch8`): 폐기된 MAC Token Profile 대신 현대 표준 **DPoP(RFC 9449)**
로 "토큰 비밀을 전송선에 싣지 않는 소유 증명(PoP)"을 재현.

```bash
# 1. 데모 키쌍 생성 (privateJwk는 서버가 문자열로 받으므로 json.dumps로 감싸 전달)
KEYS=$(curl -s -X POST http://localhost:19080/api/ch8/dpop/keypair)
PRIVATE_JWK=$(echo "$KEYS" | python3 -c "import sys,json;print(json.dumps(json.load(sys.stdin)['privateJwk']))")

# 2. 토큰 요청용 DPoP proof 서명
PROOF=$(curl -s -X POST http://localhost:19080/api/ch8/dpop/proof -H 'Content-Type: application/json' \
  -d "{\"privateJwk\": $PRIVATE_JWK, \"htm\":\"POST\", \"htu\":\"http://localhost:19080/api/ch8/dpop/token\"}" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['proof'])")

# 3. DPoP-바인딩 access token 획득
TOKEN=$(curl -s -X POST http://localhost:19080/api/ch8/dpop/token -H "DPoP: $PROOF" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# 4. 리소스 요청용 새 proof(ath 바인딩) 서명 후, 토큰 + proof 동시 제시
PROOF2=$(curl -s -X POST http://localhost:19080/api/ch8/dpop/proof -H 'Content-Type: application/json' \
  -d "{\"privateJwk\": $PRIVATE_JWK, \"htm\":\"GET\", \"htu\":\"http://localhost:19080/api/ch8/protected/resource\", \"accessToken\":\"$TOKEN\"}" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['proof'])")
curl -H "Authorization: Bearer $TOKEN" -H "DPoP: $PROOF2" http://localhost:19080/api/ch8/protected/resource
```

**관찰 포인트**: bearer 토큰과 달리, 토큰을 훔쳐도 **개인키가 없으면** 유효한
proof를 만들 수 없어 사용 불가하다(= "hidden credentials"의 현대적 실현).

---

## 참고

- 각 장의 상세 요약: [`BOOK-SUMMARY.md`](BOOK-SUMMARY.md)
- 데모 코드에서 연습 가능한 취약점 시나리오: [`VULNERABILITY-SCENARIOS.md`](VULNERABILITY-SCENARIOS.md)
- 챕터별 엔드포인트/실행 방법: [`README.md`](README.md)
