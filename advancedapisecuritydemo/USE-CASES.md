# 실무 활용 가이드 (Use Cases)

이 문서는 `advancedapisecuritydemo`에 구현된 각 메커니즘·취약점 시나리오가
**실제 실무에서 어떻게 쓰이는지**를 정리한 것입니다. 각 항목은
"실무 상황 → 이 프로젝트의 무엇이 대응되는가 → 흔한 실수" 형식입니다.

- 방어 메커니즘: [BOOK-SUMMARY.md](BOOK-SUMMARY.md) (책 챕터 요약),
  [PATTERNS.md](PATTERNS.md) (조합 패턴)
- 공격/취약점: [VULNERABILITY-SCENARIOS.md](VULNERABILITY-SCENARIOS.md) (재현·대응)

---

## 큰 그림: 하나의 서비스로 조각 잇기

가상의 송금 서비스 **PayFoo**를 예로 들면, 구현된 조각들이 이렇게 조립됩니다.

```
[모바일 앱] --(1) OIDC 로그인(Authorization Code + PKCE)--> [인가 서버]
     |                                                         |
     |  (2) access token(scope: balance.read) 발급 <-----------+
     |
     +--(3) Bearer 토큰으로 잔액 조회--> [API 게이트웨이] --(4) 토큰 introspection--> [인가 서버]
                                              |
                                              +--(5) 라우팅--> [잔액 서비스] --(6) mTLS/Client Credentials--> [정산 서비스]
```

1. **OIDC + PKCE (ch12/ch7)** — 사용자 인증, 공개 클라이언트 보호
2. **Scope 기반 access token (ch7)** — 비밀번호가 아니라 "권한"을 위임
3. **Bearer 토큰 (ch7)** — 매 API 호출에 첨부
4. **Introspection/Revocation (ch9)** — 게이트웨이가 토큰 유효성·폐기 확인
5. **Rate Limiting (ch2)** — 요금제별 쿼터, 남용 차단
6. **mTLS / Client Credentials (ch4/ch7)** — 서비스 간 신뢰

즉 실무 인증·인가 아키텍처는 이 조각들의 **조합**이며, 각 조각을 언제 고르는지가
설계 역량입니다.

---

## 1부. 방어 메커니즘의 실무 활용

### OAuth 2.0 Authorization Code + PKCE (ch7)
- **실무 상황**: 웹/모바일 앱이 사용자를 대신해 API를 호출해야 할 때(소셜 로그인,
  자사 SSO). PKCE는 시크릿을 숨길 수 없는 SPA·모바일의 사실상 표준.
- **적용**: "카카오/구글로 로그인", 뱅킹 앱이 사용자 대신 계좌 API 호출.
- **흔한 실수**: `redirect_uri`를 느슨하게 매칭(부분 일치 허용) → 토큰 탈취.
  공개 클라이언트에 PKCE 미적용. Implicit grant를 아직도 사용(현재 비권장).

### Client Credentials (ch7)
- **실무 상황**: 사용자 없이 서버↔서버가 통신(마이크로서비스, 배치, 크론).
- **적용**: 주문 서비스가 재고 서비스 호출, 야간 정산 배치.
- **흔한 실수**: 사람용 토큰과 서비스용 토큰의 scope를 구분하지 않음. client
  secret을 코드/이미지에 하드코딩.

### OIDC ID Token (ch12)
- **실무 상황**: 단일 로그인(SSO)과 "이 사용자가 누구인가"의 표준 증명.
- **적용**: 사내 여러 시스템 한 번 로그인, 소셜 로그인의 프로필 수신.
- **흔한 실수**: ID token의 `aud`/`iss`/`nonce`/`exp` 검증 누락, ID token을 API
  접근 토큰처럼 오용(ID token은 "인증 증명", access token은 "인가"가 원칙).

### mTLS (ch4)
- **실무 상황**: 금융/B2B API, 서비스 메시 내부 통신, 파트너사 전용 연동.
- **적용**: 오픈뱅킹, Istio 사이드카 간 통신, 결제 대행사 연동.
- **흔한 실수**: **인증서 신뢰 = 관리자 권한**으로 뭉뚱그림(→ 시나리오 4). 인증서
  폐기(CRL/OCSP) 미확인. 인증서 만료 모니터링 부재.

### DPoP - sender-constrained token (ch8)
- **실무 상황**: 토큰 탈취 시 재사용을 막아야 하는 고위험 도메인(핀테크, 오픈뱅킹).
- **적용**: 공개 클라이언트(SPA)에서 bearer 토큰 탈취 위험 완화.
- **흔한 실수**: `jti` 재전송 캐시를 단일 인스턴스 메모리에만 둠(분산 환경에서
  우회). proof의 `htu`/`htm`/`ath` 바인딩 검증 생략.

### Token Introspection·Revocation (ch9)
- **실무 상황**: API 게이트웨이의 중앙 토큰 검증, 로그아웃/침해 시 즉시 무효화.
- **적용**: Kong/APISIX 등이 매 요청 introspection, 계정 탈취 시 전 토큰 폐기.
- **흔한 실수**: 자체 인코딩(JWT) 토큰은 **로컬 검증만으로는 폐기 반영 불가** →
  수명을 짧게 + refresh로 보완해야 함. introspection 엔드포인트 미보호.

### UMA (ch10)
- **실무 상황**: 사용자가 자기 데이터를 제3자에게 **정책 기반으로** 공유.
- **적용**: 마이데이터, 헬스케어 동의 공유, 문서 공유 권한 위임.
- **흔한 실수**: 티켓 발급 = 곧 접근 허용으로 처리(정책 평가 생략, → 시나리오 7).

### Federation / JWT·SAML Bearer (ch11)
- **실무 상황**: 인수합병·제휴로 외부 조직 사용자를 신뢰해야 할 때.
- **적용**: 파트너사 직원의 자사 API 접근, 기업 간 SSO.
- **흔한 실수**: 외부 assertion의 `iss`/`aud`/서명/만료 검증 미흡 → 신원 사칭
  (→ 시나리오 6). 신뢰 대상(발급자)을 화이트리스트로 고정하지 않음.

### JWT / JWS / JWE (ch13)
- **실무 상황**: 무상태 인증, 서비스 간 클레임 전달, 민감정보 암호화 전송.
- **적용**: 게이트웨이가 검증한 사용자 정보를 JWS로 하위 서비스에 전달, 민감
  클레임은 JWE로 암호화.
- **흔한 실수**: `alg` 고정 안 함(→ 시나리오 15), 약한 HMAC 키, "서명 후 암호화"
  순서 위반, 민감정보를 서명만 하고 평문으로 노출.

### Rate Limiting (ch2)
- **실무 상황**: API 상품화(요금제별 쿼터), 무차별 대입·DDoS 완화.
- **적용**: 무료 100회/일 vs 유료 무제한, 로그인 시도 제한.
- **흔한 실수**: 클라이언트가 조작 가능한 헤더로 식별(→ 시나리오 1), 단일 인스턴스
  메모리 카운터(분산 우회). 인증 사용자는 IP가 아닌 사용자 ID 기준 병행 필요.

---

## 2부. 취약점의 실무적 의미 (펜테스트·시큐어코딩)

lab(#8–17)은 실제 침해사고·버그바운티에서 가장 자주 나오는 항목들입니다.

### IDOR / BOLA (#10) — OWASP API 보안 1위
- **어디서**: `/api/orders/{id}`류 모든 조회/수정 API.
- **실무 의미**: 로그인은 정상인데 **객체 소유권 검증**을 빠뜨려 남의 주문·진료
  기록·문서를 열람. 대형 개인정보 유출의 단골 원인.
- **점검 포인트**: id를 1씩 증감하거나 다른 계정의 리소스 id로 접근해 본다.

### SQL 인젝션 (#8)
- **어디서**: 로그인·검색·필터·정렬 파라미터.
- **실무 의미**: 인증 우회, DB 전체 덤프. `sqlmap` 자동화 도구의 주 표적.
- **점검 포인트**: `'`, `' OR '1'='1`, `UNION SELECT`, 시간지연(blind) 페이로드.

### SSRF (#12)
- **어디서**: "URL을 입력받아 미리보기/가져오기/웹훅" 기능.
- **실무 의미**: 서버만 접근 가능한 내부망·클라우드 메타데이터 탈취.
  대표적으로 **Capital One(2019)** — SSRF로 AWS 메타데이터의 자격증명을 얻어
  1억여 건이 유출된 사고 유형.
- **점검 포인트**: `http://169.254.169.254/`, `http://localhost:.../internal` 등
  내부 주소를 넣어 본다.

### Mass Assignment (#11)
- **어디서**: 회원정보 수정, 프로필 업데이트.
- **실무 의미**: 요청 바디에 `{"role":"admin"}`·`{"isVerified":true}`를 끼워
  권한 상승. ORM에 요청 객체를 통째로 바인딩할 때 발생.

### XSS (#9)
- **어디서**: 게시판·댓글·검색 결과·프로필 등 사용자 입력이 화면에 표시되는 곳.
- **실무 의미**: 세션 쿠키 탈취, 관리자 계정 장악, 피싱, 웜.

### OS Command Injection (#14)
- **어디서**: 관리 도구, 네트워크 진단(ping/nslookup), 파일 변환·이미지 처리.
- **실무 의미**: 서버 완전 장악(RCE). 셸에 입력을 연결할 때 발생.

### Path Traversal (#13)
- **어디서**: 파일 다운로드/업로드, 템플릿·리소스 로딩.
- **실무 의미**: `../`로 설정파일·비밀키·`/etc/passwd` 유출.

### SSTI / 표현식 인젝션 (#16)
- **어디서**: 이메일/리포트 템플릿, 노코드·수식 입력 기능.
- **실무 의미**: 서버측 표현식 평가 → 정보 노출·RCE. Spring이면 SpEL, 그 외
  Freemarker/Velocity/Jinja2 등.

### JWT alg:none · 약한 키 (#15)
- **어디서**: 검증 로직을 자체 구현한 경우.
- **실무 의미**: 관리자 토큰 위조, 인증 완전 우회. "표준 라이브러리 + alg 고정 +
  강한 키"가 원칙.

### NoSQL 인젝션 (#17)
- **어디서**: MongoDB 기반 로그인·검색.
- **실무 의미**: `{"$ne":null}` 같은 연산자 주입으로 비밀번호 없이 로그인.

---

## 3부. 이 프로젝트를 실무에 쓰는 3가지 방법

1. **개발자 온보딩 / 시큐어코딩 교육**
   - 각 lab의 "취약 vs 안전" 엔드포인트를 직접 호출해 비교. 왜 PreparedStatement·
     출력 인코딩·소유권 검증·입력 타입 강제가 필요한지 체감.
   - 예: `search`(취약) vs `search-safe`(안전)에 같은 페이로드를 넣어 결과 대조.

2. **레드팀 / 모의해킹 훈련**
   - Burp Suite·`sqlmap`·OWASP ZAP의 연습 표적으로 사용.
   - 예: `sqlmap -u "http://localhost:19080/api/lab/sqli/search?name=x"`로 UNION
     자동 추출, ZAP 스캐너로 XSS/SSRF 탐지.

3. **CI 보안 회귀 테스트**
   - "안전 엔드포인트는 공격 페이로드를 차단해야 한다"를 자동 테스트로 만들어,
     리팩터링 중 방어가 깨지면 빌드를 실패시킴.
   - 예: `' OR '1'='1` → `search-safe`는 0건, `verify-secure`는 alg:none을 401로
     거부하는지 검증(문서의 재현 명령이 그대로 테스트 케이스가 됨).

---

## 핵심 교훈

- **인증(누구인가)만으로는 부족하고, 인가(무엇을 할 수 있나)가 진짜 방어선**입니다.
  훌륭한 OAuth/OIDC를 붙여도 IDOR(#10)처럼 객체 단위 권한을 빠뜨리면 무너집니다
  (그래서 OWASP API 1위가 BOLA입니다).
- **보안 기능을 자체 구현하지 말고 검증된 표준·라이브러리를 쓰고, 알고리즘·신뢰
  대상을 명시적으로 고정**하세요(alg:none·약한 키·audience 미검증이 반복되는 실수).
- **입력은 데이터로만 다루세요.** SQL·OS 명령·HTML·표현식·쿼리 문서 어디서든
  사용자 입력이 "코드/구조"가 되는 순간 인젝션이 됩니다. 파라미터 바인딩·출력
  인코딩·타입 강제가 공통 해법입니다.

---

# 부록 A. IDOR / BOLA 심화

> 관련 구현: [`lab/IdorLabController.java`](src/main/java/com/example/apisecurity/lab/IdorLabController.java),
> 시나리오 [#10](VULNERABILITY-SCENARIOS.md)

## A.1 BOLA vs BFLA — 무엇을 놓쳤는가

OWASP API 보안에는 인가 결함이 두 종류로 나뉩니다.

- **BOLA (Broken Object Level Authorization, API1)**: "이 **객체**(주문 1002)에
  접근할 권한이 있는가?"를 안 봄. → 남의 주문을 열람.
- **BFLA (Broken Function Level Authorization, API5)**: "이 **기능**(관리자 삭제
  API)을 호출할 권한이 있는가?"를 안 봄. → 일반 사용자가 관리자 엔드포인트 호출.

lab의 `orders` 예시는 BOLA, ch2의 PDP(admin-resource)나 ch3의 역할 기반 제약은
BFLA 방어에 해당합니다. **둘 다 필요합니다** — 엔드포인트 접근 권한(BFLA)이
있어도 그 안에서 다루는 객체의 소유권(BOLA)을 또 확인해야 합니다.

## A.2 흔한 착각: "UUID를 쓰면 안전하다"

순차 ID(`1001, 1002`)를 UUID로 바꾸면 **추측은 어려워지지만 취약점은 그대로**
입니다. IDOR의 본질은 "예측 가능성"이 아니라 **"접근 시 인가 검증을 안 한다"**는
것입니다. UUID는 로그·리퍼러·공유 링크·앱 내부에 노출되므로 방어가 아니라 완화책
일 뿐입니다. (그래서 시나리오 #10의 안전 엔드포인트도 id 형태와 무관하게
**소유권을 검증**합니다.)

## A.3 어디서 검증하나 — 컨트롤러가 아니라 데이터 접근 계층

취약 코드는 보통 "조회한 뒤 반환"입니다:

```java
// 취약: id로 찾아서 그냥 반환 (소유권 미확인)
Order o = orderRepository.findById(id);
return o;
```

세 가지 견고한 방어 패턴:

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

**권장은 (1)**: "없으면 404"라 리소스 존재 여부조차 노출하지 않습니다. 컨트롤러
한 곳에서만 막으면 새 엔드포인트를 추가할 때 빠지기 쉬우므로, **리포지토리/서비스
계층에 소유권을 밀어 넣는 것**이 실무에서 안전합니다.

## A.4 실전 점검 방법 (펜테스트)

1. 계정 A로 로그인해 리소스 목록/상세를 캡처하고 id를 수집.
2. 계정 B의 토큰으로 **A의 id에 접근**해 본다(순차라면 ±1 fuzzing).
3. Burp Suite의 **Autorize / Auth Analyzer** 확장으로 "저권한 세션으로 고권한
   요청 재생 → 응답이 200인가"를 자동 비교.
4. 조회뿐 아니라 **수정/삭제(PUT/DELETE)** 와 중첩 리소스(`/orders/1002/items`)도
   반드시 확인.

## A.5 lab로 직접 확인

```bash
# 취약: alice가 bob(1002)의 주문 열람
curl -s "http://localhost:19080/api/lab/idor/orders/1002?asUser=alice"
# 안전: 소유자 아니면 403
curl -s "http://localhost:19080/api/lab/idor/orders-safe/1002?asUser=alice"
```

> 실무 참고: 대형 개인정보 유출의 상당수가 BOLA에서 비롯됩니다. "로그인은
> 됐으니 안전하다"는 착각이 가장 위험합니다 — 인증과 객체 인가는 별개입니다.

---

# 부록 B. mTLS(상호 TLS) 심화

> 관련 구현: [`config/MtlsSecurityConfig.java`](src/main/java/com/example/apisecurity/config/MtlsSecurityConfig.java),
> [`ch4/Ch4Controller.java`](src/main/java/com/example/apisecurity/ch4/Ch4Controller.java),
> 시나리오 [#4](VULNERABILITY-SCENARIOS.md)

## B.1 단방향 TLS vs 상호 TLS

- **단방향 TLS(일반 HTTPS)**: 클라이언트만 **서버**의 신원을 검증(서버 인증서).
  웹 브라우징의 기본.
- **상호 TLS(mTLS)**: 핸드셰이크에서 **서버도 클라이언트에게 인증서를 요구**하고,
  클라이언트가 개인키로 서명(`CertificateVerify`)해 신원을 증명. 양쪽이 서로를
  검증합니다.

핸드셰이크 관점(ch4 요약): 서버 `CertificateRequest` → 클라이언트가 인증서 체인
전송 → `CertificateVerify`(그동안의 핸드셰이크 메시지를 클라이언트 개인키로 서명)
→ 서버가 클라이언트 공개키로 검증 + 트러스트스토어의 신뢰 CA로 체인 검증.

## B.2 핵심 원칙: "신뢰(truststore) ≠ 인가(권한)"

시나리오 #4의 교훈이 실무에서 가장 자주 깨지는 지점입니다. mTLS가 보장하는 것은
**"이 인증서는 우리가 신뢰하는 CA가 서명했다"**까지입니다. 그 인증서의 **주체가
무엇을 할 수 있는지(권한)는 별도로 결정**해야 합니다.

```java
// 취약(#4): 신뢰된 인증서면 CN 무관하게 전원 ROLE_ADMIN
return User.withUsername(cn).authorities("ROLE_ADMIN").build();

// 안전: 인증서의 Subject DN/SAN을 신원 저장소와 매핑해 실제 권한을 조회
UserDetails u = partnerDirectory.lookupByCertificateSubject(subjectDn); // 없으면 인증 실패
// -> 파트너 A의 서비스 계정은 ch5.read, 배치 계정은 ch5.write 처럼 개별 권한
```

Spring Security 관점에서는 `x509()`의 `subjectPrincipalRegex`로 CN/SAN을 추출한
뒤, **그 값을 진짜 디렉터리(DB/LDAP)와 매핑하는 `UserDetailsService`** 를
연결해야 합니다. lab처럼 "인증서 = 관리자"로 뭉뚱그리면 트러스트스토어에 인증서가
하나 추가되는 순간 전원이 관리자가 됩니다.

## B.3 인증서 수명주기 — 발급·회전·폐기·만료

실무 mTLS의 절반은 인증서 운영입니다.

- **발급**: 사내 CA(또는 Vault PKI, cert-manager)로 서비스/파트너별 인증서 발급.
- **회전(rotation)**: 짧은 수명 인증서를 자동 갱신(예: SPIFFE/SPIRE는 수 시간
  단위 SVID를 자동 회전).
- **폐기(revocation)**: 유출 시 **CRL/OCSP**로 무효화. mTLS에서 흔히 빠지는 부분
  — 폐기 확인을 안 하면 탈취된 인증서가 만료까지 유효합니다.
- **만료 모니터링**: 인증서 만료로 인한 장애가 대형 서비스 중단의 단골 원인.

## B.4 실무 적용 예시

- **오픈뱅킹/결제**: 영국 OBIE, eIDAS QWAC 등은 mTLS를 필수로 요구. 은행-핀테크
  간 API 호출에서 클라이언트 인증서로 기관을 식별.
- **서비스 메시**: Istio/Linkerd는 사이드카 간 통신에 **자동 mTLS**를 적용해,
  애플리케이션 코드 변경 없이 서비스 간 신원과 암호화를 확보.
- **IoT/디바이스**: 디바이스마다 인증서를 심어 무단 기기의 접속을 차단.
- **제로 트러스트 내부망**: "네트워크 위치"가 아니라 "인증서 신원"으로 서비스 간
  접근을 통제.

## B.5 흔한 함정

- 커넥터 전역 `clientAuth=required`로 강제해 헬스체크·정적자원까지 인증서를
  요구(가용성 저하). → ch4처럼 **특정 경로에만** mTLS를 적용(optional 검증 +
  Spring Security 필터에서 강제)하는 편이 유연.
- 폐기(CRL/OCSP) 미확인.
- 인증서 신원과 권한을 분리하지 않음(#4).
- 개인키를 이미지/리포지토리에 포함(→ 이 프로젝트도 `certs/*.p12,*.pem`을
  `.gitignore`로 제외하고, 실행 시 `generate-certs.sh`로 로컬 생성).

## B.6 lab로 직접 확인

```bash
./certs/generate-certs.sh
MTLS_ENABLED=true mvn spring-boot:run
# 신뢰된 클라이언트 인증서 -> 200
curl -k --cert certs/client-cert.pem --key certs/client-key.pem https://localhost:8443/api/ch4/whoami
# 인증서 없음 -> 거부
curl -k https://localhost:8443/api/ch4/whoami
```
