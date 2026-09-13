# 『Advanced API Security』 장별 상세 요약 (한글)

> 원서: **Prabath Siriwardena, _Advanced API Security: Securing APIs with
> OAuth 2.0, OpenID Connect, JWS, and JWE_** (Apress, 1st ed.)
>
> 이 문서는 `advancedapisecuritydemo` 데모 프로젝트가 기반으로 삼은 위 책의
> 장별 내용을 한글로 상세 요약한 것입니다. **2~14장 전체(6·7·8·9·10·12·13·14장
> 포함)를 책 원문을 직접 읽고 요약**했습니다. (초판 문서에서 원문 부재로
> 보충 처리했던 7·8·9·10장은 온전한 PDF를 확보하여 원문 기반 요약으로
> 교체했습니다. 원서 목차의 1장(서론)은 제공되지 않았습니다.)

## 전체 구성 한눈에 보기

| 장 | 제목 | 핵심 주제 | 원문 |
|---|---|---|---|
| 2 | Security by Design | 보안 설계 원칙, CIA 삼요소, 위협 모델링 | ✅ 원문 |
| 3 | HTTP Basic/Digest Authentication | 사용자명/비밀번호 기반 인증의 기초 | ✅ 원문 |
| 4 | Mutual Authentication with TLS | TLS 상호 인증(mTLS), TLS 동작 원리 | ✅ 원문 |
| 5 | Identity Delegation | 위임 접근의 역사(OAuth 이전) | ✅ 원문 |
| 6 | OAuth 1.0 | 서명 기반 토큰 댄스, 3-legged/2-legged | ✅ 원문 |
| 7 | OAuth 2.0 | OAuth 2.0 프레임워크, 4가지 grant, WRAP | ✅ 원문 |
| 8 | OAuth 2.0 MAC Token Profile | 소유 증명(PoP) 토큰, bearer vs MAC | ✅ 원문 |
| 9 | OAuth 2.0 Profiles | introspection·chain·dynamic reg·revocation | ✅ 원문 |
| 10 | User Managed Access (UMA) | 사용자 주도 중앙 인가(PAT/AAT/RPT) | ✅ 원문 |
| 11 | Federation | SAML/JWT bearer를 통한 신원 연합 | ✅ 원문 |
| 12 | OpenID Connect | OAuth2 위의 인증 계층, ID token, discovery | ✅ 원문 |
| 13 | JWT, JWS, JWE | JSON 메시지 서명·암호화 | ✅ 원문 |
| 14 | Patterns and Practices | 10가지 API 보안 솔루션 패턴 | ✅ 원문 |

---

# 2장 — Security by Design (설계 단계의 보안)

보안은 나중에 덧붙이는 것이 아니라 개발 프로젝트 처음부터 통합되어야 한다.
요구사항 수집 → 설계 → 개발 → 테스트 → 배포 → 모니터링 전 단계에 걸쳐
고려되어야 하며, 이 장은 책 전체의 기초가 되는 보안 원칙을 다룬다.

## 설계 시의 도전 과제 (Design Challenges)

- **사용자 편의성(User Comfort)**: 보안과 사용성 사이의 균형이 가장 어렵다.
  20자 이상 대소문자·숫자·특수문자 강제 정책은 결국 사용자가 비밀번호를
  종이에 적게 만들어 오히려 보안을 해친다. → "심리적 수용성" 원칙.
- **성능(Performance)**: 보안이 추가하는 오버헤드의 비용. 예를 들어 키
  수명을 매우 짧게 하면 탈취 피해는 줄지만, 매 호출마다 새 키 발급이 필요해
  성능이 급락한다. 트레이드오프를 설계해야 한다.
- **가장 약한 고리(Weakest Link)**: 시스템은 가장 약한 링크만큼만 강하다.
  (프랑스 Monoprix 마트에서 강도들이 금고가 아니라 현금 이송용 공압 파이프에
  진공청소기를 연결해 60만 유로를 훔친 사례.)
- **심층 방어(Defense in Depth)**: 계층적 방어. 한 계층이 뚫려도 다음 계층이
  막는다. (공항 보안 다단계 사례.)
- **내부자 공격(Insider Attacks)**: 네트워크 오용의 60~80%가 내부에서
  발생(CSI 통계). WikiLeaks, 스노든 사례 모두 정당한 접근 권한을 가진
  내부자였다.
- **모호성에 의한 보안 지양(Security by Obscurity 지양)**: Kerckhoffs 원칙 —
  키를 제외한 시스템의 모든 것이 공개되어도 안전해야 한다. 표준을 벗어나
  독자 알고리즘/프로토콜을 쓰는 것은 위험하다.

## Saltzer & Schroeder의 8대 설계 원칙

1. **최소 권한(Least Privilege)**: 필요한 최소한의 권한만 부여, 필요 시 추가,
   불필요 시 회수. (군사의 "need to know" 원칙과 연결.)
2. **안전한 기본값(Fail-Safe Defaults)**: 기본은 "거부", 명시적으로만 "허용".
3. **경제성(Economy of Mechanism)**: 설계는 최대한 단순하게.
4. **완전한 중재(Complete Mediation)**: 모든 자원 접근마다 권한을 검증.
5. **개방 설계(Open Design)**: 비밀 알고리즘에 의존하지 않는다.
6. **권한 분리(Separation of Privilege)**: 단일 조건만으로 권한을 부여하지
   않는다(예: 경비를 청구한 관리자가 스스로 승인하지 못하게).
7. **최소 공통 메커니즘(Least Common Mechanism)**: 컴포넌트 간 상태 공유의
   위험을 줄인다.
8. **심리적 수용성(Psychological Acceptability)**: 보안 장치가 없을 때보다
   자원 접근을 더 어렵게 만들면 안 된다.

## CIA 삼요소 (기밀성·무결성·가용성)

- **기밀성(Confidentiality)**: 전송 중·저장 중 데이터를 암호화로 보호.
  - **전송 계층 보안(TLS/HTTPS)** vs **메시지 계층 보안**을 비교:
    전송 계층은 점대점(point-to-point)·전체 암호화·고성능이지만 채널을 벗어나면
    보호가 끊긴다(프록시 내부에서 평문 노출 가능). 메시지 계층은 종단간
    (end-to-end)·부분 암호화 지원·전송 독립적이나 상대적으로 느리다.
  - SSL 브리징 vs SSL 터널링: 높은 보안엔 프록시가 평문을 못 보는 터널링 권장.
  - XML Encryption, JOSE(JWE/JWS) 같은 메시지 계층 표준화 노력.
- **무결성(Integrity)**: 데이터의 정확성/신뢰성 보장 및 무단 변경 탐지.
  예방적(암호화 채널)·탐지적(메시지 다이제스트, MAC) 조치를 전송·저장 양쪽에.
  HTTP Digest의 `qop=auth-int`로 메시지 무결성 보호 가능(3장).
- **가용성(Availability)**: 정당한 사용자가 언제나 접근 가능하도록. DDoS/DoS
  대응이 핵심. SOAP/XML 기반 8가지 DoS 공격 소개:
  강제 파싱(coercive parsing), SOAP 배열 공격, XML 요소/속성 수 공격,
  XML 엔티티 확장(XML 폭탄, billion laughs), 외부 엔티티 DoS, 과대 이름 공격,
  해시 충돌(HashDoS). → 임계값 설정, 부적합 메시지의 조기 차단이 최선의 방어이며,
  이는 **인증/인가 검사를 시스템 진입점 가장 가까이 두어야 한다**는 원칙과 연결.

## 보안 통제 (Security Controls)

- **인증(Authentication)**: "아는 것(비밀번호)", "가진 것(인증서/스마트카드)",
  "자신인 것(생체정보)". 다중요소 인증은 서로 다른 범주 2개 이상 조합
  (비밀번호+PIN은 다중요소가 아님; 구글 2단계 인증은 다중요소).
- **인가(Authorization)**: 인증된 사용자가 무엇을 할 수 있는지.
  - **DAC vs MAC**: 임의 접근 제어(소유자가 권한 위임 가능; Unix/Linux/Windows)
    vs 강제 접근 제어(지정된 자만 부여, 전달 불가; SELinux/Trusted Solaris).
  - 접근 제어 표현: 인가 테이블, 접근 제어 목록(ACL, 자원 중심),
    권한 목록(capability, 주체 중심).
  - **정책 기반 접근 제어**: **XACML**이 사실상 표준. PAP(정책 작성)·
    PDP(정책 평가)·PEP(정책 시행)·PIP(속성 제공)의 분산 참조 아키텍처와
    요청/응답 프로토콜, 정책 언어를 제공. (JSON 프로파일도 존재.)
- **부인 방지(Nonrepudiation)**: 거래를 나중에 부인하지 못하게. 디지털 서명이
  사용자와 거래를 강하게 결합. TLS의 MAC은 공유 비밀키 기반이라 부인 방지를
  제공하지 못함(디지털 서명 필요).
- **감사(Auditing)**: 정당한 접근(부인 방지용)과 불법 접근 시도(위협 식별용)
  모두 추적. 감사 로그는 실시간 분석으로 부정 탐지(CEP)에 활용.

## 보안 패턴 (Security Patterns)

- **직접 인증(Direct Authentication)**: HTTP Basic/Digest처럼 자체 사용자
  저장소를 소유·관리. 공개 API는 DMZ에서 인증 검사, 사용자 저장소는 별도
  보안 구역(yellow zone)에 두는 계층 방어 배치.
- **자격증명 관리(Managing Credentials)**: 전송 중엔 TLS(HTTPS/LDAPS/JDBC
  over TLS), 저장 시엔 **단방향 해시 + 솔트(salted hash)**. 해시만으로는
  부족(해시 교체 공격 가능), 솔트로 레인보우 테이블 방어. (LinkedIn 2012
  유출 — SHA-1 해시였으나 솔트 없어 30만 개 크랙됨.)
- **생체 인증(Biometric Authentication)**: 직접 인증 패턴의 구현. 스캐너↔게이트웨이
  ↔생체시스템 채널 전 구간 TLS 필요.
- **봉인된 그린존(Sealed Green Zone)**: 그린존으로 인바운드 포트를 열지 않고,
  메시지 브로커 큐를 통해 아웃바운드 방향으로만 통신.
- **최소 공통 메커니즘 패턴**: 내부/외부 사용자 저장소를 물리적으로 분리.
- **브로커드 인증(Brokered Authentication)**: 개별 인증서를 일일이 확인하지
  않고, 신뢰하는 CA가 서명했는지만 검증(4장 mTLS와 연결).
- **정책 기반 접근 제어 패턴**: 게이트웨이가 인증 후 사용자=주체, API 컨텍스트=
  자원, HTTP 메서드=액션으로 XACML 요청을 만들어 PDP에 질의.

## 위협 모델링 (Threat Modeling)

자산 식별 → 인터페이스/상호작용 식별 → 위협·공격 목록화 → 공격 계획/도구 선정
→ 실행 → 취약점 식별 → 대응책 수립. **STRIDE** 기법으로 체계적 식별:
Spoofing(인증), Tampering(무결성), Repudiation(부인 방지), Information
disclosure(기밀성), Denial of service(가용성), Escalation of privilege(인가).

> **데모 연결**: `ch2/` 패키지 — PolicyDecisionPoint(XACML 스타일 PDP),
> RateLimitingFilter(가용성/DoS 완화), BCrypt salted 저장(register 엔드포인트),
> fail-safe default 거부.

---

# 3장 — HTTP Basic/Digest Authentication

OAuth 이전 시대에 웹 자원 보호에 가장 널리 쓰인 두 가지 사용자명/비밀번호
기반 인증 방식. 둘 다 RFC 2617에 정의(원조 Basic은 HTTP/1.0, RFC 1945).

## HTTP Basic Authentication

- 사용자는 각 **realm(보호 영역)** 마다 사용자명/비밀번호로 인증. realm 값은
  인증 서버가 지정하는 문자열로, 자원을 보호 도메인 집합으로 분할.
- 요청 형식: `Authorization: Basic Base64Encode(username:password)`.
- **Base64 인코딩은 평문과 다름없다** — 쉽게 디코딩 가능. 따라서 Basic은
  반드시 TLS 같은 외부 보안 시스템과 함께 써야 한다.
- 예제: GitHub REST API가 Basic으로 보호됨(공개 API는 인증 불필요, 저장소
  생성 등은 401 반환 → 자격증명 필요). cURL에서 `-u user:pass`로 헤더 생성.
- (당시 GitHub는 401 시 `WWW-Authenticate` 헤더를 반환하지 않아 HTTP 1.1
  비준수였다는 지적.)

## HTTP Digest Authentication

- RFC 2617이 Basic의 한계를 보완하려 제안. **비밀번호를 평문으로 전송하지
  않는** 챌린지/응답 방식. 비밀번호가 절대 전송선을 타지 않으므로 TLS가 필수는
  아니다.
- **흐름**: 인증 정보 없이 요청 → 서버가 401과 챌린지 반환 → 클라이언트가
  응답(response) 계산해 재요청.
- **챌린지의 4대 요소**: `realm`(표시용 문자열), `nonce`(401마다 유일 생성되는
  서버 지정 데이터), `opaque`(클라이언트가 그대로 되돌려줄 문자열),
  `qop`(보호 품질 — `auth`=인증, `auth-int`=인증+무결성).
- **다이제스트 계산**(MD5 또는 MD5-sess):
  - A1 = `username:password:realm` (MD5-sess는 `MD5(A1):nonce:cnonce`)
  - A2 = `request-method:uri` ( `auth-int`이면 `:H(entity-body)` 추가 )
  - response = `MD5(MD5(A1):nonce:nc:cnonce:qop:MD5(A2))`
  - `cnonce`(클라이언트 nonce)는 선택 평문 공격 방지, `nc`(nonce count,
    16진수 요청 수)는 **재전송 공격 탐지용**. 서버는 자신의 nonce/nc 사본을
    유지해 중복되면 재전송으로 간주.
- **Basic vs Digest 비교**: Basic은 평문 전송·TLS 필수·인증만 / Digest는
  평문 미전송·전송 보안 비의존·무결성 보호 가능(auth-int).
- **저장소 딜레마**: Digest는 서버가 다이제스트를 검증하려면 평문 비밀번호나
  `username:password:realm`의 해시를 저장해야 한다(솔트 해시 불가). 권장은
  `username:password:realm` 해시를 암호화해 저장.

## 실습 요점 (Cute-Cupcake Recipe API)

- Apache Tomcat에 Recipe API(WAR) 배포. GET/POST/PUT/DELETE 5개 오퍼레이션.
- Apache Directory Server(LDAP) 구성, Tomcat을 `JNDIRealm`으로 LDAP 연결.
- `web.xml`의 `<security-constraint>`로 URL·HTTP 메서드별 역할 접근 제어
  (admin은 전체, user는 GET만).
- TLS 활성화(keytool로 JKS 키스토어 생성, `<Connector>` 설정,
  `transport-guarantee=CONFIDENTIAL`).
- Digest는 Tomcat `JNDIRealm`이 미지원이라 `UserDatabaseRealm`(tomcat-users.xml)
  으로 전환해 실습.

> **데모 연결**: `ch3/` — 직접 구현한 RFC 2617 `DigestAuthenticationFilter`
> (Spring Security가 Digest 필터를 더 이상 제공하지 않으므로), Basic은 `ch2`/`ch3/basic`
> 필터체인. realm은 `cute-cupcakes.com`, 사용자 `prabath/prabath123`.

---

# 4장 — Mutual Authentication with TLS (TLS 상호 인증)

**TLS 상호 인증(양방향 SSL, 클라이언트 인증)**: 일반 단방향 TLS는 서버만
신원을 증명하지만, 상호 인증은 클라이언트와 서버 양쪽을 인증한다. "가진 것"
범주의 강력한 인증(2장).

## TLS의 진화

SSL 1.0(미공개) → SSL 2.0(1994, Netscape; 40비트 키 취약점) → Microsoft의
PCT(1995) → SSL 3.0(1996, Paul Kocher; MD5+SHA-1 하이브리드, 가장 안정적) →
IETF TLS 워킹그룹 → **TLS 1.0(RFC 2246, 1999)** → TLS 1.1(RFC 4346, 2006) →
**TLS 1.2(RFC 5246, 2008)**. TLS 1.0과 SSL 3.0은 비호환.

## TLS 동작 원리

두 단계: **핸드셰이크**와 **데이터 전송**.

**핸드셰이크** (하위 3개 프로토콜: Handshake, Change Cipher Spec, Alert):
1. **Client Hello**: 지원 TLS 최고 버전, 클라이언트 난수, cipher suite 목록,
   압축 알고리즘, (선택) 세션 식별자(세션 재개용 → 성능 최대 20% 향상).
2. **Server Hello**: 합의된 버전, 서버 난수, 최강 cipher suite, 압축 알고리즘,
   세션 식별자. (양쪽 난수로 master secret 유도.)
3. 서버가 **인증서 체인**(루트 CA까지) 전송 → 클라이언트가 검증.
4. (상호 인증 시) 서버가 **클라이언트 인증서 요청**(신뢰 CA 목록 포함) →
   Server Hello Done.
5. 클라이언트가 자신의 인증서 체인 전송 → **Client Key Exchange**
   (서버 공개키로 암호화한 premaster secret) → **Certificate Verify**
   (그간의 모든 핸드셰이크 메시지를 클라이언트 개인키로 서명 → 서버가
   공개키로 검증).
6. 양쪽이 client 난수·server 난수·premaster secret으로 **master secret** 생성.
7. **Change Cipher Spec** + **Finished**(전체 핸드셰이크 해시) 교환.

핸드셰이크 공격(cipher suite/version rollback = 다운그레이드 MITM)은 SSL 3.0의
Change Cipher Spec 도입으로 완화(양쪽이 읽은 핸드셰이크 메시지 해시를 상호 확인).

**데이터 전송**: TLS Record 프로토콜이 메시지를 블록으로 나눠 압축→MAC 계산→
암호화. master secret에서 4개 키 유도(양방향 각각 MAC용·암호화용).

## 실습 요점

- Tomcat에서 키스토어(`catalina-keystore.jks`) + 신뢰 저장소
  (`catalina-truststore.jks`, 신뢰 CA/클라이언트 공개 인증서) 구성.
- 클라이언트 키쌍 생성 → 공개 인증서를 서버 truststore에 import.
- `<Connector>`의 `clientAuth=true`로 컨테이너 전역 상호 인증(권장은
  API별 적용). `web.xml`에서 `auth-method=CLIENT-CERT`,
  `transport-guarantee=CONFIDENTIAL`, `role-name` 제약.
- 사용자명은 클라이언트 인증서 **Subject의 CN**(`CN=client`).
- cURL: `curl -k --cert client.pem https://localhost:8443/recipe`.

## 심화 주제

- **JKS vs PKCS#12**: JKS는 Java 전용, PKCS#12(.p12/.pfx)는 언어 중립.
- **인코딩 규칙(ASN.1/X.690)**: BER/DER/CER. keytool export는 DER,
  PEM은 Base64 인코딩된 DER.
- **TLS 역공학**: 서버 개인키가 유출되고 핸드셰이크가 기록됐다면, premaster
  secret → master secret → 4개 키를 복원해 기록된 전체 통신을 복호화할 수 있다.
- **완전 순방향 비밀성(PFS)**: 세션키를 master secret에서 나중에 유도할 수
  없게 만들어 개인키 유출 시에도 과거 통신 기밀성 보호. **ephemeral
  Diffie-Hellman(DHE/ECDHE)** cipher suite 필요.
  (예: `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256`. Qualys SSL Labs로 점검.)

> **데모 연결**: `ch4/` + `config/MtlsSecurityConfig` — 별도 8443 커넥터를 열고
> `certificateVerification="optional"`로 설정(핸드셰이크는 통과시키고 Spring
> Security x509 필터가 401/403 응답), 인증서 CN → 사용자 매핑.

---

# 5장 — Identity Delegation (신원 위임)

**위임**: API의 소유자와 직접 소비자가 다를 수 있다. 제3자가 당신을 대신해
자원에 접근하려 할 때, **자격증명 공유는 안티패턴**이다. 이 장은 OAuth로
이어지는 위임 모델의 역사를 다룬다.

## 위임의 3대 역할과 두 모델

- 역할: **위임자(delegator=자원 소유자)**, **피위임자(delegate)**,
  **서비스 제공자(service provider=자원 서버)**.
- **직접 위임(Direct Delegation)**: 위임자가 자신의 권한 부분집합을 피위임자에게
  직접 위임. (예: Flickr 사진을 Snapfish가 가져와 인화 — Snapfish에 읽기/업로드
  권한 위임하되 삭제 등은 불가.)
- **브로커드/간접 위임(Brokered Delegation)**: 위임자→중간 피위임자→또 다른
  피위임자로 연쇄 위임. (예: Lucidchart에 Google Drive 읽기/쓰기 위임 →
  Lucidchart가 Snapfish에는 읽기 권한만 재위임.)

## 위임의 진화 (pre-2006 vs post-2006)

- **~2006(자격증명 공유 시대)**: Twitter, SlideShare, Google Calendar 등이
  제3자 앱에 이메일/블로그 계정 비밀번호를 그대로 넘기게 했다. "비밀번호를
  저장하지 않는다"고 안내했지만 원리상 앱이 뭐든 할 수 있었다.
- **2006~(비공유 프로토콜 등장)**: 커뮤니티 반발로 Google이 새로운 방식을 발명.
  - **Google ClientLogin**: 설치형 앱(데스크톱/모바일)용. 사용자 자격증명 →
    request token → Google 인증 서비스 → CAPTCHA → Auth 토큰 발급. 여전히
    자격증명 공유 기반. (2012 폐기.)
  - **Google AuthSub**: 웹앱용, **자격증명 비공유**. 사용자를 Google로
    리다이렉트→로그인/승인→임시 토큰→세션 토큰 교환→API 접근. scope로 접근
    범위 제한. (2012 폐기.)
  - **Flickr Authentication API**: **서명 기반**. 앱 시크릿으로 각 요청을 서명
    (파라미터 정렬→시크릿 선붙임→MD5=`api_sig`). frob(단회용 토큰)→세션 토큰.
  - **Yahoo! BBAuth**(2006): 리다이렉트→로그인/승인→임시 토큰(14일 유효)→
    auth 쿠키+WSSID 교환. 타임스탬프+시크릿 MD5 서명.

## OAuth의 탄생

Google AuthSub·Yahoo BBAuth·Flickr가 표준 위임 모델 논의를 촉발.
2006/11 Blaine Cook(Twitter의 OpenID 구현) + Larry Halff(Magnolia) +
Chris Messina 등이 2007/4 논의 그룹 결성 → **OAuth**.
- OAuth 1.0 core(2007/12) → IETF 이관 → 세션 고정 공격 수정한 **1.0a**(2009) →
  **RFC 5849(2010, OAuth 1.0)**.
- 2009/11 WRAP(Web Resource Authorization Profiles, MS/Google/Yahoo 제안) →
  2009/12 OAuth 2.0에 흡수되며 폐기.
- OpenID/OAuth 하이브리드 확장(OpenID 인증 요청에 OAuth 승인 요청 임베드).
- 사용성·확장성 비판을 받은 1.0을 개선해, **프로토콜이 아닌 인가 프레임워크**로
  설계된 **OAuth 2.0 = RFC 6749(2012)** 탄생.

> **데모 연결**: `ch5/` — 유효한 bearer JWT를 제시하면 더 좁은 scope·다른
> audience의 새 JWT를 발급(RFC 8693 Token Exchange 취지의 브로커드 위임),
> `act`(actor) 클레임 기록.

---

# 6장 — OAuth 1.0

OAuth 1.0은 신원 위임 표준화를 향한 첫걸음이다. 위임 트랜잭션에 세 당사자가
관여한다: **위임자(user → RFC 5849에서는 resource owner)**, **피위임자
(consumer → client)**, **서비스 제공자(service provider → server)**.

## 토큰 댄스 (The Token Dance)

토큰 기반 인증의 뿌리는 1994년 쿠키(Mosaic Netscape 0.9)로 거슬러 올라간다.
OAuth 1.0 핸드셰이크는 3단계로 구성되며 **모든 단계는 TLS 위에서** 이뤄져야
한다:

1. **임시 자격증명 요청(Temporary-Credential Request)**: 클라이언트가
   `oauth_consumer_key`, `oauth_signature_method`, `oauth_signature`,
   `oauth_callback`을 담아 요청 → 서버가 `oauth_token` +
   `oauth_token_secret` + `oauth_callback_confirmed=true` 반환.
2. **자원 소유자 인가(Resource-Owner Authorization)**: 클라이언트가 사용자를
   서버로 리다이렉트(`oauth_token` 쿼리) → 사용자 인증·승인 → 콜백으로
   `oauth_token` + `oauth_verifier` 반환.
3. **토큰 자격증명 요청(Token-Credential Request)**: `oauth_token` +
   `oauth_verifier` + 서명으로 access token 엔드포인트 호출 → 최종
   `oauth_token` + `oauth_token_secret` 획득.

이후 비즈니스 API 호출마다 `oauth_timestamp`와 `oauth_nonce`(재전송 방지 —
서버는 이전에 본 nonce를 거부)를 추가하고 서명한다.

## oauth_signature 3가지 방식

- **PLAINTEXT**: 서명 없음. `consumer_secret&`(토큰 단계에서는
  `consumer_secret&token_secret`). TLS 필수.
- **HMAC-SHA1**: 공유 키 서명. 8단계로 **base string**(HTTP 메서드 + URL +
  정렬·URL 인코딩된 파라미터)을 만들어 `HMAC-SHA1(consumer_secret&token_secret,
  base-string)`.
- **RSA-SHA1**: 클라이언트가 등록한 RSA 개인키로 base string 서명.

base string 생성이 각 방식의 핵심 난제 — 대문자 메서드, 소문자 scheme/host,
경로·쿼리, `oauth_signature` 제외한 모든 파라미터를 `&`로 연결 후 URL 인코딩.

## 3-legged vs 2-legged OAuth

- **3-legged**: 자원 소유자·클라이언트·서버 세 당사자. 클라이언트가 사용자를
  대신해 접근(일반적 패턴).
- **2-legged**: 클라이언트가 곧 자원 소유자. 접근 위임이 없고 토큰 댄스도 없이
  `oauth_consumer_key` + `consumer_secret&`로 서명. HTTP Digest와 유사하나,
  Digest는 사용자를 인증하고 2-legged OAuth는 애플리케이션을 인증한다.

## OAuth WRAP

2009/11 제안된 접근 위임 드래프트(OAuth 1.0 위에 구축). **서명 스킴에 의존하지
않고** 모든 통신에 TLS를 강제. 검증 코드를 access token으로 교환. 이후 OAuth
2.0에 흡수되며 폐기. WRAP이 도입한 확장성 개념이 OAuth 2.0의 기반이 되었다.

> **데모 연결**: `ch6/`(신규) — HMAC-SHA1/PLAINTEXT `oauth_signature`를 실제로
> 계산·검증하는 서명 검증기와 `oauth_nonce` 재전송 방지 저장소를 제공.
> Twitter가 여전히 OAuth 1.0을 쓰는 이유(레거시 호환)를 실습으로 보여준다.

---

# 7장 — OAuth 2.0

OAuth 2.0은 신원 위임의 큰 도약이다. OAuth 1.0에 뿌리를 두되 OAuth WRAP의
영향을 크게 받았다. **핵심 차이: 1.0은 위임을 위한 구체적 프로토콜, 2.0은 고도로
확장 가능한 프레임워크.** 오늘날 API 보안의 사실상 표준(Facebook·Google·
LinkedIn·PayPal·GitHub 등). Twitter는 예외적으로 여전히 1.0 사용.

## OAuth WRAP → OAuth 2.0

WRAP은 서명을 없애고 TLS를 강제했으며 두 종류의 프로파일을 도입:
- **자율 클라이언트 프로파일**: Client Account & Password Profile,
  Assertion Profile (클라이언트=자원 소유자, 2-legged와 등가).
- **사용자 위임 프로파일**: Username & Password Profile, Web App Profile,
  Rich App Profile. **refresh token(토큰 갱신)** 기능을 처음 도입.

OAuth 2.0은 여기에 **grant type**과 **token type**이라는 두 확장점을 도입.

## 4가지 core grant type

| grant type | 대응 WRAP 프로파일 | 용도 |
|---|---|---|
| **Authorization Code** | Web App / Rich App | 브라우저 구동 가능한 웹·모바일 앱. code→token 2단계, refresh token 있음 |
| **Implicit** | (없음) | 브라우저 내 JavaScript 클라이언트. 토큰을 URI fragment로 직접 반환, refresh 없음 |
| **Resource Owner Password Credentials** | Username & Password | 신뢰된 앱, Basic/Digest→OAuth 마이그레이션용 |
| **Client Credentials** | Client Account & Password | 사용자 없는 서버간 통신, 클라이언트=자원 소유자, refresh 없음 |

- Authorization Code: `response_type=code`, code 수명은 10분 이하 권장, code는
  1회만 사용(재사용 감지 시 발급된 모든 토큰 폐기), 토큰 엔드포인트는 HTTP
  Basic으로 클라이언트 인증.

## 토큰 타입과 클라이언트 타입

- **Bearer Token Profile(RFC 6750)**: 가장 널리 쓰임. 토큰을 가진 자면 누구나
  사용 → 반드시 TLS. Authorization 헤더/쿼리 파라미터(`access_token`)/폼 바디로
  전달. 토큰 값은 인가 서버에게만 의미 있음(클라이언트·자원 서버는 해석 금지).
- **MAC Token Profile**: 8장 참조.
- **클라이언트 타입**: **Confidential**(자격증명 보호 가능, 웹앱) vs
  **Public**(보호 불가 — user-agent JS 앱, 네이티브 앱). 모든 grant는 사전 등록
  필요(단 Implicit은 client secret 없음).

> **데모 연결**: `ch7/` + `config/AuthorizationServerConfig` — 실제 Spring
> Authorization Server로 Authorization Code+PKCE / Client Credentials grant를
> 구현. 클라이언트 `demo-authcode-client`(PKCE), `demo-service-client`.

---

# 8장 — OAuth 2.0 MAC Token Profile

OAuth 2.0 core는 토큰 타입을 강제하지 않는다(확장점). 거의 모든 공개 구현은
Bearer Token Profile을 쓰지만, 이 장은 Eran Hammer가 도입한 **MAC Token
Profile**을 다룬다.

## "OAuth 2.0 and the Road to Hell"

2012/7 명세 리드 에디터 Eran Hammer가 사임하며 쓴 유명한 글. 그는 OAuth 2.0이
1.0보다 복잡성·상호운용성·완전성·보안 면에서 나쁜 프로토콜이라 비판했다. 그가
지적한 1.0→2.0 아키텍처 변화:
- **Unbounded Tokens**: 2.0은 요청마다 클라이언트 자격증명을 쓰지 않아 토큰이
  특정 클라이언트에 묶이지 않음 → 인증 수단으로서의 유용성 저하.
- **Bearer Tokens**: 프로토콜 수준의 서명·암호화를 없애고 TLS에만 의존 → 명세
  자체로는 덜 안전.
- **Expiring Tokens**: 자체 인코딩(self-encoded) 토큰은 폐기가 안 되므로
  단명해야 하고, 클라이언트가 토큰 상태 관리를 해야 함.

이런 비판에도 확장성 덕분에 2.0이 사실상 표준이 되었다.

## Bearer 토큰 vs MAC 토큰

- **Bearer = 현금**: 소유자면 누구나 사용. 검증되는 건 유효성이지 소유자가
  아님. 토큰 비밀을 매번 전송선에 실어야 함.
- **MAC = 신용카드**: 사용할 때마다 서명으로 인증. 훔쳐도 서명을 흉내 못 내면
  못 씀. **토큰 비밀을 전송선에 절대 싣지 않음.** (Basic vs Digest 관계와 유사.)

## MAC 토큰 획득과 사용

- 어떤 grant type으로든 MAC 토큰을 얻을 수 있으나 토큰 요청에 **`audience`
  파라미터가 필수**(발급된 토큰이 특정 자원 서버 대상임을 명시). 응답은
  `token_type:"mac"`, `kid`(키 식별자 = base64(sha-1(access_token))),
  `mac_key`(세션 키), `mac_algorithm`(hmac-sha-256 등)을 포함.
- `mac_key`는 자원 서버의 공개키/공유키로 암호화되어 access_token 안에 인코딩됨.
- API 호출 시 클라이언트는 **authenticator**를 만들어 Authorization 헤더에 실음:
  `kid`, `ts`(타임스탬프), `seq-nr`(시퀀스 번호), `access_token`, `mac`, `h`
  (서명 대상 헤더), `cb`(TLS 채널 바인딩, RFC 5929).
- **MAC 계산**: input-string = Request-Line + ts + seq-nr + 지정 헤더들을
  `\n`으로 연결 → `HMAC-SHA256(mac_key, input-string)`.
- **자원 서버 검증**: access_token에서 mac_key 추출 → audience 검증 → MAC 재계산
  후 비교 → 타임스탬프로 재전송 공격 탐지. 첫 요청에만 access_token 포함, 이후엔
  kid로 캐시된 mac_key 사용.

> **데모 연결**: `ch8/` — 폐기된 MAC Token Profile 대신 현대 표준 **DPoP
> (RFC 9449)** 로 같은 "sender-constrained token" 개념을 구현. DPoP proof JWT
> (서명·`htm`/`htu`·`jti` 재전송 방지·`ath` 액세스 토큰 해시 바인딩), 토큰의
> `cnf.jkt`(JWK 지문)와 대조.

---

# 9장 — OAuth 2.0 Profiles

OAuth 2.0 프레임워크 위에 엔터프라이즈급 배포를 위한 생태계를 구축하는 4대
프로파일을 다룬다.

## 1. Token Introspection Profile

OAuth 2.0은 자원 서버↔인가 서버 통신 API를 표준화하지 않아 벤더별 독자 API가
난립했다. Introspection은 인가 서버가 노출하는 **표준 토큰 메타데이터 조회 API**
(`POST /introspection`, HTTP Basic 보호). 응답: `active`(활성 여부),
`client_id`, `scope`, `sub`, `aud`. 자원 서버는 `active=true` → `aud` 일치 →
`scope` 포함 여부 순으로 검증.

**XACML 연계**: introspection 응답으로 XACML 요청을 만들어 PDP에 질의해 세밀한
접근 제어 가능(client_id·scope·sub·resource·action을 XACML 속성으로 매핑).

## 2. Chain Grant Type Profile

audience 제약이 걸린 토큰은 의도한 audience에만 쓸 수 있다. 첫 번째 API가 두
번째 API를 호출해야 할 때, 받은 토큰을 그대로 넘기면 audience 검증에 실패한다.
Chain Grant Type(`grant_type=http://oauth.net/grant_type/chain`)은 첫 API가
원래 토큰을 **더 좁은(또는 동일) scope의 새 access token으로 교환**하게 한다
(refresh token 없음, 새 토큰 필요 시 원래 토큰 재제시).

## 3. Dynamic Client Registration Profile

모든 클라이언트는 사전 등록이 필요하지만, 이 프로파일은 **실시간 등록 엔드포인트**
(`POST /register`)를 표준화한다. `redirect_uris`, `token_endpoint_auth_method`,
`grant_types`, `response_types`를 전달 → `client_id`/`client_secret` 발급.
**모바일 앱에 특히 유용**: 설치마다 다른 client secret을 발급해, 한 secret이
유출돼도 전체 설치가 영향받지 않게 한다.

## 4. Token Revocation Profile (RFC 7009)

클라이언트가 자신이 획득한 access/refresh token을 폐기하는 표준 엔드포인트
(`POST /revoke`, HTTP Basic 보호). `token` + `token_type_hint` 전달. refresh
token 폐기 시 연관된 모든 access token 무효화. (Buffer가 2013년 공격 당시 모든
키를 폐기해 피해를 막은 사례.)

> **데모 연결**: `ch9/` — Spring Authorization Server가 자동 제공하는
> `/oauth2/introspect`·`/oauth2/revoke`, 그리고 커스텀
> `urn:ietf:params:oauth:grant-type:jwt-bearer` grant(RFC 7523)를 1급 grant로
> 구현한 `JwtBearerAuthenticationProvider`. 신규 `ch9b/`는 Chain Grant Type과
> Dynamic Client Registration을 테스트 가능한 형태로 추가 구현.

---

# 10장 — User Managed Access (UMA)

UMA는 OAuth 2.0 프로파일이다. OAuth 2.0이 자원 서버와 인가 서버를 분리했다면,
UMA는 한 발 더 나아가 **분산된 여러 자원 서버를 중앙 인가 서버로 제어**하고,
자원 소유자가 정책을 미리 정의해 **소유자 부재 시에도** 정책 평가로 접근을
허용하게 한다.

## ProtectServe (UMA의 뿌리)

Kantara Initiative에서 출발. 4당사자(user, authorization manager, service
provider, consumer)를 정의하고 OAuth 1.0으로 API를 보호했다. UMA는
OAuth 1.0 → WRAP → OAuth 2.0으로 진화.

## UMA 아키텍처 (5개 컴포넌트)

resource owner, resource server, authorization server, client,
**requesting party**(클라이언트를 쓰는 실제 사람 — 클라이언트와 다를 수 있음).

## 3단계

- **Phase 1 — 자원 보호**: 자원 소유자가 분산된 자원 서버들을 중앙 인가 서버에
  소개(설정 endpoint JSON 제공) → 자원 서버가 dynamic client registration으로
  등록 → **PAT(Protection API Token)** 획득(자원 서버·자원 소유자별) →
  Resource Set Registration API로 보호할 자원 등록. PAT scope는
  `http://docs.kantarainitiative.org/uma/scopes/prot.json`.
- **Phase 2 — 인가 획득**: 클라이언트가 자원 접근 시도 → 401 + `as_uri` →
  클라이언트가 **AAT(Authorization API Token)** 획득(클라이언트·requesting
  party별) → RPT 엔드포인트에서 **초기 RPT**(권한 없는 임시 토큰) 획득 →
  자원 재요청 시 자원 서버가 introspection으로 검증 → 권한 부족이면 자원 서버가
  Permission Registration API로 필요 권한 등록 → `ticket` 반환(403) →
  클라이언트가 ticket + AAT로 **권한 있는 RPT** 요청 → 인가 서버가 자원 소유자
  정책 평가(필요 시 requesting party와 직접 상호작용) → 최종 RPT 발급.
- **Phase 3 — 자원 접근**: 유효 RPT로 접근 → 자원 서버가 introspection으로 확인.

## UMA API

- **Protection API**(자원 서버↔인가 서버, PAT로 보호): Resource Set
  Registration + Client Requested Permission Registration + Token Introspection.
- **Authorization API**(클라이언트↔인가 서버, AAT로 보호): RPT 발급.

> **데모 연결**: `ch10/` — permission ticket 발급(`UmaTicketStore`) → RPT 교환
> (`urn:ietf:params:oauth:grant-type:uma-ticket`) → RPT의 `resource_id`
> 대조. (데모의 단순화 한계는 `VULNERABILITY-SCENARIOS.md` 시나리오 7 참고.)

---

# 11장 — Federation (신원 연합)

**연합(Federation)**: 서로 다른 신원 관리 시스템 또는 서로 다른 기업 간에
사용자 신원을 전파하는 것. 인수·합병·파트너십 증가로, 국경을 넘는 여러 이질적
보안 시스템을 다룰 능력이 필요해졌다.

## 연합이 필요한 이유

파트너사 사용자를 어떻게 인증할까? 그 사용자는 외부가 관리한다. HTTP Basic은
불가(외부 사용자 자격증명이 없고, LDAP/JDBC를 방화벽 밖에 노출할 수 없음).
OAuth 2.0의 Authorization Code/Implicit grant도 **인가 서버에서 사용자를 어떻게
인증할지는 규정하지 않는다** — 로컬 사용자면 직접 인증, 외부면 **브로커드
인증**을 써야 한다.

## 브로커드 인증 (Brokered Authentication)

인가 서버가 외부의 개별 사용자를 일일이 신뢰하지 않고, 해당 도메인의 **트러스트
브로커**를 신뢰한다. 각 외부 파티는 자기 사용자를 (직접) 인증하고 그 결과를
신뢰 가능한 방식으로 인가 서버에 전달하는 브로커를 둔다. 브로커와 인가 서버
간 신뢰는 **out-of-band**(사전 합의, 보통 X.509 인증서)로 확립.

- 예: Foo Inc. 직원이 Bar Inc. 웹앱에 로그인 → 웹앱이 Foo의 API를 대신 호출.
  (자원 소유자·자원 서버·인가 서버 = Foo, 클라이언트 = Bar.)
- 흐름: 사용자→Bar 웹앱 방문→Foo 인가 서버로 리다이렉트(client_id 전달, 이때
  개별 클라이언트를 인증하지 않고 도메인만 신뢰) → authorization code 발급 →
  Bar 웹앱이 **자기 도메인의 트러스트 브로커에 인증해 서명된 assertion 획득** →
  그 assertion을 증거로 Foo 인가 서버에 제시 → 서명 검증 후 access token 발급.
- **assertion**: "이 개체가 트러스트 브로커에서 인증된 개체"라는 서명된 주장.
  서명이 없으면 중간자가 변조 가능; 브로커의 개인키 서명으로 변조 탐지.

## SAML (Security Assertion Markup Language)

- OASIS 표준. 인증·인가·신원 데이터를 XML로 교환. SAML 1.0(2001)→1.1(2002)→
  **2.0(2005**, SAML 1.1 + Liberty Alliance IFF + Shibboleth 1.3 통합).
- **4대 요소**: Assertions(인증/인가/속성), Protocol(요청/응답 패키징),
  Bindings(전송 방식 — HTTP/SOAP), Profiles(특정 유스케이스용 조합 — 예:
  Web SSO 프로파일).

## SAML 2.0 Profile for OAuth — 두 가지 유스케이스

1. **클라이언트 인증(Client Authentication)**: 토큰 요청 시
   `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:saml2-bearer`
   와 base64url 인코딩된 SAML assertion(`client_assertion`)을 함께 전송.
   assertion 규칙: 고유 Issuer, Subject의 NameID(=client ID),
   SubjectConfirmation method = `...cm:bearer`, 인증했다면 단일 AuthnStatement.
2. **Grant Type(사용자 assertion)**: 사용자가 SAML 2.0 Web SSO로 웹앱에 로그인
   (IdP가 SAML 응답/assertion 발급) → 웹앱이 그 assertion을
   `grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer`,
   `assertion=<base64url>` 로 인가 서버에 제시해 access token 교환.
   - refresh token은 발급되지 않음. access token 수명은 assertion 수명을 크게
     넘지 않아야 함. scope는 out-of-band로 자원 소유자가 사전 합의(요청 scope는
     그 부분집합이어야 함).
   - 자원 서버와 인가 서버가 다른 도메인이면 introspection(9장)으로 토큰 검증.

## 실습 요점 (WSO2 Identity Server)

두 인스턴스 — 하나는 SAML 2.0 IdP(Foo, 포트 9443), 하나는 OAuth 인가 서버
(Bar, 포트 9445). SP 등록·Assertion Consumer URL·Audience Restriction·서명
설정 → IdP 공개 인증서를 인가 서버에 업로드해 신뢰 확립 → SAML Response Builder로
assertion 생성 → base64url 인코딩 → `saml2-bearer` grant로 cURL 토큰 요청.

## JWT Profile for OAuth 2.0 (RFC 7523)

SAML 프로파일이 XML 세계에서 하는 일을 **JWT가 JSON 세계에서** 동일하게 수행.
- 클라이언트 인증: `client_assertion_type=...:jwt-bearer` + 서명된 JWT.
- Grant type: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` + `assertion`.
동일 유스케이스를, XML 대신 JSON으로.

> **데모 연결**: `ch11/` — SAML/XML 툴링 대신 **JWT Bearer(RFC 7523)** 로 동일
> 신뢰 모델 구현. 독립적인 외부 IdP("Foo Inc.")가 자체 RSA 키로 assertion을
> 서명하고, 우리 인가 서버가 그 assertion을 신뢰해 자체 토큰을 발급
> (`ExternalIdpConfig`, `JwtBearerAuthenticationProvider`). 9장의 JWT Bearer
> grant 기계를 그대로 재사용.

---

# 12장 — OpenID Connect

OpenID Connect(OIDC)는 2014/2 표준화. **OAuth 2.0 위에 얹은 경량 인증(identity)
계층**이다. OpenID(2005, SAML의 뒤를 이어 웹 인증 혁신)에 뿌리를 두되 OAuth 2.0의
영향을 크게 받았다.

## OpenID의 역사 (배경)

OpenID는 흩어진 프로필 문제를 해결 — 프로필을 OpenID provider 한 곳에 두고 다른
사이트(relying party)가 조회. 사용자가 OpenID(URL)를 입력 → relying party가
discovery로 provider를 찾음 → (smart RP는 association으로 공유키 수립) →
사용자를 provider로 리다이렉트 → 인증·승인 → 서명된 응답 반환. OpenID는 **인증**,
OAuth 1.0은 **위임 인가**로 관심사가 다르며, 둘을 결합하려는 Google Step 2 →
OpenID Connect(3세대)로 발전.

## ID Token (OIDC의 핵심)

OAuth 2.0에 더해지는 주된 요소. **인증된 사용자 정보를 인가 서버→클라이언트로
전달하는 JWT.** 주요 클레임:
- `iss`(발급자 URL), `sub`(사용자 로컬 식별자), `aud`(대상 — client ID 포함
  필수), `exp`/`iat`, `auth_time`(사용자 인증 시각).
- `nonce`: **재전송 공격 완화** — 인가 요청의 nonce를 ID token에 그대로 담아
  클라이언트가 검증.
- `acr`(인증 컨텍스트 참조 = 인증 강도), `amr`(인증 방법), `azp`(인가된 당사자).
- ID token은 **JWS로 서명 필수**, 선택적 JWE 암호화(암호화 시 서명 먼저 → 암호화).

## OIDC 요청 파라미터 & grant

- 인증 요청은 **`scope`에 `openid` 필수.** 추가 파라미터: `response_mode`,
  `display`(page/popup/touch/wap), `prompt`(none/login/consent/select_account),
  `max_age`, `login_hint`, `id_token_hint`, `acr_values`.
- **grant/flow별 반환**: Authorization Code(`code`) → 토큰 엔드포인트에서 ID
  token+access token / Implicit(`id_token` 또는 `id_token token`) / Hybrid
  (`code id_token`, `code token`, `code token id_token` 조합).

## 사용자 속성 요청

- **scope 방식**: `profile`, `email`, `address`, `phone`. (`profile`이면 name,
  given_name 등 다수 속성 포함.)
- **claims 파라미터**: JSON으로 특정/커스텀 클레임 요청(커스텀 클레임은 이 방식만).
- **UserInfo 엔드포인트**: OAuth 보호 자원. access token으로 GET/POST해 속성 획득.

## Discovery (WebFinger + 메타데이터)

- **WebFinger**(RFC 7033): 사용자 식별자(예: 이메일 `acct:peter@apress.com`)로
  `/.well-known/webfinger?resource=...&rel=http://openid.net/specs/connect/1.0/issuer`
  질의 → 해당 사용자의 OpenID provider(issuer) 발견.
- **Provider 메타데이터**: `/.well-known/openid-configuration`에서
  authorization/token/userinfo/jwks/registration 엔드포인트, 지원 scope·알고리즘
  등을 JSON으로 획득.
- **Dynamic Client Registration**: `registration_endpoint`에 POST해 client_id/
  secret 획득(DoS 방지 위해 rate limit 권장).

## API 보안에서의 OIDC

API는 결국 OAuth 2.0 access token으로 보호된다. ID token은 **신원의 증명(assertion)**
으로, API 인증에 쓸 수 있다(서명된 JWT를 Authorization 헤더에 담아 전달 →
API가 서명·클레임 검증). API를 대상으로 할 때는 API가 아는 URI를 `aud`에 추가해야
한다(현재는 out-of-band 설정 필요).

> **데모 연결**: `ch12/`(신규) — Spring Authorization Server의 OIDC 지원
> (`openid` scope)로 ID token을 발급하고, ID token의 JWS 서명·`iss`/`aud`/`nonce`
> 클레임을 검증하는 엔드포인트, 그리고 `/userinfo` 유사 엔드포인트를 제공.

---

# 13장 — JWT, JWS, and JWE

JSON은 API의 사실상 표준 교환 포맷이 되었고, JSON 메시지를 **메시지 수준**에서
보호할 표준이 필요해졌다(TLS는 전송 계층만 보호). IETF **JOSE** 워킹그룹이
JWS·JWE·JWK·JWA를 개발.

## JSON Web Token (JWT)

당사자 간 데이터를 JSON으로 전송하는 컨테이너. base64url 인코딩된 **세 부분**을
`.`으로 구분:
1. **JOSE 헤더**: 적용된 암호 연산 기술(예: `{"alg":"RS256","kid":"..."}`).
2. **payload/claim set**: 실제 데이터. **claim 3분류** — registered(iss, sub,
   aud, exp, nbf, iat, jti), public(IANA 등록 또는 충돌 방지 네임스페이스),
   private(당사자 간 사전 공유). JWT 명세는 registered claim 사용을 강제하지 않음.
3. **signature**: base64url 인코딩된 서명.
- **Plaintext JWT**는 서명이 없어 2부분뿐, `alg`가 `none`.

## JSON Web Signature (JWS)

JSON 메시지를 **디지털 서명 또는 MAC**하는 방법. JWS 헤더 속성: `alg`, `jku`
(JWK Set URL), `jwk`(공개키), `kid`, `x5u`/`x5c`/`x5t`(X.509), `typ`, `cty`, `crit`.
- **서명 알고리즘(JWA)**: HS256/384/512(HMAC), RS256/384/512(RSASSA-PKCS1-v1_5),
  ES256/384/512(ECDSA), PS256/384/512(RSASSA-PSS), None.
- **직렬화**: **Compact**(URL-safe, `.`으로 3부분 — OpenID Connect가 강제, 단일
  서명) vs **JSON**(다중 서명 가능, `payload`/`signatures`/`protected`/`header`
  구조). JWT는 반드시 compact 직렬화.

## JSON Web Encryption (JWE)

JSON 메시지를 **암호화**. 추가 헤더: `enc`(콘텐츠 암호화 알고리즘), `zip`(압축).
- **콘텐츠 암호화 vs 키 래핑**: `enc`는 콘텐츠 암호화(주로 대칭키, 예: A256GCM),
  `alg`는 콘텐츠 암호화 키를 감싸는 키 래핑(주로 비대칭, 예: RSA-OAEP). 발신자가
  랜덤 키로 콘텐츠를 AES-GCM 암호화하고, 그 키를 RSA-OAEP로 암호화해 JWE에 넣음.
- **AEAD**(Authenticated Encryption with Associated Data): 기밀성+무결성+인증성
  동시 제공(RFC 5116).
- **직렬화**: Compact JWE는 `.`으로 구분된 **5부분** — (1)헤더 (2)암호화된 키
  (3)초기화 벡터(IV) (4)암호문 (5)인증 태그.
- **서명+암호화 병용 시 서명 먼저, 그다음 암호화**(법적 수용성 때문).

> **데모 연결**: `ch13/`(신규) — HS256/RS256으로 JWT를 서명·검증하고, RSA-OAEP +
> A128GCM으로 JWT를 암호화·복호화하는 엔드포인트를 Nimbus JOSE+JWT로 제공.
> (책의 Java 예제와 동일한 API를 REST로 노출.)

---

# 14장 — Patterns and Practices (패턴과 실무)

2장에서 다룬 보안 패턴을 확장해, **10가지 실무 API 보안 솔루션 패턴**을 제시한다.
각 패턴은 앞 장들의 개념 위에 구축된다.

1. **Direct Authentication with the Trusted Subsystem**: 웹앱이 사용자 인증 후
   신뢰된 하위 시스템으로서 백엔드 API 호출. **mTLS**로 API 보호(또는 네트워크
   수준 격리).
2. **SSO with Delegated Access Control**: SAML 2.0 IdP로 로그인 → SAML 토큰을
   **SAML grant type**으로 access token 교환 → 백엔드 API 접근. (SAML 토큰 만료 시
   IdP 재방문으로 재발급.)
3. **SSO with Integrated Windows Authentication**: 위와 동일하되 SAML IdP를 IWA로
   보호해 Windows 도메인 사용자 자동 인증.
4. **Identity Proxy with Delegated Access Control**: 파트너사 직원도 접근. 내부
   IdP가 외부 IdP와 신뢰 브로커링(프로토콜 변환 포함) → 내부 앱은 자기 IdP만 신뢰.
5. **Delegated Access Control with JWT**: OpenID Connect IdP로 로그인 → **ID
   token(JWT)을 JWT Bearer grant로** access token 교환(OIDC 서버와 인가 서버가
   다를 때).
6. **Nonrepudiation with JWS**: 금융 API 등 부인 방지 필수 시. 기관이 사용자별
   키쌍 발급(공개 인증서만 보관) → 모든 API 호출을 사용자 개인키로 **JWS 서명** +
   기관 공개키로 **JWE 암호화**(서명 먼저, 암호화 나중).
7. **Chained Access Delegation**: API가 다른 도메인 API를 사용자 대신 호출
   (Water API → MyHealth API). **Chain Grant Type**으로 JWT access token 교환.
   계정 매핑은 OpenID Connect 인증으로 보호(임의 매핑 취약점 방지).
8. **Trusted Master Access Delegation**: 부서별 인가 서버 + 중앙(master) 인가
   서버. master가 발급한 **self-explanatory JWT**(iss 포함)로 어느 부서 API든
   접근. 부서 인가 서버가 발급자 확인 → master introspection → XACML PDP 평가.
9. **Resource STS with Delegated Access Control**: 클라이언트·API 변경 없이 보안
   추가. 양쪽에 인터셉터(PEP) 삽입 → WS-Trust로 STS 간 SAML 토큰 교환 → SAML grant
   type으로 access token 교환.
10. **Delegated Access Control with Hidden Credentials**: 자격증명이 전송선을
    타면 안 될 때. **HTTP Digest** 또는 **OAuth 2.0 MAC 토큰**(API별 발급·개별
    폐기 가능해 더 우수) 사용.

> **데모 연결**: 이 장의 패턴들은 데모 프로젝트의 여러 챕터 구현
> (mTLS=ch4, SAML/JWT bearer=ch11, Chain=ch9b, MAC/DPoP=ch8, OIDC=ch12,
> JWS/JWE=ch13)을 조합해 구성할 수 있다. `PATTERNS.md`(신규)에 각 패턴을 데모
> 엔드포인트로 재현하는 방법을 정리했다.

---

## 참고

이 요약은 제공된 2~14장 PDF를 원문 그대로 읽고 작성했습니다(원서 목차의 1장
서론은 제공되지 않음). 각 장 말미의 "데모 연결"은 `advancedapisecuritydemo`
프로젝트의 구현과 이어지며, 신규로 추가된 테스트 시나리오(6·9b·12·13장 등)는
프로젝트 README와 `VULNERABILITY-SCENARIOS.md`에서 실행 방법을 확인할 수 있습니다.
