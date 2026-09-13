# 『Advanced API Security』 장별 상세 요약 (한글)

> 원서: **Prabath Siriwardena, _Advanced API Security: Securing APIs with
> OAuth 2.0, OpenID Connect, JWS, and JWE_** (Apress, 1st ed.)
>
> 이 문서는 `advancedapisecuritydemo` 데모 프로젝트가 기반으로 삼은 위 책의
> 장별 내용을 한글로 상세 요약한 것입니다. 제공된 PDF(2·3·4·5·7·8·9·10·11장)
> 중 **7·8·9·10장 PDF에는 본문이 담겨 있지 않았습니다**(O'Reilly Learning
> 뷰어에서 저장될 때 본문이 렌더링되지 않아 머리글/바닥글만 있는 1페이지
> 파일로 저장됨). 따라서:
>
> - **2 · 3 · 4 · 5 · 11장**은 책 원문을 직접 읽고 요약한 것입니다.
> - **7 · 8 · 9 · 10장**은 원문이 없어, 이 책이 해당 장에서 표준적으로 다루는
>   주제를 일반 지식과 관련 RFC 기반으로 보충 정리한 것입니다(원문 요약이
>   아니며, 아래에 별도 표시). 정확한 원문 요약이 필요하면 해당 장의 온전한
>   PDF를 다시 제공해 주세요.

## 전체 구성 한눈에 보기

| 장 | 제목 | 핵심 주제 | 원문 |
|---|---|---|---|
| 2 | Security by Design | 보안 설계 원칙, CIA 삼요소, 위협 모델링 | ✅ 원문 |
| 3 | HTTP Basic/Digest Authentication | 사용자명/비밀번호 기반 인증의 기초 | ✅ 원문 |
| 4 | Mutual Authentication with TLS | TLS 상호 인증(mTLS), TLS 동작 원리 | ✅ 원문 |
| 5 | Identity Delegation | 위임 접근의 역사(OAuth 이전) | ✅ 원문 |
| 7 | OAuth 2.0 | OAuth 2.0 프레임워크, 4가지 grant | ⚠️ 보충 |
| 8 | OAuth 2.0 MAC Token Profile | 소유 증명(PoP) 토큰 | ⚠️ 보충 |
| 9 | OAuth 2.0 Profiles | introspection·revocation·확장 grant | ⚠️ 보충 |
| 10 | User Managed Access (UMA) | 사용자 주도 접근 제어 | ⚠️ 보충 |
| 11 | Federation | SAML/JWT bearer를 통한 신원 연합 | ✅ 원문 |

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

# 7장 — OAuth 2.0  ⚠️ (제공 PDF에 본문 없음 · 아래는 표준 지식 기반 보충)

> 이 장의 PDF에는 본문이 담겨 있지 않아, 이 책이 7장에서 다루는 주제를 일반
> 지식과 RFC 6749 기반으로 개괄한 것입니다. 원문 요약이 아닙니다.

- **OAuth 2.0(RFC 6749)**: 위임 접근을 위한 **인가 프레임워크**. 4대 역할 —
  자원 소유자(Resource Owner), 클라이언트(Client), 인가 서버(Authorization
  Server), 자원 서버(Resource Server).
- **4가지 표준 grant type**:
  - **Authorization Code**: 서버측 웹앱용. 사용자 승인 후 code 발급 → 토큰
    교환. 공개 클라이언트(SPA/모바일)에는 **PKCE**(RFC 7636) 권장.
  - **Implicit**: 브라우저에서 토큰 직접 반환(현재는 비권장, PKCE로 대체).
  - **Resource Owner Password Credentials**: 신뢰된 1st-party 앱 한정(비권장).
  - **Client Credentials**: 사용자 없이 클라이언트 자신의 자격으로(서버간 통신).
- **토큰**: access token(단명), refresh token(재발급용). `scope`로 접근 범위 제한.
- `redirect_uri` 정확 일치 검증, `state`(CSRF 방지) 등 보안 고려사항.

> **데모 연결**: `ch7/` + `config/AuthorizationServerConfig` — 실제 Spring
> Authorization Server로 Authorization Code+PKCE / Client Credentials grant를
> 구현. 클라이언트 `demo-authcode-client`(PKCE), `demo-service-client`.

---

# 8장 — OAuth 2.0 MAC Token Profile  ⚠️ (제공 PDF에 본문 없음 · 보충)

> 원문 미포함. 아래는 이 장 주제(MAC Token Profile 및 소유 증명 개념)에 대한
> 일반 지식 기반 보충입니다.

- **Bearer 토큰의 한계**: bearer 토큰은 문자열을 가진 자면 누구나 사용 가능 —
  탈취되면 그대로 악용된다.
- **MAC Token Profile**: 토큰에 결합된 비밀키로 각 요청에 **MAC(메시지 인증
  코드)** 서명을 붙여, 요청자가 실제로 키를 소유했음을 증명하는 **소유 증명
  (Proof-of-Possession, PoP)** 방식. HTTP 메서드·URI·nonce 등을 서명 대상에 포함.
- MAC Token Profile 드래프트는 표준화되지 못하고 폐기되었으며, 오늘날 같은
  목적(sender-constrained token)은 **DPoP(RFC 9449)** 나 **mTLS 결합 토큰
  (RFC 8705)** 으로 달성한다.

> **데모 연결**: `ch8/` — 폐기된 MAC Token Profile 대신 **DPoP(RFC 9449)** 로
> 구현. DPoP proof JWT(서명·`htm`/`htu`·`jti` 재전송 방지·`ath` 액세스 토큰
> 해시 바인딩), 토큰의 `cnf.jkt`(JWK 지문)와 대조. 책의 "sender-constrained
> token" 개념을 현대 표준으로 재해석한 것.

---

# 9장 — OAuth 2.0 Profiles  ⚠️ (제공 PDF에 본문 없음 · 보충)

> 원문 미포함. 아래는 이 장 주제(OAuth 2.0 확장 프로파일)에 대한 일반 지식
> 기반 보충입니다.

- OAuth 2.0은 확장 가능하도록 설계되어, 여러 보완 프로파일이 존재:
  - **Token Introspection(RFC 7662)**: 자원 서버가 인가 서버의
    `/introspect` 엔드포인트에 토큰을 질의해 활성 여부·scope·만료 등을 확인.
  - **Token Revocation(RFC 7009)**: `/revoke`로 토큰 폐기.
  - **확장 grant type**: JWT Bearer(RFC 7523), SAML2 Bearer(RFC 7522),
    Token Exchange(RFC 8693) 등 새로운 grant를 추가하는 방식.
  - **PKCE(RFC 7636)**, **Dynamic Client Registration(RFC 7591)** 등.

> **데모 연결**: `ch9/` — Spring Authorization Server가 자동 제공하는
> `/oauth2/introspect`·`/oauth2/revoke`, 그리고 커스텀
> `urn:ietf:params:oauth:grant-type:jwt-bearer` grant(RFC 7523)를 1급 grant로
> 구현한 `JwtBearerAuthenticationProvider`.

---

# 10장 — User Managed Access (UMA)  ⚠️ (제공 PDF에 본문 없음 · 보충)

> 원문 미포함. 아래는 이 장 주제(UMA)에 대한 일반 지식 기반 보충입니다.

- **UMA(User-Managed Access)**: OAuth 2.0 위에 구축된 접근 제어 프로토콜로,
  **자원 소유자가 자신이 자리에 없을 때(비동기적으로)** 정책을 통해 제3자
  (요청 당사자, Requesting Party)의 접근을 관리·허용하게 한다.
- 핵심 흐름:
  1. 요청자가 RPT(Requesting Party Token) 없이 보호 자원 요청 →
  2. 자원 서버가 **permission ticket** 과 함께 401 반환 →
  3. 요청자가 인가 서버에서 티켓을 **RPT**로 교환(정책 평가/필요 시 추가 클레임) →
  4. RPT로 자원 재요청.
- 표준 grant: `urn:ietf:params:oauth:grant-type:uma-ticket`.
- UMA 2.0은 Kantara Initiative에서 표준화.

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

## 참고: 빠진 장에 대하여

이 요약은 제공된 9개 PDF를 기준으로 작성되었습니다. 원서의 목차에는 이 외에도
**6장(OAuth 1.0)**, **12장(OpenID Connect)**, **13장(JWS/JWE)** 등이 있으나 제공
파일에는 포함되지 않았습니다. 또한 **7·8·9·10장**은 위에서 밝힌 대로 PDF 본문이
비어 있어 표준 지식으로 보충했습니다. 정확한 원문 요약이 필요한 장은 온전한
PDF(본문이 렌더링된 형태)를 다시 제공해 주세요.
