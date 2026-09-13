# www-security

웹 보안 및 모의 해킹(Web Pentest) 훈련을 위한 프로젝트 모음 레포지토리입니다.

## 프로젝트 목록

### [advancedapisecuritydemo](advancedapisecuritydemo/)

*"Advanced API Security: Securing APIs with OAuth 2.0, OpenID Connect, JWS, and
JWE"* 도서를 기반으로 한 Spring Boot 3.4.1 / Spring Security 6.4 / Spring
Authorization Server 데모 프로젝트입니다. 각 챕터를 독립적으로 테스트 가능한
REST 엔드포인트 그룹으로 구현했습니다.

다루는 주제:

- HTTP Basic / Digest 인증
- 상호 TLS 인증(mTLS)
- OAuth 2.0 인가 코드(PKCE) / 클라이언트 크리덴셜 플로우
- 발신자 제한 토큰 (DPoP, RFC 9449)
- OAuth 2.0 프로필 (토큰 introspection/revocation, JWT Bearer 그랜트)
- User-Managed Access(UMA) 2.0
- 외부 IdP 연동을 통한 페더레이션

자세한 실행 방법과 챕터별 엔드포인트 매핑은 [해당 프로젝트의
README](advancedapisecuritydemo/README.md)를 참고하세요.

모의 해킹 실습용으로 정리한 취약점 시나리오(재현 절차, 근본 원인, 대응 방안)는
[VULNERABILITY-SCENARIOS.md](advancedapisecuritydemo/VULNERABILITY-SCENARIOS.md)를
참고하세요.

이 데모의 기반이 된 책 『Advanced API Security』의 장별 상세 요약(한글)은
[BOOK-SUMMARY.md](advancedapisecuritydemo/BOOK-SUMMARY.md)를 참고하세요.

책 14장의 10가지 API 보안 패턴을 데모 엔드포인트로 재현하는 실행 가이드(한글)는
[PATTERNS.md](advancedapisecuritydemo/PATTERNS.md)를 참고하세요.
