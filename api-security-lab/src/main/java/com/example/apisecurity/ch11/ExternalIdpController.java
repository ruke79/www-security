package com.example.apisecurity.ch11;

import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Chapter 11 - Federation.
 *
 * Simulates "Foo Inc.'s" external Identity Provider minting a signed
 * assertion about one of its own users. INTENTIONALLY public/unauthenticated
 * - in the real world this would be a completely separate company's server
 * that our Authorization Server has no control over; we can only choose
 * whether to TRUST assertions it signs (see ExternalIdpConfig /
 * JwtBearerAuthenticationProvider), never how it issues them.
 */
@RestController
@RequestMapping("/api/ch11")
public class ExternalIdpController {

    private final JwtEncoder externalIdpJwtEncoder;
    private final String issuer;

    public ExternalIdpController(JwtEncoder externalIdpJwtEncoder,
                                 @org.springframework.beans.factory.annotation.Value("${app.issuer-uri}") String issuer) {
        this.externalIdpJwtEncoder = externalIdpJwtEncoder;
        this.issuer = issuer;
    }

    @GetMapping("/external-idp/assertion")
    public Map<String, Object> mintAssertion(
            @RequestParam(defaultValue = "alice@foo-inc.example") String user) {

        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(ExternalIdpConfig.EXTERNAL_IDP_ISSUER)
                .subject(user)
                .audience(List.of("demo-jwtbearer-client"))
                .issuedAt(now)
                .expiresAt(now.plusSeconds(300))
                .claim("company", "Foo Inc.")
                .build();

        JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256).build();
        String assertion = externalIdpJwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims)).getTokenValue();

        String curlCommand = "curl -u demo-jwtbearer-client:jwtbearer-secret -X POST " + issuer + "/oauth2/token "
                + "-d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer "
                + "-d assertion=" + assertion;

        return Map.of(
                "chapter", "Chapter 11 - Federation (external IdP assertion, standing in for a SAML 2.0 Bearer Assertion)",
                "issuer", ExternalIdpConfig.EXTERNAL_IDP_ISSUER,
                "subject", user,
                "assertion", assertion,
                "howToUse", curlCommand
        );
    }
}
