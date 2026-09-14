package com.example.apisecurity.ch5;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Chapter 5 - Identity Delegation, "brokered delegation" variant.
 *
 * The book's example (LucidChart asking Google Drive for a user's files,
 * brokered through Google) is realized here as: a caller presents a valid
 * bearer JWT (already validated by Spring's resource server support - see
 * ResourceServerConfig), and this endpoint mints a NEW, narrower-scoped JWT
 * for a DIFFERENT downstream audience, in the spirit of RFC 8693 (OAuth 2.0
 * Token Exchange).
 *
 * Implemented as a standalone controller (not wired into Spring
 * Authorization Server's own /oauth2/token pipeline like Chapter 9's JWT
 * Bearer grant) - a deliberate risk/complexity trade-off, reusing the same
 * shared JwtEncoder/issuer as the main Authorization Server so the resulting
 * token is still verifiable by the app-wide "jwtDecoder" bean.
 */
@RestController
@RequestMapping("/api/ch5/broker")
public class BrokerExchangeController {

    private final JwtEncoder jwtEncoder;
    private final String issuer;

    public BrokerExchangeController(JwtEncoder jwtEncoder, @Value("${app.issuer-uri}") String issuer) {
        this.jwtEncoder = jwtEncoder;
        this.issuer = issuer;
    }

    public record ExchangeRequest(String audience, List<String> scope) {
    }

    @PostMapping("/exchange")
    @PreAuthorize("hasAuthority('SCOPE_ch5.read') or hasAuthority('SCOPE_ch5.write')")
    public Map<String, Object> exchange(JwtAuthenticationToken authentication, @RequestBody ExchangeRequest request) {
        Jwt subjectToken = authentication.getToken();

        // Spring Authorization Server emits "scope" as a JSON array, while
        // this app's own manually-minted tokens (ch5/ch8/ch10) use a single
        // space-delimited string - handle both shapes, same as Spring
        // Security's own JwtGrantedAuthoritiesConverter does internally.
        Set<String> originalScopes = new LinkedHashSet<>();
        Object rawScopeClaim = subjectToken.getClaims().get("scope");
        if (rawScopeClaim instanceof java.util.Collection<?> collection) {
            collection.forEach(value -> originalScopes.add(String.valueOf(value)));
        } else if (rawScopeClaim instanceof String s && !s.isBlank()) {
            originalScopes.addAll(List.of(s.split(" ")));
        }

        Set<String> requestedScopes = request.scope() == null || request.scope().isEmpty()
                ? originalScopes
                : new LinkedHashSet<>(request.scope());

        // The exchanged token may never be granted MORE than the original
        // token already had - this is the crux of "narrower-scoped, brokered"
        // delegation from Chapter 5.
        requestedScopes.retainAll(originalScopes);

        if (requestedScopes.isEmpty()) {
            return Map.of(
                    "error", "invalid_scope",
                    "error_description", "None of the requested scopes are a subset of the original token's scopes"
            );
        }

        String audience = (request.audience() == null || request.audience().isBlank())
                ? "unspecified-api"
                : request.audience();

        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .subject(subjectToken.getSubject())
                .audience(List.of(audience))
                .issuedAt(now)
                .expiresAt(now.plusSeconds(300))
                .claim("scope", String.join(" ", requestedScopes))
                // "act" (RFC 8693 "actor" claim) records who performed the
                // exchange on the subject's behalf - here, the client that
                // presented the original token.
                .claim("act", Map.of("sub", authentication.getName()))
                .build();

        String exchangedToken = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

        return Map.of(
                "access_token", exchangedToken,
                "issued_token_type", "urn:ietf:params:oauth:token-type:access_token",
                "token_type", "Bearer",
                "expires_in", 300,
                "scope", String.join(" ", requestedScopes)
        );
    }
}
