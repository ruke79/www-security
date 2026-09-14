package com.example.apisecurity.ch9;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Chapter 9 (continued) - two more OAuth 2.0 profiles the chapter defines that
 * aren't covered by the built-in Authorization Server endpoints:
 *
 *  - Chain Grant Type profile: an API that received an access token from a
 *    client, and needs to call a SECOND API, can't just forward that token
 *    (audience restriction would fail). Instead it exchanges the original token
 *    for a new, equal-or-narrower-scoped one (no refresh token).
 *      POST /api/ch9b/chain/token
 *
 *  - Dynamic Client Registration profile: exposes a registration endpoint so
 *    clients can register on the fly and get a per-installation client_id /
 *    client_secret (mitigates the "one baked-in secret for all installs"
 *    problem, especially for mobile apps).
 *      POST /api/ch9b/register
 *
 * Both reuse the shared JwtEncoder/JwtDecoder/issuer so the resulting tokens are
 * verifiable by the app-wide "jwtDecoder" bean. /api/ch9b/** is public (the
 * catch-all permitAll chain); the chain endpoint still requires a valid bearer
 * JWT in the body to exchange.
 */
@RestController
@RequestMapping("/api/ch9b")
public class Ch9bController {

    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;
    private final String issuer;

    // In-memory registry of dynamically-registered clients.
    private final ConcurrentHashMap<String, Map<String, Object>> registeredClients = new ConcurrentHashMap<>();

    public Ch9bController(JwtEncoder jwtEncoder, JwtDecoder jwtDecoder,
                          @Value("${app.issuer-uri}") String issuer) {
        this.jwtEncoder = jwtEncoder;
        this.jwtDecoder = jwtDecoder;
        this.issuer = issuer;
    }

    // --- Chain Grant Type -----------------------------------------------------

    public record ChainRequest(String oauthToken, String scope, String audience) {
    }

    @PostMapping("/chain/token")
    public ResponseEntity<Map<String, Object>> chain(@RequestBody ChainRequest request) {
        Jwt original;
        try {
            original = jwtDecoder.decode(request.oauthToken());
        } catch (JwtException e) {
            return ResponseEntity.status(401).body(Map.of(
                    "error", "invalid_grant",
                    "error_description", "The presented oauth_token is invalid: " + e.getMessage()));
        }

        // Determine the original scopes (handle both space-string and array forms).
        Set<String> originalScopes = new LinkedHashSet<>();
        Object rawScope = original.getClaims().get("scope");
        if (rawScope instanceof java.util.Collection<?> collection) {
            collection.forEach(v -> originalScopes.add(String.valueOf(v)));
        } else if (rawScope instanceof String s && !s.isBlank()) {
            originalScopes.addAll(List.of(s.split(" ")));
        }

        // Requested scope must be equal to or a subset of the original.
        Set<String> requested = new LinkedHashSet<>();
        if (request.scope() != null && !request.scope().isBlank()) {
            requested.addAll(List.of(request.scope().split(" ")));
        } else {
            requested.addAll(originalScopes);
        }
        requested.retainAll(originalScopes);
        if (requested.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "invalid_scope",
                    "error_description", "Requested scope is not a subset of the original token's scope."));
        }

        Instant now = Instant.now();
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .subject(original.getSubject())
                .issuedAt(now)
                .expiresAt(now.plusSeconds(1800))
                .claim("scope", String.join(" ", requested));
        if (request.audience() != null && !request.audience().isBlank()) {
            claims.audience(List.of(request.audience()));
        }
        String chained = jwtEncoder.encode(JwtEncoderParameters.from(claims.build())).getTokenValue();

        // Per the Chain Grant Type profile: NO refresh token is returned.
        return ResponseEntity.ok(Map.of(
                "access_token", chained,
                "token_type", "Bearer",
                "expires_in", 1800,
                "scope", String.join(" ", requested),
                "note", "No refresh token by design - present the original token again to re-chain."));
    }

    // --- Dynamic Client Registration -----------------------------------------

    public record RegisterRequest(List<String> redirectUris, List<String> grantTypes,
                                  List<String> responseTypes, String tokenEndpointAuthMethod) {
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@RequestBody RegisterRequest request) {
        String clientId = UUID.randomUUID().toString().replace("-", "");
        String authMethod = request.tokenEndpointAuthMethod() == null
                ? "client_secret_basic" : request.tokenEndpointAuthMethod();

        Map<String, Object> response = new java.util.LinkedHashMap<>();
        response.put("client_id", clientId);
        // Public clients (auth method "none") don't get a secret.
        if (!"none".equals(authMethod)) {
            response.put("client_secret", UUID.randomUUID().toString().replace("-", ""));
            response.put("client_secret_expires_at", Instant.now().plusSeconds(365L * 24 * 3600).getEpochSecond());
        }
        response.put("client_id_issued_at", Instant.now().getEpochSecond());
        response.put("redirect_uris", request.redirectUris() == null ? List.of() : request.redirectUris());
        response.put("grant_types", request.grantTypes() == null ? List.of("authorization_code") : request.grantTypes());
        response.put("response_types", request.responseTypes() == null ? List.of("code") : request.responseTypes());
        response.put("token_endpoint_auth_method", authMethod);

        registeredClients.put(clientId, response);
        return ResponseEntity.status(201).body(response);
    }
}
