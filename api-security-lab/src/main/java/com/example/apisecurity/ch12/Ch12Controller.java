package com.example.apisecurity.ch12;

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
import java.util.List;
import java.util.Map;

/**
 * Chapter 12 - OpenID Connect.
 *
 * OpenID Connect layers an identity token (ID token) on top of OAuth 2.0. The
 * ID token is a signed JWT that carries authenticated-user information from the
 * authorization server to the client, with a well-defined claim set (iss, sub,
 * aud, exp, iat, auth_time, nonce, ...). This controller demonstrates the
 * OpenID-Connect-specific pieces on top of the app's existing OAuth 2.0
 * Authorization Server:
 *
 *  POST /api/ch12/id-token/issue     -> mint an OIDC ID token (signed JWT) for a user
 *  POST /api/ch12/id-token/validate  -> validate an ID token: signature + iss/aud/nonce
 *  POST /api/ch12/userinfo           -> UserInfo-style endpoint: return claims for an ID token
 *
 * The ID token is signed with the SAME shared RSA key / issuer as the rest of
 * the app (see AuthorizationServerConfig), so the shared "jwtDecoder" validates
 * it. The 'nonce' handling mirrors the OIDC replay-mitigation rule: the value
 * sent in the authentication request must come back unchanged in the ID token,
 * and the client must verify it.
 */
@RestController
@RequestMapping("/api/ch12")
public class Ch12Controller {

    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;
    private final String issuer;

    public Ch12Controller(JwtEncoder jwtEncoder, JwtDecoder jwtDecoder,
                          @Value("${app.issuer-uri}") String issuer) {
        this.jwtEncoder = jwtEncoder;
        this.jwtDecoder = jwtDecoder;
        this.issuer = issuer;
    }

    public record IdTokenRequest(String subject, String clientId, String nonce, Map<String, Object> extraClaims) {
    }

    public record ValidateRequest(String idToken, String expectedClientId, String expectedNonce) {
    }

    public record TokenOnlyRequest(String idToken) {
    }

    @PostMapping("/id-token/issue")
    public ResponseEntity<Map<String, Object>> issue(@RequestBody IdTokenRequest request) {
        if (request.subject() == null || request.subject().isBlank()
                || request.clientId() == null || request.clientId().isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "invalid_request",
                    "error_description", "subject and clientId are required."));
        }
        Instant now = Instant.now();
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .subject(request.subject())
                .audience(List.of(request.clientId()))
                .issuedAt(now)
                .expiresAt(now.plusSeconds(300))
                // OIDC: time of end-user authentication.
                .claim("auth_time", now.getEpochSecond())
                // 'azp' (authorized party) is set to the client id.
                .claim("azp", request.clientId());
        // OIDC: echo back the nonce so the client can detect replay.
        if (request.nonce() != null && !request.nonce().isBlank()) {
            claims.claim("nonce", request.nonce());
        }
        if (request.extraClaims() != null) {
            request.extraClaims().forEach(claims::claim);
        }
        String idToken = jwtEncoder.encode(JwtEncoderParameters.from(claims.build())).getTokenValue();
        return ResponseEntity.ok(Map.of(
                "id_token", idToken,
                "token_type", "Bearer",
                "note", "Signed JWT. Validate it at POST /api/ch12/id-token/validate "
                        + "(check iss, aud=clientId, and nonce)."));
    }

    @PostMapping("/id-token/validate")
    public ResponseEntity<Map<String, Object>> validate(@RequestBody ValidateRequest request) {
        Jwt jwt;
        try {
            jwt = jwtDecoder.decode(request.idToken());
        } catch (JwtException e) {
            return ResponseEntity.status(401).body(Map.of(
                    "valid", false,
                    "error", "invalid_token",
                    "error_description", "Signature/expiry validation failed: " + e.getMessage()));
        }

        // iss check
        if (!issuer.equals(jwt.getIssuer() == null ? null : jwt.getIssuer().toString())) {
            return ResponseEntity.status(401).body(Map.of(
                    "valid", false, "error", "issuer_mismatch",
                    "error_description", "iss does not match this authorization server."));
        }
        // aud check (must contain the OAuth client id)
        if (request.expectedClientId() != null
                && (jwt.getAudience() == null || !jwt.getAudience().contains(request.expectedClientId()))) {
            return ResponseEntity.status(401).body(Map.of(
                    "valid", false, "error", "audience_mismatch",
                    "error_description", "aud does not contain the expected client id."));
        }
        // nonce check (OIDC replay mitigation)
        if (request.expectedNonce() != null
                && !request.expectedNonce().equals(jwt.getClaimAsString("nonce"))) {
            return ResponseEntity.status(401).body(Map.of(
                    "valid", false, "error", "nonce_mismatch",
                    "error_description", "nonce in the ID token does not match the one sent in the auth request."));
        }
        return ResponseEntity.ok(Map.of(
                "valid", true,
                "sub", jwt.getSubject(),
                "aud", jwt.getAudience(),
                "auth_time", jwt.getClaims().getOrDefault("auth_time", "n/a"),
                "message", "ID token is valid (signature + iss + aud + nonce)."));
    }

    @PostMapping("/userinfo")
    public ResponseEntity<Map<String, Object>> userinfo(@RequestBody TokenOnlyRequest request) {
        try {
            Jwt jwt = jwtDecoder.decode(request.idToken());
            // A real UserInfo endpoint returns the standard OIDC claims for the
            // subject; here we surface whatever claims the ID token carries.
            return ResponseEntity.ok(Map.of(
                    "sub", jwt.getSubject(),
                    "claims", jwt.getClaims()));
        } catch (JwtException e) {
            return ResponseEntity.status(401).body(Map.of(
                    "error", "invalid_token", "error_description", e.getMessage()));
        }
    }
}
