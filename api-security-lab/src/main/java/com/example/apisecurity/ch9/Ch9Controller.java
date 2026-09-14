package com.example.apisecurity.ch9;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Chapter 9 - OAuth 2.0 Profiles.
 *
 * Reachable with an access token obtained via the custom
 * "urn:ietf:params:oauth:grant-type:jwt-bearer" grant (RFC 7523) - see
 * JwtBearerAuthenticationProvider - and also, more conventionally, via
 * /oauth2/introspect and /oauth2/revoke (both auto-provided by Spring
 * Authorization Server, no extra code needed) against ANY token this
 * Authorization Server has issued, including jwt-bearer ones, since
 * JwtBearerAuthenticationProvider explicitly saves an OAuth2Authorization
 * record for each token it mints.
 */
@RestController
@RequestMapping("/api/ch9")
public class Ch9Controller {

    @GetMapping("/resource")
    @PreAuthorize("hasAuthority('SCOPE_ch9.read')")
    public Map<String, Object> resource(JwtAuthenticationToken authentication) {
        Jwt jwt = authentication.getToken();
        return Map.of(
                "chapter", "Chapter 9 - OAuth 2.0 Profiles (custom JWT Bearer grant, RFC 7523)",
                "federatedSubject", jwt.getSubject(),
                "scope", jwt.getClaims().getOrDefault("scope", ""),
                "message", "This token's subject came from a JWT assertion, not a username/password " +
                        "or client_id - see /api/ch11/external-idp/assertion for how it was minted."
        );
    }
}
