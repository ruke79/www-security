package com.example.apisecurity.ch7;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Chapter 7 - OAuth 2.0 core: protected resources exercised via the real
 * Spring Authorization Server's Authorization Code + PKCE grant
 * (demo-authcode-client) and Client Credentials grant (demo-service-client).
 */
@RestController
@RequestMapping("/api/ch7")
public class Ch7Controller {

    @GetMapping("/resource")
    @PreAuthorize("hasAuthority('SCOPE_ch7.read')")
    public Map<String, Object> resource(JwtAuthenticationToken authentication) {
        Jwt jwt = authentication.getToken();
        return Map.of(
                "chapter", "Chapter 7 - OAuth 2.0 core",
                "subject", jwt.getSubject(),
                "clientId", jwt.getClaimAsString("client_id") != null ? jwt.getClaimAsString("client_id") : "n/a",
                "scope", jwt.getClaims().getOrDefault("scope", "")
        );
    }

    @GetMapping("/admin-resource")
    @PreAuthorize("hasAuthority('SCOPE_ch7.write')")
    public Map<String, Object> adminResource(JwtAuthenticationToken authentication) {
        Jwt jwt = authentication.getToken();
        return Map.of(
                "chapter", "Chapter 7 - OAuth 2.0 core (write-scoped resource)",
                "subject", jwt.getSubject(),
                "scope", jwt.getClaims().getOrDefault("scope", "")
        );
    }
}
