package com.example.apisecurity.ch11;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Chapter 11 - Federation.
 *
 * Reachable with an access token minted via the same custom JWT Bearer
 * grant as Chapter 9, but here specifically using an assertion obtained
 * from the "external IdP" simulated in ExternalIdpController - i.e. this
 * proves an end-to-end federation flow: Foo Inc.'s IdP vouches for a user,
 * our Authorization Server trusts that assertion, and issues its own token
 * scoped to ch11.read.
 */
@RestController
@RequestMapping("/api/ch11")
public class Ch11ResourceController {

    @GetMapping("/resource")
    @PreAuthorize("hasAuthority('SCOPE_ch11.read')")
    public Map<String, Object> resource(JwtAuthenticationToken authentication) {
        Jwt jwt = authentication.getToken();
        return Map.of(
                "chapter", "Chapter 11 - Federation (JWT assertion standing in for SAML 2.0 Bearer Assertion)",
                "federatedSubject", jwt.getSubject(),
                "scope", jwt.getClaims().getOrDefault("scope", ""),
                "message", "This access token was issued because our Authorization Server trusted a signed " +
                        "assertion from https://idp.foo-inc.example - a completely separate signing key/issuer."
        );
    }
}
