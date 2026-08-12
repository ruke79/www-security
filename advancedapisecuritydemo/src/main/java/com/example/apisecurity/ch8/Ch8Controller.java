package com.example.apisecurity.ch8;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Chapter 8 - reachable only if the caller presents both:
 *  1. A valid Bearer access token (checked by Spring Security's standard
 *     oauth2ResourceServer support), AND
 *  2. A matching DPoP proof for this exact request (checked by
 *     {@link DpopValidationFilter}, added after the Bearer filter).
 */
@RestController
@RequestMapping("/api/ch8/protected")
public class Ch8Controller {

    @GetMapping("/resource")
    public Map<String, Object> protectedResource(JwtAuthenticationToken authentication) {
        Jwt jwt = authentication.getToken();
        return Map.of(
                "chapter", "Chapter 8 - DPoP (RFC 9449), the modern successor to the OAuth MAC Token Profile",
                "subject", jwt.getSubject(),
                "cnf", jwt.getClaimAsMap("cnf"),
                "message", "This request was verified as sender-constrained: the DPoP proof you sent " +
                        "matches the key thumbprint bound into this access token's cnf.jkt claim."
        );
    }
}
