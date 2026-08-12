package com.example.apisecurity.ch5;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Chapter 5 - Identity Delegation.
 *
 * "foo-api/drive" represents the book's Google Drive resource (reachable
 * with the ORIGINAL token, direct or brokered).
 *
 * "snapfish-api/print" represents the book's Snapfish print-photos resource
 * - reachable ONLY with a token whose audience was narrowed to it, i.e. the
 * output of {@link BrokerExchangeController}'s brokered exchange. This is
 * checked manually against the JWT's "aud" claim rather than through Spring
 * Security's scope-based method security, since audience restriction (not
 * just scope) is exactly the property Chapter 5's brokered delegation is
 * meant to demonstrate.
 */
@RestController
public class Ch5ResourceController {

    @GetMapping("/api/ch5/foo-api/drive")
    @PreAuthorize("hasAuthority('SCOPE_ch5.read') or hasAuthority('SCOPE_ch5.write')")
    public Map<String, Object> drive(JwtAuthenticationToken authentication) {
        Jwt jwt = authentication.getToken();
        return Map.of(
                "chapter", "Chapter 5 - Identity Delegation (direct delegation to foo-api/drive)",
                "subject", jwt.getSubject(),
                "message", "Access granted using the original (or a brokered) token."
        );
    }

    @GetMapping("/api/ch5/snapfish-api/print")
    public Map<String, Object> print(JwtAuthenticationToken authentication) {
        Jwt jwt = authentication.getToken();

        if (jwt.getAudience() == null || !jwt.getAudience().contains("snapfish-api")) {
            throw new AccessDeniedException(
                    "This resource requires a token whose audience was narrowed to 'snapfish-api' " +
                            "via /api/ch5/broker/exchange (brokered delegation) - the original token's audience is not sufficient.");
        }

        Object act = jwt.getClaims().get("act");

        return Map.of(
                "chapter", "Chapter 5 - Identity Delegation (brokered delegation to snapfish-api/print)",
                "subject", jwt.getSubject(),
                "actingParty", act == null ? "none (not a brokered token)" : act,
                "message", "Access granted only because this token's audience was narrowed to snapfish-api by the broker."
        );
    }
}
