package com.example.apisecurity.ch10;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Chapter 10 - User-Managed Access (UMA) 2.0.
 *
 * Exchanges a permission ticket (obtained from Ch10ResourceController's 401
 * challenge) for a Requesting Party Token (RPT), via a custom
 * grant_type=urn:ietf:params:oauth:grant-type:uma-ticket - modeled as a
 * standalone endpoint (NOT wired into Spring Authorization Server's own
 * /oauth2/token pipeline, unlike Chapter 9's JWT Bearer grant) since this is
 * a deliberately simpler, lower-risk implementation reusing the shared
 * JwtEncoder/issuer.
 */
@RestController
@RequestMapping("/api/ch10/uma")
public class Ch10AuthorizationController {

    private static final String UMA_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:uma-ticket";

    private final UmaTicketStore ticketStore;
    private final JwtEncoder jwtEncoder;
    private final String issuer;

    public Ch10AuthorizationController(
            UmaTicketStore ticketStore, JwtEncoder jwtEncoder, @Value("${app.issuer-uri}") String issuer) {
        this.ticketStore = ticketStore;
        this.jwtEncoder = jwtEncoder;
        this.issuer = issuer;
    }

    public record TokenRequest(String grant_type, String ticket, String claim_token) {
    }

    @PostMapping("/token")
    public ResponseEntity<Map<String, Object>> token(@RequestBody TokenRequest request) {
        if (!UMA_GRANT_TYPE.equals(request.grant_type())) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "unsupported_grant_type",
                    "error_description", "grant_type must be " + UMA_GRANT_TYPE));
        }

        UmaTicketStore.Ticket ticket = ticketStore.consume(request.ticket());
        if (ticket == null) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "invalid_grant",
                    "error_description", "The ticket is missing, unknown, already used, or expired"));
        }

        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .subject("requesting-party")
                .audience(List.of("uma-demo"))
                .issuedAt(now)
                .expiresAt(now.plusSeconds(300))
                .claim("scope", String.join(" ", ticket.scopes()))
                .claim("resource_id", ticket.resourceId())
                .build();

        String rpt = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

        return ResponseEntity.ok(Map.of(
                "access_token", rpt,
                "token_type", "Bearer",
                "expires_in", 300,
                "scope", String.join(" ", ticket.scopes())
        ));
    }
}
