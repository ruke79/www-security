package com.example.apisecurity.ch10;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Chapter 10 - User-Managed Access (UMA) 2.0.
 *
 * Deliberately NOT protected by Spring Security's oauth2ResourceServer
 * support (it falls through to the Chapter 100 catch-all permitAll chain
 * instead) - this controller does its OWN bearer-token parsing so it can
 * return the UMA-flavored challenge (401 + WWW-Authenticate: UMA
 * ticket="...") that the protocol requires, instead of Spring's generic
 * "Bearer" challenge.
 *
 * Reuses the SAME main "jwtDecoder" bean as every other chapter to validate
 * a presented RPT, since Ch10AuthorizationController mints RPTs using the
 * same shared signing key/issuer.
 */
@RestController
@RequestMapping("/api/ch10")
public class Ch10ResourceController {

    private final UmaTicketStore ticketStore;
    private final JwtDecoder jwtDecoder;
    private final String issuer;

    public Ch10ResourceController(
            UmaTicketStore ticketStore, JwtDecoder jwtDecoder, @Value("${app.issuer-uri}") String issuer) {
        this.ticketStore = ticketStore;
        this.jwtDecoder = jwtDecoder;
        this.issuer = issuer;
    }

    @GetMapping("/resource/{resourceId}")
    public ResponseEntity<Map<String, Object>> resource(
            @PathVariable String resourceId, HttpServletRequest request, HttpServletResponse response) {

        String authorizationHeader = request.getHeader("Authorization");

        if (authorizationHeader == null || !authorizationHeader.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return challenge(resourceId);
        }

        String token = authorizationHeader.substring(7).trim();

        Jwt rpt;
        try {
            rpt = jwtDecoder.decode(token);
        } catch (JwtException e) {
            return challenge(resourceId);
        }

        Object claimedResourceId = rpt.getClaims().get("resource_id");
        if (!resourceId.equals(claimedResourceId)) {
            return challenge(resourceId);
        }

        return ResponseEntity.ok(Map.of(
                "chapter", "Chapter 10 - User-Managed Access (UMA) 2.0",
                "resourceId", resourceId,
                "accessedBy", rpt.getSubject(),
                "grantedScopes", rpt.getClaims().getOrDefault("scope", "")
        ));
    }

    private ResponseEntity<Map<String, Object>> challenge(String resourceId) {
        UmaTicketStore.Ticket ticket = ticketStore.issueTicket(resourceId, List.of("read"));
        String wwwAuthenticate = "UMA realm=\"uma-demo\", as_uri=\"" + issuer + "\", ticket=\"" + ticket.ticket() + "\"";

        return ResponseEntity.status(401)
                .header("WWW-Authenticate", wwwAuthenticate)
                .body(Map.of(
                        "error", "uma_ticket_required",
                        "ticket", ticket.ticket(),
                        "as_uri", issuer,
                        "message", "Exchange this ticket for an RPT at POST /api/ch10/uma/token, " +
                                "then retry this request with 'Authorization: Bearer <rpt>'."
                ));
    }
}
