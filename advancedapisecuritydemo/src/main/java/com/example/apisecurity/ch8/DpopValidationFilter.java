package com.example.apisecurity.ch8;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

/**
 * Chapter 8 - runs AFTER Spring Security's normal Bearer JWT authentication
 * (added via .addFilterAfter(..., BearerTokenAuthenticationFilter.class)),
 * and enforces that the caller also presents a valid DPoP proof matching
 * the "cnf.jkt" thumbprint embedded in the access token - i.e. that the
 * caller genuinely holds the private key the token is bound to, not just
 * the bearer string itself.
 *
 * Deliberately NOT a @Component - it is manually constructed and wired via
 * .addFilterAfter() in ResourceServerConfig, scoped only to
 * /api/ch8/protected/**, so it never runs for other chapters' Bearer-JWT
 * traffic.
 */
public class DpopValidationFilter extends OncePerRequestFilter {

    private final DpopProofValidator dpopProofValidator;
    private final String issuer;

    public DpopValidationFilter(DpopProofValidator dpopProofValidator, String issuer) {
        this.dpopProofValidator = dpopProofValidator;
        this.issuer = issuer;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (!(authentication instanceof JwtAuthenticationToken jwtAuth)) {
            // No Bearer JWT was authenticated at all (e.g. missing/invalid
            // Authorization header) - let Spring Security's own resource
            // server entry point have already handled/will handle that.
            chain.doFilter(request, response);
            return;
        }

        Jwt jwt = jwtAuth.getToken();

        Map<String, Object> cnf = jwt.getClaimAsMap("cnf");
        String expectedJkt = cnf != null ? String.valueOf(cnf.get("jkt")) : null;
        if (expectedJkt == null || "null".equals(expectedJkt)) {
            rejectDpop(response, "invalid_token", "Access token is not DPoP-bound (missing cnf.jkt claim)");
            return;
        }

        String proof = request.getHeader("DPoP");
        if (proof == null || proof.isBlank()) {
            rejectDpop(response, "invalid_request", "Missing required DPoP proof header");
            return;
        }

        String htu = issuer + request.getRequestURI();

        try {
            DpopProofValidator.ValidatedProof validated =
                    dpopProofValidator.validate(proof, request.getMethod(), htu, jwt.getTokenValue());

            if (!expectedJkt.equals(validated.jkt())) {
                rejectDpop(response, "invalid_dpop_proof",
                        "DPoP proof key does not match the access token's cnf.jkt");
                return;
            }
        } catch (DpopProofValidator.DpopValidationException e) {
            rejectDpop(response, "invalid_dpop_proof", e.getMessage());
            return;
        }

        chain.doFilter(request, response);
    }

    private void rejectDpop(HttpServletResponse response, String error, String errorDescription) throws IOException {
        SecurityContextHolder.clearContext();
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setHeader("WWW-Authenticate", "DPoP error=\"" + error + "\"");
        response.setContentType("application/json");
        response.getWriter().write(
                "{\"error\":\"" + error + "\",\"error_description\":\"" + escape(errorDescription) + "\"}");
    }

    private static String escape(String value) {
        return value == null ? "" : value.replace("\"", "'");
    }
}
