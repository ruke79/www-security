package com.example.apisecurity.ch8;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Chapter 8 - reinterpreted for this demo as DPoP (RFC 9449, "OAuth 2.0
 * Demonstrating Proof of Possession"), the modern sender-constrained-token
 * mechanism that superseded the book's (deprecated, pre-standard) OAuth
 * MAC Token Profile. Same underlying goal as MAC tokens - prove the caller
 * holds the private key bound to the token, not just the bearer string -
 * achieved instead via a signed "DPoP proof" JWT sent alongside the access
 * token on every request.
 *
 * Implemented directly against the Nimbus JOSE+JWT library (rather than
 * relying on any built-in Spring Security DPoP support) so the mechanics are
 * fully visible: proof signature verification, JWK thumbprint (RFC 7638)
 * computation for the "cnf.jkt" confirmation claim, htm/htu binding, replay
 * protection via jti, and the optional "ath" (access token hash) binding.
 */
@Component
public class DpopProofValidator {

    private static final long PROOF_FRESHNESS_SECONDS = 300;

    // In-memory replay cache: jti -> expiry epoch millis. Fine for a
    // single-instance demo; a real deployment would use a shared/distributed
    // cache (Redis etc.) so replay detection works across instances.
    private final Map<String, Long> seenProofIds = new ConcurrentHashMap<>();

    public record ValidatedProof(String jkt, String htm, String htu) {
    }

    public static class DpopValidationException extends RuntimeException {
        public DpopValidationException(String message) {
            super(message);
        }
    }

    /**
     * Validates a DPoP proof JWT against the expected HTTP method/URI, and
     * (if present) checks it matches the given access token via the "ath"
     * claim.
     *
     * @param proofJwt          the raw "DPoP" request header value
     * @param expectedHtm       the HTTP method of the current request (e.g. "POST")
     * @param expectedHtu       the HTTP target URI of the current request, no query/fragment
     * @param accessTokenValue  the bearer access token presented alongside this proof, or null
     * @return the validated proof's key thumbprint + htm/htu
     */
    public ValidatedProof validate(String proofJwt, String expectedHtm, String expectedHtu, String accessTokenValue) {
        evictExpiredEntries();

        SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(proofJwt);
        } catch (Exception e) {
            throw new DpopValidationException("Malformed DPoP proof JWT: " + e.getMessage());
        }

        String typ = signedJWT.getHeader().getType() != null ? signedJWT.getHeader().getType().getType() : null;
        if (!"dpop+jwt".equals(typ)) {
            throw new DpopValidationException("DPoP proof must have header \"typ\":\"dpop+jwt\", was: " + typ);
        }

        JWK jwk = signedJWT.getHeader().getJWK();
        if (jwk == null) {
            throw new DpopValidationException("DPoP proof JOSE header is missing an embedded public JWK");
        }
        if (jwk.isPrivate()) {
            throw new DpopValidationException("DPoP proof JOSE header must contain only the PUBLIC key, not private key material");
        }

        RSAKey rsaKey;
        try {
            rsaKey = jwk.toRSAKey();
        } catch (Exception e) {
            throw new DpopValidationException("Only RSA DPoP proof keys are supported in this demo: " + e.getMessage());
        }

        try {
            JWSVerifier verifier = new RSASSAVerifier(rsaKey);
            if (!signedJWT.verify(verifier)) {
                throw new DpopValidationException("DPoP proof signature verification failed");
            }
        } catch (DpopValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new DpopValidationException("Error verifying DPoP proof signature: " + e.getMessage());
        }

        JWTClaimsSet claims;
        try {
            claims = signedJWT.getJWTClaimsSet();
        } catch (Exception e) {
            throw new DpopValidationException("Could not parse DPoP proof claims: " + e.getMessage());
        }

        String jti = claims.getClaim("jti") instanceof String s ? s : null;
        if (jti == null || jti.isBlank()) {
            throw new DpopValidationException("DPoP proof is missing required \"jti\" claim");
        }

        Date iat = claims.getIssueTime();
        if (iat == null) {
            throw new DpopValidationException("DPoP proof is missing required \"iat\" claim");
        }
        long ageSeconds = (System.currentTimeMillis() - iat.getTime()) / 1000L;
        if (ageSeconds > PROOF_FRESHNESS_SECONDS || ageSeconds < -PROOF_FRESHNESS_SECONDS) {
            throw new DpopValidationException("DPoP proof \"iat\" is outside the acceptable freshness window");
        }

        String htm = claims.getClaim("htm") instanceof String s ? s : null;
        String htu = claims.getClaim("htu") instanceof String s ? s : null;
        if (htm == null || htu == null) {
            throw new DpopValidationException("DPoP proof is missing required \"htm\"/\"htu\" claims");
        }
        if (!htm.equalsIgnoreCase(expectedHtm)) {
            throw new DpopValidationException("DPoP proof \"htm\" (" + htm + ") does not match request method (" + expectedHtm + ")");
        }
        if (!htu.equals(expectedHtu)) {
            throw new DpopValidationException("DPoP proof \"htu\" (" + htu + ") does not match request URI (" + expectedHtu + ")");
        }

        if (accessTokenValue != null) {
            String ath = claims.getClaim("ath") instanceof String s ? s : null;
            if (ath == null) {
                throw new DpopValidationException("DPoP proof is missing required \"ath\" claim for an access-token-bound request");
            }
            String expectedAth = computeAth(accessTokenValue);
            if (!ath.equals(expectedAth)) {
                throw new DpopValidationException("DPoP proof \"ath\" does not match the presented access token");
            }
        }

        // Replay protection: each jti may only be seen once within the
        // freshness window.
        Long existing = seenProofIds.putIfAbsent(jti, System.currentTimeMillis() + PROOF_FRESHNESS_SECONDS * 1000L);
        if (existing != null) {
            throw new DpopValidationException("DPoP proof \"jti\" has already been used (replay detected)");
        }

        String jkt = computeThumbprint(jwk);
        return new ValidatedProof(jkt, htm, htu);
    }

    /** RFC 7638 JWK SHA-256 thumbprint, Base64URL-encoded (no padding). */
    public String computeThumbprint(JWK jwk) {
        try {
            return jwk.toRSAKey().toPublicJWK().computeThumbprint("SHA-256").toString();
        } catch (Exception e) {
            throw new DpopValidationException("Failed computing JWK thumbprint: " + e.getMessage());
        }
    }

    /** RFC 9449 "ath" claim: Base64URL(SHA-256(ASCII(access_token))), no padding. */
    public String computeAth(String accessTokenValue) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] digest = sha256.digest(accessTokenValue.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new DpopValidationException("Failed computing \"ath\" claim: " + e.getMessage());
        }
    }

    private void evictExpiredEntries() {
        long now = System.currentTimeMillis();
        seenProofIds.entrySet().removeIf(entry -> entry.getValue() < now);
    }
}
