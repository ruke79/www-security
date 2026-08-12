package com.example.apisecurity.ch8;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Chapter 8 (DPoP, RFC 9449) - TESTING-CONVENIENCE endpoints ONLY.
 *
 * A real DPoP client never sends its private key to a server - it generates
 * a keypair locally and signs proofs itself, entirely client-side. Since
 * this demo is exercised purely with curl (no separate client program), these
 * endpoints exist solely so you can simulate that client-side behaviour
 * over HTTP for testing purposes. Every response and doc-comment here is
 * explicit about that so nobody mistakes this for how real DPoP works.
 */
@RestController
@RequestMapping("/api/ch8/dpop")
public class DpopIssueController {

    private final JwtEncoder jwtEncoder;
    private final String issuer;
    private final DpopProofValidator dpopProofValidator;

    public DpopIssueController(
            JwtEncoder jwtEncoder, @Value("${app.issuer-uri}") String issuer, DpopProofValidator dpopProofValidator) {
        this.jwtEncoder = jwtEncoder;
        this.issuer = issuer;
        this.dpopProofValidator = dpopProofValidator;
    }

    /**
     * TESTING CONVENIENCE ONLY: generates a demo RSA keypair and returns
     * BOTH the private and public JWK as JSON. A real DPoP client keeps its
     * private key local and would never expose it like this.
     */
    @PostMapping("/keypair")
    public Map<String, Object> generateKeypair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey(keyPair.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .build();

        return Map.of(
                "warning", "TESTING CONVENIENCE ONLY - a real DPoP client generates this locally and never exposes the private key",
                "privateJwk", rsaKey.toJSONString(),
                "publicJwk", rsaKey.toPublicJWK().toJSONString()
        );
    }

    public record ProofRequest(String privateJwk, String htm, String htu, String accessToken) {
    }

    /**
     * TESTING CONVENIENCE ONLY: signs a DPoP proof JWT server-side, given a
     * private JWK from /keypair. A real client library (e.g. a browser's
     * WebCrypto-based DPoP implementation, or a backend OAuth client SDK)
     * does exactly this signing step itself, locally.
     */
    @PostMapping("/proof")
    public Map<String, Object> signProof(@RequestBody ProofRequest request) throws Exception {
        RSAKey privateRsaKey = RSAKey.parse(request.privateJwk());

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(new JOSEObjectType("dpop+jwt"))
                .jwk(privateRsaKey.toPublicJWK())
                .build();

        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .issueTime(Date.from(Instant.now()))
                .claim("htm", request.htm())
                .claim("htu", request.htu());

        if (request.accessToken() != null && !request.accessToken().isBlank()) {
            claimsBuilder.claim("ath", dpopProofValidator.computeAth(request.accessToken()));
        }

        SignedJWT signedJWT = new SignedJWT(header, claimsBuilder.build());
        JWSSigner signer = new RSASSASigner(privateRsaKey);
        signedJWT.sign(signer);

        return Map.of(
                "warning", "TESTING CONVENIENCE ONLY - a real DPoP client signs this locally with its private key",
                "proof", signedJWT.serialize()
        );
    }

    /**
     * Mints a DPoP-bound access token: the caller must present a valid DPoP
     * proof (over this exact request), and the resulting token's "cnf.jkt"
     * claim is set to that proof key's thumbprint - binding the token to
     * that key going forward, per RFC 9449 section 5.
     */
    @PostMapping("/token")
    public Map<String, Object> issueToken(@RequestHeader("DPoP") String dpopProof) {
        String htu = issuer + "/api/ch8/dpop/token";

        DpopProofValidator.ValidatedProof validated = dpopProofValidator.validate(dpopProof, "POST", htu, null);

        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .subject("dpop-demo-user")
                .audience(List.of("ch8-api"))
                .issuedAt(now)
                .expiresAt(now.plusSeconds(300))
                .claim("scope", "ch8.read")
                .claim("cnf", Map.of("jkt", validated.jkt()))
                .build();

        String tokenValue = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

        return Map.of(
                "access_token", tokenValue,
                "token_type", "DPoP",
                "expires_in", 300,
                "scope", "ch8.read",
                "note", "This token is bound (cnf.jkt) to the key that signed the DPoP proof you just presented. " +
                        "Every subsequent call to /api/ch8/protected/** must include a NEW DPoP proof signed by " +
                        "that SAME key, matching that request's method+URI."
        );
    }
}
