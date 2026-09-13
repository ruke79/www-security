package com.example.apisecurity.ch13;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Chapter 13 - JWT, JWS, and JWE.
 *
 * The book walks through Nimbus JOSE+JWT Java snippets for building a plaintext
 * JWT, signing a JWT with HMAC-SHA256 (JWS) and RSA-SHA256, and encrypting a
 * JWT with RSA-OAEP + AES/GCM (JWE). This controller exposes exactly those
 * operations as testable REST endpoints so you can watch a JSON payload turn
 * into a compact-serialized JWS/JWE and back again:
 *
 *  POST /api/ch13/jws/hmac/sign      -> HS256-sign your claims with a shared secret
 *  POST /api/ch13/jws/hmac/verify    -> verify an HS256 JWS with the same secret
 *  POST /api/ch13/jws/rsa/sign       -> RS256-sign your claims (server keypair)
 *  POST /api/ch13/jws/rsa/verify     -> verify an RS256 JWS with the server public key
 *  POST /api/ch13/jwe/encrypt        -> RSA-OAEP + A128GCM encrypt your claims
 *  POST /api/ch13/jwe/decrypt        -> decrypt a JWE produced above
 *
 * All of /api/ch13/** is intentionally public (falls through to the catch-all
 * permitAll chain) - it's a cryptography playground, not a protected resource.
 */
@RestController
@RequestMapping("/api/ch13")
public class Ch13Controller {

    // A stable server RSA keypair so a JWS/JWE produced by one call can be
    // verified/decrypted by a later call. Generated once at startup; a real
    // deployment would load a long-lived key from a keystore.
    private final KeyPair rsaKeyPair;

    public Ch13Controller() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            this.rsaKeyPair = generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate Ch13 demo RSA keypair", e);
        }
    }

    public record ClaimsRequest(String issuer, String subject, List<String> audience) {
    }

    public record HmacSignRequest(String secret, String issuer, String subject, List<String> audience) {
    }

    public record VerifyRequest(String jwt, String secret) {
    }

    public record TokenRequest(String jwt) {
    }

    private JWTClaimsSet buildClaims(String issuer, String subject, List<String> audience) {
        Instant now = Instant.now();
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issuer(issuer == null ? "https://apress.com" : issuer)
                .subject(subject == null ? "john" : subject)
                .issueTime(Date.from(now))
                .notBeforeTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(600)))
                .jwtID(java.util.UUID.randomUUID().toString());
        builder.audience(audience == null || audience.isEmpty()
                ? List.of("https://app1.foo.com", "https://app2.foo.com")
                : audience);
        return builder.build();
    }

    // --- JWS with HMAC-SHA256 -------------------------------------------------

    @PostMapping("/jws/hmac/sign")
    public ResponseEntity<Map<String, Object>> hmacSign(@RequestBody HmacSignRequest request) {
        try {
            if (request.secret() == null || request.secret().getBytes(StandardCharsets.UTF_8).length < 32) {
                return ResponseEntity.badRequest().body(Map.of(
                        "error", "weak_secret",
                        "error_description", "HS256 requires a shared secret of at least 32 bytes (256 bits)."));
            }
            JWTClaimsSet claims = buildClaims(request.issuer(), request.subject(), request.audience());
            SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
            JWSSigner signer = new MACSigner(request.secret().getBytes(StandardCharsets.UTF_8));
            signedJWT.sign(signer);
            return ResponseEntity.ok(Map.of(
                    "alg", "HS256",
                    "jws", signedJWT.serialize(),
                    "note", "Verify it at POST /api/ch13/jws/hmac/verify with the same secret."));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "sign_failed", "error_description", String.valueOf(e.getMessage())));
        }
    }

    @PostMapping("/jws/hmac/verify")
    public ResponseEntity<Map<String, Object>> hmacVerify(@RequestBody VerifyRequest request) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(request.jwt());
            JWSVerifier verifier = new MACVerifier(request.secret().getBytes(StandardCharsets.UTF_8));
            boolean valid = signedJWT.verify(verifier);
            return ResponseEntity.ok(Map.of(
                    "valid", valid,
                    "header", signedJWT.getHeader().toString(),
                    "claims", signedJWT.getJWTClaimsSet().toString()));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(Map.of("valid", false, "error_description", String.valueOf(e.getMessage())));
        }
    }

    // --- JWS with RSA-SHA256 --------------------------------------------------

    @PostMapping("/jws/rsa/sign")
    public ResponseEntity<Map<String, Object>> rsaSign(@RequestBody ClaimsRequest request) {
        try {
            JWTClaimsSet claims = buildClaims(request.issuer(), request.subject(), request.audience());
            SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims);
            signedJWT.sign(new RSASSASigner((RSAPrivateKey) rsaKeyPair.getPrivate()));
            return ResponseEntity.ok(Map.of(
                    "alg", "RS256",
                    "jws", signedJWT.serialize(),
                    "note", "Verify it at POST /api/ch13/jws/rsa/verify (server holds the matching public key)."));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "sign_failed", "error_description", String.valueOf(e.getMessage())));
        }
    }

    @PostMapping("/jws/rsa/verify")
    public ResponseEntity<Map<String, Object>> rsaVerify(@RequestBody TokenRequest request) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(request.jwt());
            boolean valid = signedJWT.verify(new RSASSAVerifier((RSAPublicKey) rsaKeyPair.getPublic()));
            return ResponseEntity.ok(Map.of(
                    "valid", valid,
                    "header", signedJWT.getHeader().toString(),
                    "claims", signedJWT.getJWTClaimsSet().toString()));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(Map.of("valid", false, "error_description", String.valueOf(e.getMessage())));
        }
    }

    // --- JWE with RSA-OAEP + A128GCM -----------------------------------------

    @PostMapping("/jwe/encrypt")
    public ResponseEntity<Map<String, Object>> encrypt(@RequestBody ClaimsRequest request) {
        try {
            JWTClaimsSet claims = buildClaims(request.issuer(), request.subject(), request.audience());
            JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM);
            EncryptedJWT encryptedJWT = new EncryptedJWT(header, claims);
            encryptedJWT.encrypt(new RSAEncrypter((RSAPublicKey) rsaKeyPair.getPublic()));
            return ResponseEntity.ok(Map.of(
                    "alg", "RSA-OAEP-256",
                    "enc", "A128GCM",
                    "jwe", encryptedJWT.serialize(),
                    "note", "5 dot-separated parts: header.encryptedKey.iv.ciphertext.tag. "
                            + "Decrypt at POST /api/ch13/jwe/decrypt."));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "encrypt_failed", "error_description", String.valueOf(e.getMessage())));
        }
    }

    @PostMapping("/jwe/decrypt")
    public ResponseEntity<Map<String, Object>> decrypt(@RequestBody TokenRequest request) {
        try {
            EncryptedJWT encryptedJWT = EncryptedJWT.parse(request.jwt());
            encryptedJWT.decrypt(new RSADecrypter((RSAPrivateKey) rsaKeyPair.getPrivate()));
            return ResponseEntity.ok(Map.of(
                    "header", encryptedJWT.getHeader().toString(),
                    "claims", encryptedJWT.getJWTClaimsSet().toString()));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "decrypt_failed", "error_description", String.valueOf(e.getMessage())));
        }
    }
}
