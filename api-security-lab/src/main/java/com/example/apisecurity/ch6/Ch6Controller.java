package com.example.apisecurity.ch6;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Chapter 6 - OAuth 1.0.
 *
 * OAuth 1.0 (RFC 5849) is signature-based: every request carries an
 * {@code oauth_signature} computed over a canonical "base string". This
 * controller reproduces the two signature methods the book walks through -
 * PLAINTEXT and HMAC-SHA1 - and the {@code oauth_nonce} replay protection the
 * server must enforce, as testable endpoints:
 *
 *  POST /api/ch6/signature/base-string  -> build the RFC 5849 signature base string
 *  POST /api/ch6/signature/hmac-sha1     -> compute an HMAC-SHA1 oauth_signature
 *  POST /api/ch6/signature/plaintext     -> compute a PLAINTEXT oauth_signature
 *  POST /api/ch6/nonce/check             -> enforce oauth_nonce single-use (replay guard)
 *
 * This is a teaching aid for the "token dance" chapter, not a full OAuth 1.0
 * server. All of /api/ch6/** is public (catch-all permitAll chain).
 */
@RestController
@RequestMapping("/api/ch6")
public class Ch6Controller {

    // In-memory nonce store for replay detection. RFC 5849: "The Server MUST
    // ... reject any request with a nonce that has been seen before." Keyed by
    // consumer_key + nonce (+ timestamp in a real impl); demo keeps it simple.
    private final ConcurrentHashMap<String, Long> seenNonces = new ConcurrentHashMap<>();

    public record BaseStringRequest(String httpMethod, String baseUri, Map<String, String> oauthParams) {
    }

    public record HmacRequest(String httpMethod, String baseUri, Map<String, String> oauthParams,
                              String consumerSecret, String tokenSecret) {
    }

    public record PlaintextRequest(String consumerSecret, String tokenSecret) {
    }

    public record NonceRequest(String consumerKey, String nonce) {
    }

    // RFC 3986 percent-encoding as required by OAuth 1.0 (RFC 5849 §3.6).
    private static String percentEncode(String value) {
        if (value == null) {
            return "";
        }
        String encoded = URLEncoder.encode(value, StandardCharsets.UTF_8);
        // URLEncoder is application/x-www-form-urlencoded; adjust to RFC 3986.
        return encoded
                .replace("+", "%20")
                .replace("*", "%2A")
                .replace("%7E", "~");
    }

    @PostMapping("/signature/base-string")
    public ResponseEntity<Map<String, Object>> baseString(@RequestBody BaseStringRequest request) {
        String method = request.httpMethod() == null ? "POST" : request.httpMethod().toUpperCase();
        TreeMap<String, String> sorted = new TreeMap<>();
        if (request.oauthParams() != null) {
            request.oauthParams().forEach((k, v) -> {
                if (!"oauth_signature".equals(k)) {
                    sorted.put(k, v);
                }
            });
        }
        StringBuilder normalized = new StringBuilder();
        sorted.forEach((k, v) -> {
            if (normalized.length() > 0) {
                normalized.append('&');
            }
            normalized.append(percentEncode(k)).append('=').append(percentEncode(v));
        });
        String baseString = method
                + "&" + percentEncode(request.baseUri())
                + "&" + percentEncode(normalized.toString());
        return ResponseEntity.ok(Map.of(
                "baseString", baseString,
                "note", "Feed this into HMAC-SHA1(consumer_secret&token_secret, baseString) "
                        + "to obtain oauth_signature."));
    }

    @PostMapping("/signature/hmac-sha1")
    public ResponseEntity<Map<String, Object>> hmacSha1(@RequestBody HmacRequest request) {
        try {
            String method = request.httpMethod() == null ? "POST" : request.httpMethod().toUpperCase();
            TreeMap<String, String> sorted = new TreeMap<>();
            if (request.oauthParams() != null) {
                request.oauthParams().forEach((k, v) -> {
                    if (!"oauth_signature".equals(k)) {
                        sorted.put(k, v);
                    }
                });
            }
            StringBuilder normalized = new StringBuilder();
            sorted.forEach((k, v) -> {
                if (normalized.length() > 0) {
                    normalized.append('&');
                }
                normalized.append(percentEncode(k)).append('=').append(percentEncode(v));
            });
            String baseString = method
                    + "&" + percentEncode(request.baseUri())
                    + "&" + percentEncode(normalized.toString());

            // Signing key = percentEncode(consumer_secret) & percentEncode(token_secret)
            String key = percentEncode(request.consumerSecret())
                    + "&" + percentEncode(request.tokenSecret() == null ? "" : request.tokenSecret());

            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA1"));
            byte[] signatureBytes = mac.doFinal(baseString.getBytes(StandardCharsets.UTF_8));
            String signature = Base64.getEncoder().encodeToString(signatureBytes);

            return ResponseEntity.ok(Map.of(
                    "baseString", baseString,
                    "signingKey", key,
                    "oauth_signature", signature,
                    "note", "This value (URL-encoded) goes into the Authorization: OAuth header."));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "signature_failed", "error_description", String.valueOf(e.getMessage())));
        }
    }

    @PostMapping("/signature/plaintext")
    public ResponseEntity<Map<String, Object>> plaintext(@RequestBody PlaintextRequest request) {
        // PLAINTEXT: oauth_signature = consumer_secret & token_secret (no hashing).
        String signature = percentEncode(request.consumerSecret())
                + "&" + percentEncode(request.tokenSecret() == null ? "" : request.tokenSecret());
        return ResponseEntity.ok(Map.of(
                "oauth_signature", signature,
                "note", "PLAINTEXT performs no signing - it MUST be used only over TLS."));
    }

    @PostMapping("/nonce/check")
    public ResponseEntity<Map<String, Object>> nonceCheck(@RequestBody NonceRequest request) {
        String key = (request.consumerKey() == null ? "" : request.consumerKey()) + ":" + request.nonce();
        Long previous = seenNonces.putIfAbsent(key, System.currentTimeMillis());
        if (previous != null) {
            return ResponseEntity.status(401).body(Map.of(
                    "accepted", false,
                    "error", "nonce_used",
                    "error_description", "This oauth_nonce has already been seen - replay rejected (RFC 5849)."));
        }
        return ResponseEntity.ok(Map.of(
                "accepted", true,
                "message", "Nonce accepted. Replaying the same nonce now returns 401."));
    }
}
