package com.example.apisecurity.lab;

import jakarta.annotation.PostConstruct;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * TRAINING LAB - SSRF (Server-Side Request Forgery) and Path Traversal.
 * Deliberately vulnerable; local training only.
 *
 *   SSRF:
 *     GET /api/lab/ssrf/fetch?url=...       -> VULNERABLE (fetches any URL)
 *     GET /api/lab/ssrf/fetch-safe?url=...  -> SAFE (allow-list + block internal)
 *     GET /api/lab/ssrf/internal-metadata   -> pretend "internal only" target
 *   Path Traversal:
 *     GET /api/lab/ssrf/file?name=...       -> VULNERABLE (base + name, no check)
 *     GET /api/lab/ssrf/file-safe?name=...  -> SAFE (normalized, must stay in base)
 */
@RestController
@RequestMapping("/api/lab/ssrf")
public class SsrfLabController {

    private Path baseDir;

    // Only these hosts are allowed by the SAFE fetch endpoint.
    private static final Set<String> ALLOWED_HOSTS = Set.of("example.com", "www.example.com");

    @PostConstruct
    void setup() throws IOException {
        baseDir = Files.createTempDirectory("lab-files");
        Files.writeString(baseDir.resolve("public.txt"), "This is a public lab file.\n");
        Files.writeString(baseDir.resolve("notes.txt"), "Harmless notes for the path-traversal lab.\n");
    }

    // --- SSRF -----------------------------------------------------------------

    /** A stand-in for an internal-only endpoint (e.g. a cloud metadata service). */
    @GetMapping("/internal-metadata")
    public Map<String, Object> internalMetadata() {
        return Map.of(
                "note", "Pretend this is only reachable from inside the network",
                "secret", "internal-api-key=LAB-DEMO-8f3a1c");
    }

    /**
     * VULNERABLE: fetches whatever URL the caller supplies. An attacker can
     * point it at internal-only services the server can reach but they can't:
     *   ?url=http://localhost:19080/api/lab/ssrf/internal-metadata
     *   ?url=http://169.254.169.254/...   (cloud metadata, in a real cloud)
     */
    @GetMapping("/fetch")
    public ResponseEntity<Object> fetchVulnerable(@RequestParam String url) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("mode", "VULNERABLE (fetches any URL)");
        out.put("requestedUrl", url);
        try {
            out.put("body", read(url));
        } catch (Exception e) {
            out.put("error", e.getMessage());
        }
        return ResponseEntity.ok(out);
    }

    /**
     * SAFE: only allow-listed external hosts; anything resolving to a
     * loopback/link-local/site-local (internal) address is refused.
     */
    @GetMapping("/fetch-safe")
    public ResponseEntity<Object> fetchSafe(@RequestParam String url) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("mode", "SAFE (allow-list + internal-address block)");
        out.put("requestedUrl", url);
        try {
            URI uri = URI.create(url);
            String host = uri.getHost();
            if (host == null || !ALLOWED_HOSTS.contains(host.toLowerCase())) {
                return ResponseEntity.status(403).body(errorBody(out,
                        "host not in allow-list " + ALLOWED_HOSTS));
            }
            InetAddress addr = InetAddress.getByName(host);
            if (addr.isLoopbackAddress() || addr.isLinkLocalAddress() || addr.isSiteLocalAddress()
                    || addr.isAnyLocalAddress()) {
                return ResponseEntity.status(403).body(errorBody(out,
                        "resolved to an internal address: " + addr.getHostAddress()));
            }
            out.put("body", read(url));
            return ResponseEntity.ok(out);
        } catch (Exception e) {
            return ResponseEntity.status(400).body(errorBody(out, String.valueOf(e.getMessage())));
        }
    }

    private static Map<String, Object> errorBody(Map<String, Object> out, String msg) {
        out.put("error", "blocked");
        out.put("error_description", msg);
        return out;
    }

    private static String read(String url) throws IOException {
        URLConnection conn = new URL(url).openConnection();
        conn.setConnectTimeout(3000);
        conn.setReadTimeout(3000);
        try (var in = conn.getInputStream()) {
            byte[] bytes = in.readAllBytes();
            String s = new String(bytes, StandardCharsets.UTF_8);
            return s.length() > 2000 ? s.substring(0, 2000) + "...(truncated)" : s;
        }
    }

    // --- Path Traversal -------------------------------------------------------

    /**
     * VULNERABLE: joins the base directory with the caller-supplied name with no
     * validation, so ../ escapes the sandbox:
     *   ?name=public.txt                       (intended)
     *   ?name=../../../../../../etc/passwd      (traversal)
     */
    @GetMapping("/file")
    public ResponseEntity<Object> fileVulnerable(@RequestParam String name) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("mode", "VULNERABLE (no path validation)");
        out.put("requestedName", name);
        try {
            Path target = baseDir.resolve(name);
            out.put("resolvedPath", target.toString());
            out.put("content", Files.readString(target));
        } catch (Exception e) {
            out.put("error", e.getMessage());
        }
        return ResponseEntity.ok(out);
    }

    /** SAFE: normalize and require the resolved path to stay under the base dir. */
    @GetMapping("/file-safe")
    public ResponseEntity<Object> fileSafe(@RequestParam String name) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("mode", "SAFE (normalized; must stay under base dir)");
        out.put("requestedName", name);
        try {
            Path target = baseDir.resolve(name).normalize();
            if (!target.startsWith(baseDir)) {
                return ResponseEntity.status(403).body(errorBody(out,
                        "path escapes the base directory"));
            }
            out.put("content", Files.readString(target));
            return ResponseEntity.ok(out);
        } catch (Exception e) {
            return ResponseEntity.status(400).body(errorBody(out, String.valueOf(e.getMessage())));
        }
    }
}
