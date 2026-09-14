package com.example.apisecurity.lab;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * TRAINING LAB - OS Command Injection. Deliberately vulnerable; local training
 * only. (Runs harmless commands, but the vulnerable endpoint really does invoke
 * a shell, so keep it off any shared/public host.)
 *
 *   GET /api/lab/cmdi/lookup?host=example.com        -> VULNERABLE (shell string)
 *   GET /api/lab/cmdi/lookup-safe?host=example.com   -> SAFE (argv + validation)
 *
 * The vulnerable endpoint builds a shell command by string concatenation, so a
 * payload like  host=x; id  runs an extra command:
 *   ?host=x;id
 *   ?host=x%3Bid          (URL-encoded ';')
 */
@RestController
@RequestMapping("/api/lab/cmdi")
public class CommandInjectionLabController {

    // SAFE endpoint only accepts plausible hostnames/IPs.
    private static final Pattern HOSTNAME = Pattern.compile("[A-Za-z0-9._-]{1,253}");

    /**
     * VULNERABLE: the host value is concatenated into a string handed to
     * {@code sh -c}, so shell metacharacters (; | && $()) inject extra commands.
     */
    @GetMapping("/lookup")
    public ResponseEntity<Object> lookupVulnerable(@RequestParam String host) {
        String command = "echo resolving " + host;                 // <-- attacker controls this string
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("mode", "VULNERABLE (string handed to sh -c)");
        out.put("shellCommand", command);
        out.put("output", run(new String[]{"sh", "-c", command}));
        return ResponseEntity.ok(out);
    }

    /**
     * SAFE: no shell. The host is passed as a separate argv element (so
     * metacharacters are inert) AND validated against a hostname allow-pattern.
     */
    @GetMapping("/lookup-safe")
    public ResponseEntity<Object> lookupSafe(@RequestParam String host) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("mode", "SAFE (argv, no shell + input validation)");
        if (!HOSTNAME.matcher(host).matches()) {
            out.put("error", "invalid host");
            return ResponseEntity.badRequest().body(out);
        }
        // "echo" stands in for a real resolver; host is a single argv element,
        // so "x; id" is treated as one literal argument, not shell syntax.
        out.put("output", run(new String[]{"echo", "resolving", host}));
        return ResponseEntity.ok(out);
    }

    private static String run(String[] argv) {
        try {
            Process p = new ProcessBuilder(argv).redirectErrorStream(true).start();
            String output;
            try (BufferedReader r = new BufferedReader(
                    new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                output = r.lines().collect(Collectors.joining("\n"));
            }
            p.waitFor();
            return output;
        } catch (Exception e) {
            return "error: " + e.getMessage();
        }
    }
}
