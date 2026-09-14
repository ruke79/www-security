package com.example.apisecurity.lab;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * TRAINING LAB - IDOR / BOLA (Broken Object Level Authorization) and
 * Mass Assignment. Deliberately vulnerable; local training only.
 *
 * The "current user" is passed as a simple {@code asUser} parameter to keep the
 * lab dependency-free (a real app takes it from the authenticated principal).
 *
 *   IDOR/BOLA:
 *     GET /api/lab/idor/orders/{id}?asUser=alice        -> VULNERABLE (no owner check)
 *     GET /api/lab/idor/orders-safe/{id}?asUser=alice   -> SAFE (owner enforced)
 *   Mass Assignment:
 *     POST /api/lab/idor/profile?asUser=alice           -> VULNERABLE (binds any field, incl. role)
 *     POST /api/lab/idor/profile-safe?asUser=alice      -> SAFE (only allow-listed fields)
 */
@RestController
@RequestMapping("/api/lab/idor")
public class IdorLabController {

    // orderId -> {owner, item}
    private final Map<String, Map<String, Object>> orders = new ConcurrentHashMap<>();
    // username -> {displayName, role}
    private final Map<String, Map<String, Object>> profiles = new ConcurrentHashMap<>();

    public IdorLabController() {
        orders.put("1001", mutable("owner", "alice", "item", "Alice's cupcake order"));
        orders.put("1002", mutable("owner", "bob", "item", "Bob's SECRET order"));
        profiles.put("alice", mutable("displayName", "Alice", "role", "USER"));
        profiles.put("bob", mutable("displayName", "Bob", "role", "USER"));
    }

    private static Map<String, Object> mutable(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            m.put(String.valueOf(kv[i]), kv[i + 1]);
        }
        return m;
    }

    // --- IDOR / BOLA ----------------------------------------------------------

    /**
     * VULNERABLE: returns the order for any id, never checking that it belongs
     * to {@code asUser}. So alice can read Bob's order 1002 just by guessing it.
     *   GET /api/lab/idor/orders/1002?asUser=alice
     */
    @GetMapping("/orders/{id}")
    public ResponseEntity<Object> orderVulnerable(@PathVariable String id, @RequestParam String asUser) {
        Map<String, Object> order = orders.get(id);
        if (order == null) {
            return ResponseEntity.notFound().build();
        }
        Map<String, Object> body = new LinkedHashMap<>(order);
        body.put("mode", "VULNERABLE (no ownership check)");
        body.put("requestedBy", asUser);
        return ResponseEntity.ok(body);
    }

    /** SAFE: enforces that the requesting user owns the object (or 403). */
    @GetMapping("/orders-safe/{id}")
    public ResponseEntity<Object> orderSafe(@PathVariable String id, @RequestParam String asUser) {
        Map<String, Object> order = orders.get(id);
        if (order == null) {
            return ResponseEntity.notFound().build();
        }
        if (!asUser.equals(order.get("owner"))) {
            return ResponseEntity.status(403).body(Map.of(
                    "mode", "SAFE (ownership enforced)",
                    "error", "forbidden",
                    "error_description", asUser + " does not own order " + id));
        }
        Map<String, Object> body = new LinkedHashMap<>(order);
        body.put("mode", "SAFE (ownership enforced)");
        return ResponseEntity.ok(body);
    }

    // --- Mass Assignment ------------------------------------------------------

    /**
     * VULNERABLE: merges EVERY field from the request body into the stored
     * profile - including {@code role}. A user can escalate to ADMIN with:
     *   POST /api/lab/idor/profile?asUser=alice   {"displayName":"Alice","role":"ADMIN"}
     */
    @PostMapping("/profile")
    public ResponseEntity<Object> profileVulnerable(@RequestParam String asUser,
                                                    @RequestBody Map<String, Object> body) {
        Map<String, Object> profile = profiles.get(asUser);
        if (profile == null) {
            return ResponseEntity.notFound().build();
        }
        profile.putAll(body); // <-- no field allow-list: role can be overwritten
        Map<String, Object> out = new LinkedHashMap<>(profile);
        out.put("mode", "VULNERABLE (whole body bound; role overwritable)");
        return ResponseEntity.ok(out);
    }

    /** SAFE: only the allow-listed, user-editable field (displayName) is applied. */
    @PostMapping("/profile-safe")
    public ResponseEntity<Object> profileSafe(@RequestParam String asUser,
                                              @RequestBody Map<String, Object> body) {
        Map<String, Object> profile = profiles.get(asUser);
        if (profile == null) {
            return ResponseEntity.notFound().build();
        }
        if (body.containsKey("displayName")) {
            profile.put("displayName", body.get("displayName")); // role is never touched
        }
        Map<String, Object> out = new LinkedHashMap<>(profile);
        out.put("mode", "SAFE (only displayName is bindable)");
        return ResponseEntity.ok(out);
    }
}
