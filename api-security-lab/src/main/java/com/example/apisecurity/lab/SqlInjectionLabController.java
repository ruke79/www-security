package com.example.apisecurity.lab;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * TRAINING LAB - SQL Injection (deliberately vulnerable).
 *
 * The rest of this project stores everything in memory, so it has no SQL
 * surface at all. This lab wires up a real (H2 in-memory) database and exposes
 * BOTH a vulnerable and a safe product-search endpoint so you can see the exact
 * difference between string-concatenated SQL and parameterized SQL:
 *
 *   GET /api/lab/sqli/search?name=Lemon        -> VULNERABLE (string-concatenated)
 *   GET /api/lab/sqli/search-safe?name=Lemon   -> SAFE (PreparedStatement '?')
 *
 * !!! The vulnerable endpoint exists ONLY for local, controlled security
 * training. Never deploy this to a shared/public environment. !!!
 */
@RestController
@RequestMapping("/api/lab/sqli")
public class SqlInjectionLabController {

    private final JdbcTemplate jdbc;

    public SqlInjectionLabController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * VULNERABLE: the user-supplied {@code name} is concatenated straight into
     * the SQL text. Try:
     *   ?name=Lemon Cupcake                          (normal)
     *   ?name=' OR '1'='1                            (dump all rows)
     *   ?name=' UNION SELECT id, username, id FROM lab_users --   (leak creds)
     */
    @GetMapping("/search")
    public Map<String, Object> searchVulnerable(@RequestParam String name) {
        String sql = "SELECT id, name, price FROM lab_products WHERE name = '" + name + "'";
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("mode", "VULNERABLE (string-concatenated SQL)");
        result.put("executedSql", sql);
        try {
            List<Map<String, Object>> rows = jdbc.queryForList(sql);
            result.put("rowCount", rows.size());
            result.put("rows", rows);
        } catch (Exception e) {
            // Surfacing the DB error is itself part of the lesson (verbose
            // errors help an attacker craft UNION/blind payloads).
            result.put("error", e.getMessage());
        }
        return result;
    }

    /**
     * SAFE: the same query with a bound parameter. Injection payloads are
     * treated as a literal value, so {@code ' OR '1'='1} simply matches nothing.
     */
    @GetMapping("/search-safe")
    public Map<String, Object> searchSafe(@RequestParam String name) {
        String sql = "SELECT id, name, price FROM lab_products WHERE name = ?";
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("mode", "SAFE (parameterized SQL)");
        result.put("executedSql", sql + "   [param: " + name + "]");
        List<Map<String, Object>> rows = jdbc.queryForList(sql, name);
        result.put("rowCount", rows.size());
        result.put("rows", rows);
        return result;
    }
}
