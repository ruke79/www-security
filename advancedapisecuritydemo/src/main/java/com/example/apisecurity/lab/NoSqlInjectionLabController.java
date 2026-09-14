package com.example.apisecurity.lab;

import jakarta.annotation.PostConstruct;
import org.bson.Document;
import org.springframework.context.annotation.Profile;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.BasicQuery;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * TRAINING LAB - NoSQL (MongoDB) injection. Deliberately vulnerable; local
 * training only. Active ONLY under the "mongo" Spring profile:
 *
 *   docker compose up -d mongo
 *   SPRING_PROFILES_ACTIVE=mongo mvn spring-boot:run
 *
 *   POST /api/lab/nosqli/login        {username,password}  -> VULNERABLE
 *   POST /api/lab/nosqli/login-safe   {username,password}  -> SAFE
 *
 * The classic authentication-bypass payload sends an operator object instead of
 * a string password, so the query matches without knowing the real password:
 *   {"username":"admin","password":{"$ne":null}}
 *   {"username":"admin","password":{"$gt":""}}
 */
@RestController
@RequestMapping("/api/lab/nosqli")
@Profile("mongo")
public class NoSqlInjectionLabController {

    private final MongoTemplate mongo;

    public NoSqlInjectionLabController(MongoTemplate mongo) {
        this.mongo = mongo;
    }

    @PostConstruct
    void seed() {
        mongo.dropCollection("lab_users");
        mongo.getCollection("lab_users").insertMany(List.of(
                new Document("username", "admin").append("password", "S3cr3t-demo-pw!"),
                new Document("username", "alice").append("password", "alice-demo-pw")));
    }

    /**
     * VULNERABLE: the raw request body becomes the Mongo query document, so a
     * password of {"$ne": null} is interpreted as a query OPERATOR rather than a
     * literal value - matching the admin row without the real password.
     */
    @PostMapping("/login")
    public ResponseEntity<Object> loginVulnerable(@RequestBody Map<String, Object> body) {
        Document query = new Document("username", body.get("username"))
                .append("password", body.get("password")); // value may be an operator object
        Document user = mongo.getCollection("lab_users").find(query).first();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("mode", "VULNERABLE (request body used as query document)");
        out.put("query", query.toJson());
        out.put("authenticated", user != null);
        out.put("loggedInAs", user != null ? user.getString("username") : null);
        return ResponseEntity.ok(out);
    }

    /**
     * SAFE: username/password are coerced to plain strings and bound as literal
     * values via Criteria, so an operator object cannot change the query shape.
     */
    @PostMapping("/login-safe")
    public ResponseEntity<Object> loginSafe(@RequestBody Map<String, Object> body) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("mode", "SAFE (values coerced to strings + bound literally)");
        Object u = body.get("username");
        Object p = body.get("password");
        if (!(u instanceof String) || !(p instanceof String)) {
            out.put("authenticated", false);
            out.put("error", "username and password must be strings");
            return ResponseEntity.badRequest().body(out);
        }
        Query query = Query.query(Criteria.where("username").is(u).and("password").is(p));
        Document user = mongo.findOne(new BasicQuery(query.getQueryObject()), Document.class, "lab_users");
        out.put("authenticated", user != null);
        out.put("loggedInAs", user != null ? user.getString("username") : null);
        return ResponseEntity.ok(out);
    }
}
