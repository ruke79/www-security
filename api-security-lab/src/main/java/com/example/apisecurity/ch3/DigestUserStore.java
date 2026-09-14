package com.example.apisecurity.ch3;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Per Chapter 3's recommendation: "it's recommended that you encrypt and
 * store the hash of username:password:realm" instead of the cleartext
 * password, since HTTP Digest requires recomputing HA1 = MD5(user:realm:pass)
 * on the server for every request - so, unlike HTTP Basic (which can use a
 * one-way salted hash), the server needs something reversible-enough to
 * redo that calculation.
 */
@Component
public class DigestUserStore {

    public static final String REALM = "cute-cupcakes.com";

    private final Map<String, DigestUser> users = new ConcurrentHashMap<>();

    public DigestUserStore() {
        addUser("prabath", "prabath123", "ADMIN");
        addUser("alice", "alice123", "USER");
    }

    public void addUser(String username, String password, String role) {
        String ha1 = md5Hex(username + ":" + REALM + ":" + password);
        users.put(username, new DigestUser(username, ha1, role));
    }

    public DigestUser findByUsername(String username) {
        return users.get(username);
    }

    static String md5Hex(String data) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(data.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
