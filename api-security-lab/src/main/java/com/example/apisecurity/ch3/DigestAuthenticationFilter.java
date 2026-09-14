package com.example.apisecurity.ch3;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Chapter 3 - "HTTP Digest Authentication", implemented by hand following
 * RFC 2617, since modern Spring Security no longer ships a Digest filter.
 *
 * Flow:
 *  1. No/invalid Authorization header -> 401 + WWW-Authenticate: Digest ... (the "challenge")
 *  2. Client resends with "Authorization: Digest ..." containing a "response"
 *     value computed exactly as documented in the book:
 *        HA1      = MD5(username:realm:password)
 *        HA2      = MD5(method:digestURI)
 *        response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
 *
 * The nonce is self-encoding ("expiry:signature", Base64-encoded) so no
 * server-side nonce store is required, while still detecting tampering and
 * enforcing a validity window (mirrors what Tomcat/Apache digest modules do
 * internally).
 */
public class DigestAuthenticationFilter extends OncePerRequestFilter {

    private static final long NONCE_VALIDITY_MS = 5 * 60 * 1000L;
    private static final Pattern PARAM_PATTERN = Pattern.compile("(\\w+)=(\"[^\"]*\"|[^,]+)");

    private final DigestUserStore userStore;
    private final String nonceSecretKey;

    public DigestAuthenticationFilter(DigestUserStore userStore) {
        this.userStore = userStore;
        byte[] seed = new byte[16];
        new SecureRandom().nextBytes(seed);
        this.nonceSecretKey = Base64.getEncoder().encodeToString(seed);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String header = request.getHeader("Authorization");
        if (header == null || !header.regionMatches(true, 0, "Digest ", 0, 7)) {
            sendChallenge(response, false);
            return;
        }

        Map<String, String> params = parse(header.substring(7));
        String nonce = params.get("nonce");
        if (nonce == null || !isNonceValid(nonce)) {
            sendChallenge(response, true);
            return;
        }

        String username = params.get("username");
        DigestUser user = username == null ? null : userStore.findByUsername(username);
        if (user == null) {
            sendChallenge(response, false);
            return;
        }

        String uri = params.get("uri");
        String ha2 = DigestUserStore.md5Hex(request.getMethod() + ":" + uri);
        String qop = params.getOrDefault("qop", "auth");
        String expected = DigestUserStore.md5Hex(
                user.getHa1() + ":" + nonce + ":" + params.get("nc") + ":" + params.get("cnonce") + ":" + qop + ":" + ha2);

        if (params.get("response") == null || !expected.equalsIgnoreCase(params.get("response"))) {
            sendChallenge(response, false);
            return;
        }

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                user.getUsername(), null, AuthorityUtils.createAuthorityList("ROLE_" + user.getRole()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(request, response);
    }

    private void sendChallenge(HttpServletResponse response, boolean stale) throws IOException {
        String nonce = generateNonce();
        String header = "Digest realm=\"" + DigestUserStore.REALM + "\", qop=\"auth\", nonce=\"" + nonce
                + "\", opaque=\"" + DigestUserStore.md5Hex(DigestUserStore.REALM) + "\""
                + (stale ? ", stale=true" : "");
        response.setHeader("WWW-Authenticate", header);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\":\"unauthorized\",\"scheme\":\"Digest\"}");
    }

    private String generateNonce() {
        long expiry = System.currentTimeMillis() + NONCE_VALIDITY_MS;
        String signature = DigestUserStore.md5Hex(expiry + ":" + nonceSecretKey);
        return Base64.getEncoder().encodeToString((expiry + ":" + signature).getBytes(StandardCharsets.UTF_8));
    }

    private boolean isNonceValid(String nonce) {
        try {
            String decoded = new String(Base64.getDecoder().decode(nonce), StandardCharsets.UTF_8);
            String[] parts = decoded.split(":", 2);
            long expiry = Long.parseLong(parts[0]);
            String signature = parts[1];
            String expectedSignature = DigestUserStore.md5Hex(expiry + ":" + nonceSecretKey);
            return signature.equals(expectedSignature) && System.currentTimeMillis() < expiry;
        } catch (Exception e) {
            return false;
        }
    }

    private Map<String, String> parse(String header) {
        Map<String, String> result = new HashMap<>();
        Matcher matcher = PARAM_PATTERN.matcher(header);
        while (matcher.find()) {
            String key = matcher.group(1);
            String value = matcher.group(2);
            if (value.startsWith("\"") && value.endsWith("\"")) {
                value = value.substring(1, value.length() - 1);
            }
            result.put(key, value.trim());
        }
        return result;
    }
}
