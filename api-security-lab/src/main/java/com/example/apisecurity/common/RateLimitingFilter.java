package com.example.apisecurity.common;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Chapter 2 - Security by Design, "Availability" / DoS mitigation.
 *
 * A minimal in-memory token-bucket rate limiter, keyed per client IP. Not
 * distributed/production-grade (that would require a shared store such as
 * Redis) - it exists purely to demonstrate the concept discussed in the
 * book's "Availability" section: aborting excessive requests before they can
 * exhaust server resources.
 */
public class RateLimitingFilter extends OncePerRequestFilter {

    private final long capacity;
    private final double refillPerSecond;
    private final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();

    public RateLimitingFilter(long capacity, double refillPerSecond) {
        this.capacity = capacity;
        this.refillPerSecond = refillPerSecond;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String clientId = clientId(request);
        Bucket bucket = buckets.computeIfAbsent(clientId, key -> new Bucket(capacity));

        if (bucket.tryConsume(refillPerSecond, capacity)) {
            chain.doFilter(request, response);
        } else {
            response.setStatus(429);
            response.setContentType("application/json");
            response.getWriter().write(
                    "{\"error\":\"too_many_requests\",\"message\":\"Rate limit exceeded - " +
                            "see Chapter 2, Availability / DoS mitigation.\"}");
        }
    }

    private String clientId(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        return forwarded != null ? forwarded : request.getRemoteAddr();
    }

    /** Simple token bucket. Not thread-contention-optimized; fine for a demo. */
    private static final class Bucket {
        private double tokens;
        private long lastRefillNanos;

        Bucket(double initialTokens) {
            this.tokens = initialTokens;
            this.lastRefillNanos = System.nanoTime();
        }

        synchronized boolean tryConsume(double refillPerSecond, long capacity) {
            refill(refillPerSecond, capacity);
            if (tokens >= 1.0) {
                tokens -= 1.0;
                return true;
            }
            return false;
        }

        private void refill(double refillPerSecond, long capacity) {
            long now = System.nanoTime();
            double elapsedSeconds = (now - lastRefillNanos) / 1_000_000_000.0;
            double refill = elapsedSeconds * refillPerSecond;
            if (refill > 0) {
                tokens = Math.min(capacity, tokens + refill);
                lastRefillNanos = now;
            }
        }
    }
}
