package com.example.apisecurity.common;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Registers {@link RateLimitingFilter} as a plain servlet filter (NOT a
 * Spring Security filter), scoped only to the Chapter 2 endpoints, using
 * the {@code app.rate-limit.*} properties from application.yml.
 *
 * RateLimitingFilter itself is intentionally not annotated {@code @Component}
 * so that Spring Boot doesn't ALSO auto-register it as a global filter for
 * every URL - this FilterRegistrationBean is the single, explicit place it
 * gets wired up, restricted to "/api/ch2/*".
 */
@Configuration
public class RateLimitFilterConfig {

    @Bean
    public FilterRegistrationBean<RateLimitingFilter> rateLimitingFilterRegistration(
            @Value("${app.rate-limit.capacity}") long capacity,
            @Value("${app.rate-limit.refill-per-second}") double refillPerSecond) {

        FilterRegistrationBean<RateLimitingFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new RateLimitingFilter(capacity, refillPerSecond));
        registration.addUrlPatterns("/api/ch2/*");
        registration.setName("rateLimitingFilter");
        registration.setOrder(1);
        return registration;
    }
}
