package com.example.apisecurity.config;

import com.example.apisecurity.ch3.DigestAuthenticationFilter;
import com.example.apisecurity.ch3.DigestUserStore;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Chapter 3 - HTTP Digest Authentication (RFC 2617).
 *
 * Spring Security no longer ships a DigestAuthenticationFilter (removed in
 * Spring Security 5+), so {@link DigestAuthenticationFilter} is a hand-rolled
 * implementation added directly into the filter chain, in the position the
 * built-in one used to occupy (before BasicAuthenticationFilter).
 *
 * Order 20: matches only /api/ch3/digest/**.
 */
@Configuration
public class DigestSecurityConfig {

    @Bean
    @Order(20)
    public SecurityFilterChain digestAuthFilterChain(HttpSecurity http, DigestUserStore digestUserStore)
            throws Exception {

        http.securityMatcher("/api/ch3/digest/**")
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .addFilterBefore(new DigestAuthenticationFilter(digestUserStore), BasicAuthenticationFilter.class);

        return http.build();
    }
}
