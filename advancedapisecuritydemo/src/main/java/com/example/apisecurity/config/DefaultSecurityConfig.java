package com.example.apisecurity.config;

import com.example.apisecurity.ch2.Ch2UserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Chapter 2 (Security by Design) + Chapter 3's HTTP Basic Authentication
 * variant of the Recipe API.
 *
 * Order 10: matches everything under /api/ch2/** and /api/ch3/basic/**.
 * Stateless-ish HTTP Basic auth backed by {@link Ch2UserDetailsService}
 * (BCrypt-hashed passwords, per Chapter 2's "protect data at rest" +
 * Chapter 3's "always hash/salt credentials" guidance).
 */
@Configuration
public class DefaultSecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Order(10)
    public SecurityFilterChain basicAuthFilterChain(HttpSecurity http, Ch2UserDetailsService ch2UserDetailsService)
            throws Exception {

        http.securityMatcher("/api/ch2/**", "/api/ch3/basic/**")
                .csrf(csrf -> csrf.disable())
                .userDetailsService(ch2UserDetailsService)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/ch2/public", "/api/ch2/register").permitAll()
                        .anyRequest().authenticated())
                .httpBasic(basic -> {})
                .sessionManagement(session -> session
                        .sessionCreationPolicy(org.springframework.security.config.http.SessionCreationPolicy.STATELESS))
                .headers(headers -> headers
                        .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'"))
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny));

        return http.build();
    }
}
