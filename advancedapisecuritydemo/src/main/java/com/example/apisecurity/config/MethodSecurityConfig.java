package com.example.apisecurity.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

/**
 * Turns on {@code @PreAuthorize} / {@code @PostAuthorize} support, which is
 * relied on across several chapters (Ch3 Recipe API, Ch5 broker exchange,
 * Ch7/Ch9/Ch11 scope-protected resources).
 *
 * Without this, every {@code @PreAuthorize} annotation in the project is
 * silently ignored (methods execute unconditionally) - Spring Boot's
 * auto-configuration does NOT enable method security by default.
 */
@Configuration
@EnableMethodSecurity
public class MethodSecurityConfig {
}
