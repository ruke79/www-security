package com.example.apisecurity.config;

import com.example.apisecurity.ch8.DpopProofValidator;
import com.example.apisecurity.ch8.DpopValidationFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Plain OAuth2 Resource Server chains, validating Bearer JWTs minted either
 * by the real Authorization Server (Chapter 7/9 grants) or manually via the
 * shared JwtEncoder (Chapter 5's token-exchange result, Chapter 11's
 * federated-user token) - all decodable by the same "jwtDecoder" bean since
 * they share one issuer/signing key.
 */
@Configuration
public class ResourceServerConfig {

    @Bean
    @Order(30)
    public SecurityFilterChain resourceServerFilterChain(HttpSecurity http, JwtDecoder jwtDecoder) throws Exception {
        http.securityMatcher("/api/ch5/**", "/api/ch7/**", "/api/ch9/**", "/api/ch11/resource/**")
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.decoder(jwtDecoder)));

        return http.build();
    }

    /**
     * Chapter 8 - same Bearer-JWT validation as above, PLUS the DPoP
     * validation filter added directly after Spring's own
     * BearerTokenAuthenticationFilter, so it runs only once a Bearer JWT has
     * already been authenticated (and can therefore inspect its cnf.jkt
     * claim).
     */
    @Bean
    @Order(31)
    public SecurityFilterChain ch8DpopFilterChain(
            HttpSecurity http,
            JwtDecoder jwtDecoder,
            DpopProofValidator dpopProofValidator,
            @Value("${app.issuer-uri}") String issuer) throws Exception {

        http.securityMatcher("/api/ch8/protected/**")
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.decoder(jwtDecoder)))
                .addFilterAfter(new DpopValidationFilter(dpopProofValidator, issuer), BearerTokenAuthenticationFilter.class);

        return http.build();
    }
}
