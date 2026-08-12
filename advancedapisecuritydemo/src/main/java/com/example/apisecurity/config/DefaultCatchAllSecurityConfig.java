package com.example.apisecurity.config;

import com.example.apisecurity.ch2.Ch2UserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Catches everything not matched by any earlier, more specific chain:
 *  - the Authorization Server's own interactive /login page (Chapter 7's
 *    Authorization Code flow needs a resource-owner login page to redirect
 *    to),
 *  - Chapter 8's DPoP issuance endpoints (/api/ch8/dpop/**), which are
 *    public - a DPoP proof is presented instead of a Bearer token when
 *    obtaining the very first token,
 *  - Chapter 10's UMA endpoints (/api/ch10/**), which do their own manual
 *    bearer-token parsing so they can return UMA-flavored 401 challenges
 *    instead of Spring's generic one,
 *  - Chapter 11's public "external IdP" assertion-minting endpoint,
 *  - the Chapter 7 /authorized redirect-echo endpoint used for
 *    curl-based testing of the Authorization Code flow,
 *  - static content / favicon / etc.
 *
 * Explicitly wired to {@link Ch2UserDetailsService} (rather than left
 * ambiguous) so Spring doesn't fail to start due to multiple
 * UserDetailsService beans being present in the application context.
 */
@Configuration
public class DefaultCatchAllSecurityConfig {

    @Bean
    @Order(100)
    public SecurityFilterChain catchAllFilterChain(HttpSecurity http, Ch2UserDetailsService ch2UserDetailsService)
            throws Exception {

        http.userDetailsService(ch2UserDetailsService)
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .formLogin(Customizer.withDefaults());

        return http.build();
    }
}
