package com.example.apisecurity.config;

import org.apache.catalina.connector.Connector;
import org.apache.coyote.http11.Http11NioProtocol;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Chapter 4 - Mutual Authentication with TLS.
 *
 * Two independent pieces:
 *
 *  1. A SECOND Tomcat connector is opened on {@code app.mtls.port} (default
 *     8443) that requests (but does not force at the TLS handshake layer) a
 *     client certificate - certificateVerification="optional" so that a
 *     handshake without a client cert still completes, letting Spring
 *     Security's x509() filter respond with a clean 401/403 rather than the
 *     TLS layer just dropping the connection.
 *
 *  2. A dedicated SecurityFilterChain (order 5) that requires a trusted
 *     client certificate for anything under /api/ch4/**, regardless of
 *     which port the request arrived on. In practice only the 8443
 *     connector's requests will ever satisfy it, since the main :19080
 *     connector never asks for a client certificate at all.
 *
 * Run certs/generate-certs.sh first (from the project root) to produce the
 * keystore/truststore files this class points at.
 */
@Configuration
public class MtlsSecurityConfig {

    @Bean
    public WebServerFactoryCustomizer<TomcatServletWebServerFactory> mtlsConnectorCustomizer(
            @Value("${app.mtls.enabled:true}") boolean enabled,
            @Value("${app.mtls.port}") int mtlsPort,
            @Value("${app.mtls.keystore.path}") String keystorePath,
            @Value("${app.mtls.keystore.password}") String keystorePassword,
            @Value("${app.mtls.keystore.type}") String keystoreType,
            @Value("${app.mtls.truststore.path}") String truststorePath,
            @Value("${app.mtls.truststore.password}") String truststorePassword,
            @Value("${app.mtls.truststore.type}") String truststoreType) {

        return factory -> {
            if (!enabled) {
                return;
            }

            Connector connector = new Connector(Http11NioProtocol.class.getName());
            connector.setPort(mtlsPort);
            connector.setScheme("https");
            connector.setSecure(true);

            Http11NioProtocol protocol = (Http11NioProtocol) connector.getProtocolHandler();
            protocol.setSSLEnabled(true);

            SSLHostConfig sslHostConfig = new SSLHostConfig();
            sslHostConfig.setSslProtocol("TLS");
            // "optional" (not "required"): let the TLS handshake succeed even
            // without a client cert, so Spring Security can produce a proper
            // HTTP 401/403 instead of the connection being reset outright.
            sslHostConfig.setCertificateVerification("optional");

            SSLHostConfigCertificate certificate =
                    new SSLHostConfigCertificate(sslHostConfig, SSLHostConfigCertificate.Type.RSA);
            certificate.setCertificateKeystoreFile(keystorePath);
            certificate.setCertificateKeystorePassword(keystorePassword);
            certificate.setCertificateKeystoreType(keystoreType);
            sslHostConfig.addCertificate(certificate);

            sslHostConfig.setTruststoreFile(truststorePath);
            sslHostConfig.setTruststorePassword(truststorePassword);
            sslHostConfig.setTruststoreType(truststoreType);

            protocol.addSslHostConfig(sslHostConfig);

            factory.addAdditionalTomcatConnectors(connector);
        };
    }

    /**
     * Every distinct CN presented in a trusted client certificate is treated
     * as an authenticated ROLE_ADMIN user for this demo - real deployments
     * would map the certificate's subject to a proper identity store instead.
     */
    @Bean
    public UserDetailsService mtlsUserDetailsService() {
        return (String subjectPrincipal) -> {
            UserDetails user = User.withUsername(subjectPrincipal)
                    .password("{noop}n/a")
                    .authorities(AuthorityUtils.createAuthorityList("ROLE_ADMIN"))
                    .build();
            return user;
        };
    }

    @Bean
    @Order(5)
    public SecurityFilterChain mtlsFilterChain(HttpSecurity http, UserDetailsService mtlsUserDetailsService)
            throws Exception {

        http.securityMatcher("/api/ch4/**")
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .x509(x509 -> x509
                        .subjectPrincipalRegex("CN=(.*?)(?:,|$)")
                        .userDetailsService(mtlsUserDetailsService));

        return http.build();
    }
}
