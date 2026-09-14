package com.example.apisecurity.ch11;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

/**
 * Chapter 11 - Federation.
 *
 * The book's example is federation via SAML 2.0 Bearer Assertion: a trusted
 * external Identity Provider (e.g. a partner company) issues a signed
 * assertion about one of ITS users, and our Authorization Server accepts
 * that assertion (instead of a local username/password) to mint its OWN
 * access token for that federated user. This demo substitutes a signed JWT
 * assertion for the SAML/XML assertion (same trust model, JSON instead of
 * XML - SAML tooling was out of scope for this project) - realized via
 * Chapter 9's JWT Bearer grant (RFC 7523) machinery.
 *
 * The key point this class demonstrates: "Foo Inc." (the external IdP) has
 * its OWN, completely independent RSA signing key - NOT the main
 * Authorization Server's key - so trust in its assertions is a deliberate,
 * explicit configuration choice (wiring its decoder into
 * JwtBearerAuthenticationProvider), exactly as it would be with a real
 * external partner in production.
 */
@Configuration
public class ExternalIdpConfig {

    public static final String EXTERNAL_IDP_ISSUER = "https://idp.foo-inc.example";

    private static final KeyPair KEY_PAIR = generateKeyPair();

    private static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate the external IdP's demo RSA keypair", e);
        }
    }

    /**
     * The external IdP's signing key is deliberately NOT exposed as a
     * {@code JWKSource<SecurityContext>} bean: Spring Authorization Server looks
     * up that type by class (not by name) to find the Authorization Server's own
     * signing key, so a second JWKSource bean would make that lookup ambiguous
     * and break context startup. We build the JWKSource locally and hand it
     * straight to this encoder instead, keeping the external IdP's key material
     * scoped to this "partner company" trust domain.
     */
    @Bean
    public JwtEncoder externalIdpJwtEncoder() {
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) KEY_PAIR.getPublic())
                .privateKey((RSAPrivateKey) KEY_PAIR.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSource<SecurityContext> externalIdpJwkSource = new ImmutableJWKSet<>(new JWKSet(rsaKey));
        return new NimbusJwtEncoder(externalIdpJwkSource);
    }

    /**
     * Independent of the app-wide "jwtDecoder" bean on purpose - built
     * directly from the external IdP's public key rather than by reusing
     * OAuth2AuthorizationServerConfiguration.jwtDecoder(JWKSource), since
     * this decoder conceptually belongs to a completely separate trust
     * domain (a partner company's IdP), not "the" Authorization Server.
     */
    @Bean
    public JwtDecoder externalIdpJwtDecoder() {
        return NimbusJwtDecoder.withPublicKey((RSAPublicKey) KEY_PAIR.getPublic()).build();
    }
}
