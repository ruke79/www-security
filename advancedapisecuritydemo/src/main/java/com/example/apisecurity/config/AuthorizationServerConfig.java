package com.example.apisecurity.config;

import com.example.apisecurity.ch9.JwtBearerAuthenticationConverter;
import com.example.apisecurity.ch9.JwtBearerAuthenticationProvider;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.http.MediaType;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;

/**
 * Chapter 7 (OAuth 2.0 core), Chapter 9 (OAuth 2.0 Profiles: introspection,
 * revocation, PKCE, and the custom JWT Bearer grant), and Chapter 11
 * (Federation, reusing the same JWT Bearer grant) - the REAL Spring
 * Authorization Server, wired into its own dedicated filter chain.
 *
 * The custom "urn:ietf:params:oauth:grant-type:jwt-bearer" grant is added
 * ADDITIVELY to the token endpoint (accessTokenRequestConverter /
 * authenticationProvider are additive, not replacing, since Spring
 * Authorization Server 1.4) so the standard authorization_code /
 * client_credentials / refresh_token grants keep working unmodified.
 */
@Configuration
public class AuthorizationServerConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http,
            OAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<?> tokenGenerator,
            JwtDecoder externalIdpJwtDecoder) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();

        JwtBearerAuthenticationProvider jwtBearerAuthenticationProvider =
                new JwtBearerAuthenticationProvider(authorizationService, tokenGenerator, externalIdpJwtDecoder);

        http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, authorizationServer -> authorizationServer
                        .tokenEndpoint(tokenEndpoint -> tokenEndpoint
                                .accessTokenRequestConverter(new JwtBearerAuthenticationConverter())
                                .authenticationProvider(jwtBearerAuthenticationProvider)))
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .exceptionHandling(exceptions -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)));

        return http.build();
    }

    /**
     * All four demo clients used across chapters 5, 7, 9, and 11.
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient authCodeClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("demo-authcode-client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127.0.0.1:8080/authorized")
                .scope("ch7.read")
                .scope("ch7.write")
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .requireProofKey(true)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(15))
                        .build())
                .build();

        RegisteredClient serviceClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("demo-service-client")
                .clientSecret("{noop}service-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("ch7.read")
                .scope("ch7.write")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(15))
                        .build())
                .build();

        RegisteredClient lucidchartClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("lucidchart-client")
                .clientSecret("{noop}lucidchart-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("ch5.read")
                .scope("ch5.write")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(15))
                        .build())
                .build();

        RegisteredClient jwtBearerClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("demo-jwtbearer-client")
                .clientSecret("{noop}jwtbearer-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(JwtBearerAuthenticationConverter.JWT_BEARER_GRANT_TYPE)
                .scope("ch9.read")
                .scope("ch11.read")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(15))
                        .build())
                .build();

        return new InMemoryRegisteredClientRepository(
                authCodeClient, serviceClient, lucidchartClient, jwtBearerClient);
    }

    @Bean
    public OAuth2AuthorizationService authorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }

    /**
     * The Authorization Server's own RSA signing key. Every token the AS
     * itself issues (authorization_code / client_credentials / refresh_token
     * / jwt-bearer grants) is signed with this key, and this SAME
     * JWKSource backs the app-wide "jwtDecoder" bean used by every resource
     * server chain (Ch5, Ch7, Ch9, Ch11) plus the shared JwtEncoder used to
     * manually mint tokens in Ch5 (token exchange), Ch8 (DPoP-bound tokens),
     * and Ch10 (UMA RPTs) - so ONE decoder validates all of them.
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource()
            throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(
            JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public JwtEncoder jwtEncoder(
            JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator(JwtEncoder jwtEncoder) {
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(jwtCustomizer());
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
        return new DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
    }

    /**
     * No extra claims needed for the demo, but this is the natural extension
     * point (used e.g. by Chapter 9's how-to guides) if custom claims were
     * ever required on AS-issued JWTs.
     */
    private org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer<JwtEncodingContext>
            jwtCustomizer() {
        return context -> {
            // Intentionally a no-op for this demo; kept as an explicit
            // extension point rather than omitted, since several other
            // chapters' "how-to" guides hook in here.
        };
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings(
            @Value("${app.issuer-uri}") String issuerUri) {
        return AuthorizationServerSettings.builder()
                .issuer(issuerUri)
                .build();
    }
}
