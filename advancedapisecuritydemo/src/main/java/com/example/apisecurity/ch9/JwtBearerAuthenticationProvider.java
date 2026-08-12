package com.example.apisecurity.ch9;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Chapter 9 (OAuth 2.0 Profiles) / Chapter 11 (Federation) - implements the
 * JWT Bearer grant (RFC 7523) as a REAL, first-class grant type inside
 * Spring Authorization Server's own /oauth2/token endpoint pipeline.
 *
 * Flow: a client authenticates itself normally (e.g. HTTP Basic with its
 * client_id/secret), and instead of a user's credentials it presents a JWT
 * "assertion" - minted by some OTHER, trusted issuer (see Chapter 11's
 * ExternalIdpConfig) - identifying an end user. This provider verifies that
 * assertion, treats its "sub" claim as the identity of a federated user, and
 * issues a normal access token for that user, scoped to whatever the calling
 * client is allowed.
 *
 * This is the concrete mechanism behind:
 *  - Chapter 9: a modern "OAuth 2.0 profile" alternative grant type, and
 *  - Chapter 11: federation - a JWT assertion from an external IdP standing
 *    in for the book's SAML 2.0 Bearer Assertion flow (same RFC 7523 idea,
 *    JSON instead of XML).
 */
public class JwtBearerAuthenticationProvider implements AuthenticationProvider {

    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<?> tokenGenerator;
    private final JwtDecoder externalIdpJwtDecoder;

    public JwtBearerAuthenticationProvider(
            OAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<?> tokenGenerator,
            JwtDecoder externalIdpJwtDecoder) {
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
        this.externalIdpJwtDecoder = externalIdpJwtDecoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        JwtBearerAuthenticationToken jwtBearerAuthentication = (JwtBearerAuthenticationToken) authentication;

        OAuth2ClientAuthenticationToken clientPrincipal =
                getAuthenticatedClientElseThrowInvalidClient(jwtBearerAuthentication);
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

        if (registeredClient == null
                || !registeredClient.getAuthorizationGrantTypes()
                        .contains(JwtBearerAuthenticationConverter.JWT_BEARER_GRANT_TYPE)) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT));
        }

        Jwt assertionJwt;
        try {
            assertionJwt = this.externalIdpJwtDecoder.decode(jwtBearerAuthentication.getAssertion());
        } catch (JwtException ex) {
            throw new OAuth2AuthenticationException(new OAuth2Error(
                    OAuth2ErrorCodes.INVALID_GRANT, "Invalid or untrusted JWT assertion: " + ex.getMessage(), null));
        }

        String federatedSubject = assertionJwt.getSubject();
        if (federatedSubject == null || federatedSubject.isBlank()) {
            throw new OAuth2AuthenticationException(new OAuth2Error(
                    OAuth2ErrorCodes.INVALID_GRANT, "JWT assertion is missing a subject (sub) claim", null));
        }

        // Authorized scopes = intersection of what was requested (if anything)
        // with what the calling client is registered to receive.
        Set<String> authorizedScopes = new LinkedHashSet<>(registeredClient.getScopes());
        if (!jwtBearerAuthentication.getScopes().isEmpty()) {
            authorizedScopes.retainAll(jwtBearerAuthentication.getScopes());
        }

        // The token we're about to mint represents the FEDERATED END USER
        // (identified by the assertion's "sub"), not the calling client -
        // this is the semantically correct principal per RFC 7523.
        GrantedAuthority federatedUserAuthority = AuthorityUtils.createAuthorityList("ROLE_FEDERATED_USER").get(0);
        Authentication federatedUserPrincipal = new UsernamePasswordAuthenticationToken(
                federatedSubject, "", List.of(federatedUserAuthority));

        OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(federatedUserPrincipal)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizedScopes(authorizedScopes)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(JwtBearerAuthenticationConverter.JWT_BEARER_GRANT_TYPE)
                .authorizationGrant(jwtBearerAuthentication)
                .build();

        var generatedAccessToken = this.tokenGenerator.generate(tokenContext);
        if (generatedAccessToken == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(
                    OAuth2ErrorCodes.SERVER_ERROR, "The token generator failed to generate an access token", null));
        }

        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                generatedAccessToken.getTokenValue(),
                generatedAccessToken.getIssuedAt(),
                generatedAccessToken.getExpiresAt(),
                authorizedScopes);

        // Save an OAuth2Authorization so this token also works with the
        // Chapter 9 introspection (/oauth2/introspect) and revocation
        // (/oauth2/revoke) endpoints, just like any other AS-issued token.
        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(federatedSubject)
                .authorizationGrantType(JwtBearerAuthenticationConverter.JWT_BEARER_GRANT_TYPE)
                .authorizedScopes(authorizedScopes);

        if (generatedAccessToken instanceof ClaimAccessor claimAccessor) {
            authorizationBuilder.token(accessToken, metadata ->
                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claimAccessor.getClaims()));
        } else {
            authorizationBuilder.accessToken(accessToken);
        }

        this.authorizationService.save(authorizationBuilder.build());

        return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtBearerAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(
            Authentication authentication) {
        OAuth2ClientAuthenticationToken clientPrincipal = null;
        if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
            clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
        }
        if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
            return clientPrincipal;
        }
        throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT));
    }
}
