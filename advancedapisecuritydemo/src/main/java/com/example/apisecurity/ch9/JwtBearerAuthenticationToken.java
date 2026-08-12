package com.example.apisecurity.ch9;

import org.springframework.security.authentication.AbstractAuthenticationToken;

import java.util.Collections;
import java.util.Set;

/**
 * Chapter 9 / Chapter 11 - carries an in-flight "urn:ietf:params:oauth:grant-type:jwt-bearer"
 * (RFC 7523) token request through Spring Authorization Server's authentication pipeline.
 *
 * Modeled after Spring Authorization Server's own OAuth2ClientCredentialsAuthenticationToken /
 * OAuth2AuthorizationCodeAuthenticationToken pattern: an "input" token created by the
 * {@code AuthenticationConverter} and passed to {@code AuthenticationManager.authenticate(...)},
 * which the matching {@code AuthenticationProvider} then turns into an
 * {@code OAuth2AccessTokenAuthenticationToken} (the "output").
 */
public class JwtBearerAuthenticationToken extends AbstractAuthenticationToken {

    private final Object clientPrincipal;
    private final String assertion;
    private final Set<String> scopes;

    public JwtBearerAuthenticationToken(Object clientPrincipal, String assertion, Set<String> scopes) {
        super(Collections.emptyList());
        this.clientPrincipal = clientPrincipal;
        this.assertion = assertion;
        this.scopes = scopes == null ? Collections.emptySet() : Set.copyOf(scopes);
        setAuthenticated(false);
    }

    @Override
    public Object getPrincipal() {
        return this.clientPrincipal;
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    public String getAssertion() {
        return this.assertion;
    }

    public Set<String> getScopes() {
        return this.scopes;
    }
}
