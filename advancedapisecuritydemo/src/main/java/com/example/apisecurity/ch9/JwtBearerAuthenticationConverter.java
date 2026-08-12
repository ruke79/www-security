package com.example.apisecurity.ch9;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Chapter 9 (OAuth 2.0 Profiles) / Chapter 11 (Federation) - recognizes
 * {@code grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer} (RFC 7523,
 * "JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
 * Authorization Grants") at the /oauth2/token endpoint.
 *
 * Registered additively via
 * {@code tokenEndpoint.accessTokenRequestConverter(new JwtBearerAuthenticationConverter())}
 * - Spring Authorization Server tries every registered converter in turn and
 * uses the first one that returns non-null, so the standard
 * authorization_code / client_credentials / refresh_token grants keep
 * working unmodified alongside this one.
 */
public class JwtBearerAuthenticationConverter implements AuthenticationConverter {

    public static final String GRANT_TYPE_VALUE = "urn:ietf:params:oauth:grant-type:jwt-bearer";

    public static final AuthorizationGrantType JWT_BEARER_GRANT_TYPE =
            new AuthorizationGrantType(GRANT_TYPE_VALUE);

    @Override
    public Authentication convert(HttpServletRequest request) {
        String grantType = request.getParameter("grant_type");
        if (!GRANT_TYPE_VALUE.equals(grantType)) {
            // Not our grant type - return null so SAS tries the next converter.
            return null;
        }

        MultiValueMap<String, String> parameters = getParameters(request);

        String assertion = parameters.getFirst("assertion");
        if (!StringUtils.hasText(assertion)) {
            return null;
        }

        String scopeParam = parameters.getFirst("scope");
        Set<String> scopes = Collections.emptySet();
        if (StringUtils.hasText(scopeParam)) {
            scopes = new LinkedHashSet<>(List.of(StringUtils.delimitedListToStringArray(scopeParam, " ")));
        }

        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        return new JwtBearerAuthenticationToken(clientPrincipal, assertion, scopes);
    }

    private static MultiValueMap<String, String> getParameters(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        LinkedMultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameterMap.forEach((key, values) -> {
            for (String value : values) {
                parameters.add(key, value);
            }
        });
        return parameters;
    }
}
