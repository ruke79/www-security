package com.example.apisecurity.config;

import com.example.apisecurity.ch2.Ch2UserDetailsService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.webauthn.management.MapPublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.MapUserCredentialRepository;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;

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
 * This chain also owns the interactive, browser-facing login, so it is the
 * natural home for the <b>WebAuthn / passkey</b> demo (see {@code .webAuthn(..)}
 * below). WebAuthn augments the very same auto-generated {@code /login} page
 * with a "Sign in with a passkey" button and enables a passkey registration
 * page at {@code GET /webauthn/register}. The typical demo flow is:
 * <ol>
 *   <li>log in once with a password (e.g. {@code alice}/{@code alice123}),</li>
 *   <li>visit {@code /webauthn/register} and register a passkey (platform
 *       authenticator / Touch ID / Windows Hello / a security key),</li>
 *   <li>log out, then sign back in with the passkey alone - no password.</li>
 * </ol>
 * Browsers only expose the WebAuthn API in a "secure context", which includes
 * {@code http://localhost}, so the demo works over plain HTTP on localhost
 * without a TLS cert. The relying-party id ({@code rpId}) is the host only
 * ("localhost"), and the allowed origin is the full issuer URL (scheme + host +
 * port), kept in sync with {@code app.issuer-uri} so it still matches when the
 * port is overridden via {@code APP_PORT}.
 *
 * Explicitly wired to {@link Ch2UserDetailsService} (rather than left
 * ambiguous) so Spring doesn't fail to start due to multiple
 * UserDetailsService beans being present in the application context.
 */
@Configuration
public class DefaultCatchAllSecurityConfig {

    /**
     * In-memory store mapping an authenticated username to its stable WebAuthn
     * user handle (a random, opaque per-user id that the passkey is bound to -
     * deliberately NOT the username, so the username can change without
     * orphaning credentials). Demo-only: a real deployment persists this.
     */
    @Bean
    public PublicKeyCredentialUserEntityRepository publicKeyCredentialUserEntityRepository() {
        return new MapPublicKeyCredentialUserEntityRepository();
    }

    /**
     * In-memory store of the registered passkeys themselves - each holds the
     * PUBLIC key plus a monotonic signature counter (used to detect cloned
     * authenticators). The private key never leaves the user's device, so it is
     * never stored here. Demo-only; persist this in production.
     */
    @Bean
    public UserCredentialRepository userCredentialRepository() {
        return new MapUserCredentialRepository();
    }

    @Bean
    @Order(100)
    public SecurityFilterChain catchAllFilterChain(
            HttpSecurity http,
            Ch2UserDetailsService ch2UserDetailsService,
            @Value("${app.issuer-uri}") String issuer,
            @Value("${app.webauthn.rp-id:localhost}") String rpId,
            @Value("${app.webauthn.rp-name:API Security Lab}") String rpName) throws Exception {

        // The WebAuthn configurer resolves a UserDetailsService via
        // getSharedOrBean(..): it checks HttpSecurity's shared object first and
        // only then a bean. http.userDetailsService(..) wires the
        // AuthenticationManager (for form login) but does NOT register that
        // shared object, and this app intentionally has more than one
        // UserDetailsService bean (e.g. the mTLS one), so a bean lookup is
        // ambiguous and fails with "Missing UserDetailsService Bean". Register
        // the ch2 store as the shared object so WebAuthn (and form login) both
        // resolve the correct, real-user store.
        http.setSharedObject(org.springframework.security.core.userdetails.UserDetailsService.class,
                ch2UserDetailsService);

        http.userDetailsService(ch2UserDetailsService)
                // CSRF is disabled for the stateless JSON POST demo endpoints
                // (ch6 OAuth 1.0 signatures, ch9b chain/dynamic-registration,
                // ch10 UMA, ch12 OIDC, ch13 JWS/JWE, the labs, ...) - all under
                // /api/**. Like every other chain in this project they are
                // token/credential-in-body REST calls, not browser form posts,
                // so the default CSRF protection would only reject them with 403.
                //
                // CSRF stays ENABLED for the browser-facing paths this chain also
                // serves (/login, /logout, /webauthn/**): the WebAuthn passkey
                // login/registration JavaScript that Spring injects into the
                // generated /login page reads the CsrfToken to send it as a
                // header, and with CSRF fully disabled that token is null and the
                // login page itself fails to render (NPE in
                // DefaultLoginPageGeneratingFilter). Exempting only /api/** keeps
                // both worlds working.
                .csrf(csrf -> csrf.ignoringRequestMatchers("/api/**"))
                .authorizeHttpRequests(auth -> auth
                        // Registering a passkey must be done as an already
                        // authenticated user (the passkey is tied to that
                        // identity). Everything else - including the passkey
                        // *login* endpoints (/login/webauthn,
                        // /webauthn/authenticate/options) - stays open, since
                        // signing in with a passkey happens while anonymous.
                        .requestMatchers("/webauthn/register", "/webauthn/register/**").authenticated()
                        .anyRequest().permitAll())
                .formLogin(Customizer.withDefaults())
                .logout(Customizer.withDefaults())
                // Chapter 4 companion (modern, phishing-resistant login):
                // WebAuthn / FIDO2 passkeys. Public-key auth bound to the site's
                // origin, so a stolen credential or a lookalike phishing domain
                // cannot replay it.
                .webAuthn(webAuthn -> webAuthn
                        .rpName(rpName)
                        .rpId(rpId)
                        .allowedOrigins(issuer));

        return http.build();
    }
}
