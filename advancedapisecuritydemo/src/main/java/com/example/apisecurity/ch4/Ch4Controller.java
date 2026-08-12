package com.example.apisecurity.ch4;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.cert.X509Certificate;
import java.util.Map;

/**
 * Chapter 4 - Mutual Authentication with TLS.
 *
 * Reachable only through the dedicated mTLS connector (default port 8443,
 * see application.yml "app.mtls" and config/MtlsSecurityConfig). A plain
 * HTTP request to port 8080 will never carry a client certificate, so
 * Spring Security's x509() filter will reject it with 401 before this
 * controller is even invoked.
 */
@RestController
@RequestMapping("/api/ch4")
public class Ch4Controller {

    @GetMapping("/whoami")
    public Map<String, Object> whoAmI(Authentication authentication, HttpServletRequest request) {
        X509Certificate[] certs =
                (X509Certificate[]) request.getAttribute("jakarta.servlet.request.X509Certificate");
        String subjectDn = (certs != null && certs.length > 0)
                ? certs[0].getSubjectX500Principal().getName()
                : "unknown";

        return Map.of(
                "chapter", "Chapter 4 - Mutual Authentication with TLS",
                "authenticatedAs", authentication.getName(),
                "certificateSubjectDN", subjectDn,
                "note", "This request was authenticated purely via your TLS client certificate - " +
                        "no username/password or bearer token was involved."
        );
    }
}
