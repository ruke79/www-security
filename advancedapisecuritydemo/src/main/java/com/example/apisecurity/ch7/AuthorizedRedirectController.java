package com.example.apisecurity.ch7;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Chapter 7 - a stand-in "redirect_uri" for demo-authcode-client
 * (registered as http://127.0.0.1:18080/authorized), so the Authorization
 * Code + PKCE flow can be exercised entirely with curl, without a real
 * browser-based OAuth client.
 *
 * After visiting the /oauth2/authorize URL in a browser (needed once, to
 * log in and grant consent), the Authorization Server redirects here with
 * ?code=... - this endpoint just echoes it back along with the exact curl
 * command to exchange it at /oauth2/token.
 *
 * Public/unauthenticated - lives under the Chapter 100 catch-all chain.
 */
@RestController
public class AuthorizedRedirectController {

    @GetMapping("/authorized")
    public Map<String, Object> authorized(
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String state,
            @RequestParam(required = false) String error,
            @RequestParam(name = "error_description", required = false) String errorDescription) {

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("chapter", "Chapter 7 - OAuth 2.0 core (Authorization Code + PKCE redirect echo)");

        if (error != null) {
            body.put("error", error);
            body.put("error_description", errorDescription);
            return body;
        }

        body.put("code", code);
        body.put("state", state);
        body.put("howToExchange",
                "curl -u demo-authcode-client: -X POST http://localhost:18080/oauth2/token " +
                        "-d grant_type=authorization_code " +
                        "-d code=" + code + " " +
                        "-d redirect_uri=http://127.0.0.1:18080/authorized " +
                        "-d code_verifier=<the code_verifier you used to derive the code_challenge>");
        return body;
    }
}
