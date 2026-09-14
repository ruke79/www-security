package com.example.apisecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Companion code for "Advanced API Security: Securing APIs with OAuth 2.0,
 * OpenID Connect, JWS, and JWE".
 *
 * Every chapter of the book is wired up as an independently testable set of
 * endpoints in this single Spring Boot application:
 *
 *  Ch.2  Security by Design        -> /api/ch2/**
 *  Ch.3  HTTP Basic/Digest Auth     -> /api/ch3/basic/**, /api/ch3/digest/**
 *  Ch.4  Mutual Authentication TLS  -> /api/ch4/**  (port 8443, client cert required)
 *  Ch.5  Identity Delegation        -> /api/ch5/**
 *  Ch.7  OAuth 2.0 (core)           -> /oauth2/**, /api/ch7/**
 *  Ch.8  Sender-constrained tokens  -> /api/ch8/**  (modern replacement for the
 *                                      deprecated OAuth 2.0 MAC Token Profile,
 *                                      implemented here as RFC 9449-style DPoP)
 *  Ch.9  OAuth 2.0 Profiles         -> /oauth2/introspect, /oauth2/revoke, /api/ch9/**
 *  Ch.10 User-Managed Access (UMA)  -> /api/ch10/**
 *  Ch.11 Federation                -> /api/ch11/**
 *
 * See README.md in the project root for a full curl-based walkthrough of
 * every chapter.
 */
@SpringBootApplication
public class ApiSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(ApiSecurityApplication.class, args);
    }
}
