package com.example.apisecurity.ch2;

/** A minimal user record shared by Chapter 2 (registration demo) and Chapter 3 (Basic Auth). */
public class UserAccount {

    private final String username;
    private final String passwordHash;
    private final String role;

    public UserAccount(String username, String passwordHash, String role) {
        this.username = username;
        this.passwordHash = passwordHash;
        this.role = role;
    }

    public String getUsername() {
        return username;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public String getRole() {
        return role;
    }
}
