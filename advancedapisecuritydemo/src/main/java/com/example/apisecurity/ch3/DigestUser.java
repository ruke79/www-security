package com.example.apisecurity.ch3;

public class DigestUser {

    private final String username;
    private final String ha1; // MD5(username:realm:password)
    private final String role;

    public DigestUser(String username, String ha1, String role) {
        this.username = username;
        this.ha1 = ha1;
        this.role = role;
    }

    public String getUsername() {
        return username;
    }

    public String getHa1() {
        return ha1;
    }

    public String getRole() {
        return role;
    }
}
