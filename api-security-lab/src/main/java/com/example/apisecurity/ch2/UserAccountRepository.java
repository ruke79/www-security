package com.example.apisecurity.ch2;

import org.springframework.stereotype.Repository;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Repository
public class UserAccountRepository {

    private final Map<String, UserAccount> users = new ConcurrentHashMap<>();

    public UserAccount save(UserAccount account) {
        users.put(account.getUsername(), account);
        return account;
    }

    public UserAccount findByUsername(String username) {
        return users.get(username);
    }

    public boolean exists(String username) {
        return users.containsKey(username);
    }
}
