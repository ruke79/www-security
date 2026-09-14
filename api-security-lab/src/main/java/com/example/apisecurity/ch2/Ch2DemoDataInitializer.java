package com.example.apisecurity.ch2;

import jakarta.annotation.PostConstruct;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/** Seeds two demo accounts so every chapter can be tested immediately without registering first. */
@Component
public class Ch2DemoDataInitializer {

    private final UserAccountRepository repository;
    private final PasswordEncoder passwordEncoder;

    public Ch2DemoDataInitializer(UserAccountRepository repository, PasswordEncoder passwordEncoder) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
    }

    @PostConstruct
    public void seed() {
        repository.save(new UserAccount("admin", passwordEncoder.encode("admin123"), "ADMIN"));
        repository.save(new UserAccount("alice", passwordEncoder.encode("alice123"), "USER"));
    }
}
