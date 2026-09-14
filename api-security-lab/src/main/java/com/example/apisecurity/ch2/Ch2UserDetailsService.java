package com.example.apisecurity.ch2;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Backs both the Chapter 2 admin-resource demo and the Chapter 3 HTTP Basic
 * Authentication "Recipe API" demo, and the Authorization Server's own
 * interactive /login page used during the Authorization Code flow
 * (Chapter 7).
 */
@Service
public class Ch2UserDetailsService implements UserDetailsService {

    private final UserAccountRepository repository;

    public Ch2UserDetailsService(UserAccountRepository repository) {
        this.repository = repository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserAccount account = repository.findByUsername(username);
        if (account == null) {
            throw new UsernameNotFoundException("No such user: " + username);
        }
        return User.withUsername(account.getUsername())
                .password(account.getPasswordHash())
                .authorities(AuthorityUtils.createAuthorityList("ROLE_" + account.getRole()))
                .build();
    }
}
