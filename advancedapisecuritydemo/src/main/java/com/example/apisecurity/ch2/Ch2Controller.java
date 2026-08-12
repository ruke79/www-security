package com.example.apisecurity.ch2;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Chapter 2 - Security by Design.
 *
 *  GET  /api/ch2/public          -> no auth (open API, see "Direct Authentication Pattern")
 *  POST /api/ch2/register        -> salted-hash password storage ("Managing Credentials")
 *  GET  /api/ch2/admin-resource  -> HTTP Basic auth + a XACML-style PDP decision
 *
 * All requests to /api/ch2/** additionally pass through the in-memory
 * rate-limiting filter (see common/RateLimitingFilter) to illustrate
 * "Availability" / DoS mitigation from the CIA triad.
 */
@RestController
@RequestMapping("/api/ch2")
public class Ch2Controller {

    private final UserAccountRepository userAccountRepository;
    private final PasswordEncoder passwordEncoder;
    private final PolicyDecisionPoint pdp;

    public Ch2Controller(UserAccountRepository userAccountRepository, PasswordEncoder passwordEncoder,
                          PolicyDecisionPoint pdp) {
        this.userAccountRepository = userAccountRepository;
        this.passwordEncoder = passwordEncoder;
        this.pdp = pdp;
    }

    public record RegisterRequest(
            @NotBlank String username,
            @NotBlank @Size(min = 8, message = "Chapter 2 'User Comfort': require a reasonable minimum " +
                    "instead of an unusable 20+ character policy that users would just write down") String password) {
    }

    @GetMapping("/public")
    public Map<String, Object> publicInfo() {
        return Map.of(
                "chapter", "Chapter 2 - Security by Design",
                "principles", List.of("Least Privilege", "Fail-Safe Defaults", "Defense in Depth",
                        "Psychological Acceptability", "Economy of Mechanism"),
                "hint", "Try GET /api/ch2/admin-resource with HTTP Basic auth: admin/admin123 or alice/alice123. " +
                        "Also try hammering /api/ch2/public more than the configured rate limit to see a 429."
        );
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@Valid @RequestBody RegisterRequest request) {
        if (userAccountRepository.exists(request.username())) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("error", "user_exists"));
        }
        // Salted hash storage per Chapter 2's "Managing Credentials" section:
        // BCrypt embeds a random salt into the encoded hash, so two identical
        // passwords never produce the same stored value - defeating rainbow
        // table attacks even if the user store is compromised.
        String hash = passwordEncoder.encode(request.password());
        userAccountRepository.save(new UserAccount(request.username(), hash, "USER"));
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                "username", request.username(),
                "storedHash", hash,
                "note", "Only the BCrypt hash is stored - the cleartext password is never persisted. " +
                        "You can now call GET /api/ch2/admin-resource with HTTP Basic auth using these credentials " +
                        "(it will be denied by the PDP, since new users get ROLE_USER, not ROLE_ADMIN)."
        ));
    }

    @GetMapping("/admin-resource")
    public Map<String, Object> adminResource(Authentication authentication) {
        List<String> authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        PolicyDecisionPoint.Decision decision = pdp.evaluate(authorities, "admin-resource", "read");
        if (decision != PolicyDecisionPoint.Decision.PERMIT) {
            throw new AccessDeniedException("PDP denied access to 'admin-resource' for " + authentication.getName());
        }
        return Map.of(
                "chapter", "Chapter 2 - Security by Design (Policy-Based Access Control)",
                "resource", "admin-resource",
                "grantedTo", authentication.getName(),
                "authorities", authorities,
                "pdpDecision", decision.name()
        );
    }
}
