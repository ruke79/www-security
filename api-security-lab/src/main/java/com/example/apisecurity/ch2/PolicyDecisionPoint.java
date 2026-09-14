package com.example.apisecurity.ch2;

import org.springframework.stereotype.Component;

import java.util.List;

/**
 * A deliberately-simplified stand-in for a XACML Policy Decision Point (PDP).
 * See Chapter 2, "Policy-Based Access Control Pattern" (Figures 2-4 and 2-9):
 * a Policy Enforcement Point (PEP, here: the controller) builds a
 * <subject, resource, action> request and asks a PDP for a decision.
 *
 * A real PDP evaluates the request against externally-managed XACML policies
 * (loaded from a Policy Store, possibly consulting a Policy Information
 * Point for missing attributes). Here we keep a tiny in-memory policy list
 * to demonstrate the same PEP -> PDP interaction without pulling in a full
 * XACML engine.
 */
@Component
public class PolicyDecisionPoint {

    public enum Decision { PERMIT, DENY }

    public record Policy(String requiredAuthority, String resource, String action, Decision effect) {
    }

    private final List<Policy> policies = List.of(
            new Policy("ROLE_ADMIN", "admin-resource", "read", Decision.PERMIT),
            new Policy("ROLE_ADMIN", "admin-resource", "write", Decision.PERMIT),
            new Policy("ROLE_USER", "admin-resource", "read", Decision.DENY),
            new Policy("ROLE_USER", "public-resource", "read", Decision.PERMIT)
    );

    /**
     * Evaluates a request the way a XACML PDP would: walk the policy set and
     * return the first explicit match. The default is DENY - Chapter 2's
     * "Fail-Safe Defaults" design principle ("access should be denied unless
     * explicitly permitted").
     */
    public Decision evaluate(List<String> subjectAuthorities, String resource, String action) {
        for (Policy policy : policies) {
            if (subjectAuthorities.contains(policy.requiredAuthority())
                    && policy.resource().equals(resource)
                    && policy.action().equals(action)) {
                return policy.effect();
            }
        }
        return Decision.DENY;
    }
}
