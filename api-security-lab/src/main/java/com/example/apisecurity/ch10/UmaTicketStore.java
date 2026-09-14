package com.example.apisecurity.ch10;

import org.springframework.stereotype.Component;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Chapter 10 - User-Managed Access (UMA) 2.0.
 *
 * A minimal in-memory "permission ticket" store standing in for the real
 * UMA Authorization Server's ticket registration endpoint. A ticket is
 * issued whenever a request to a protected resource arrives without a valid
 * RPT (Requesting Party Token), and is later exchanged (once, before it
 * expires) for an RPT at {@code POST /api/ch10/uma/token}.
 */
@Component
public class UmaTicketStore {

    private static final long TICKET_TTL_SECONDS = 300;

    public record Ticket(String ticket, String resourceId, List<String> scopes, long expiresAtEpochSeconds) {
        boolean isExpired() {
            return System.currentTimeMillis() / 1000L > expiresAtEpochSeconds;
        }
    }

    private final ConcurrentHashMap<String, Ticket> tickets = new ConcurrentHashMap<>();

    public Ticket issueTicket(String resourceId, List<String> scopes) {
        String ticketValue = UUID.randomUUID().toString();
        Ticket ticket = new Ticket(
                ticketValue,
                resourceId,
                scopes,
                System.currentTimeMillis() / 1000L + TICKET_TTL_SECONDS);
        tickets.put(ticketValue, ticket);
        return ticket;
    }

    /**
     * Consumes (removes) a ticket if it exists and has not expired.
     * Returns null otherwise - callers should treat that as {@code invalid_grant}.
     */
    public Ticket consume(String ticketValue) {
        if (ticketValue == null) {
            return null;
        }
        Ticket ticket = tickets.remove(ticketValue);
        if (ticket == null || ticket.isExpired()) {
            return null;
        }
        return ticket;
    }
}
