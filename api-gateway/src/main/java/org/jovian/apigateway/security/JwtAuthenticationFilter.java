package org.jovian.apigateway.security;

import lombok.RequiredArgsConstructor;
import org.jovian.apigateway.service.JwtService;
import org.jovian.apigateway.service.RedisTokenBlacklistService;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements GatewayFilter {

    private final JwtService jwtService;
    private final RedisTokenBlacklistService blacklistService;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        // 1️⃣ Extract JWT from Authorization header or cookie
        String token = jwtService.extractToken(exchange);

        if (token == null) {
            return jwtService.unauthorized(exchange, "Missing authentication token");
        }

        // 2️⃣ Check if token is blacklisted (user logged out)
        if (blacklistService.isBlacklisted(token)) {
            return jwtService.unauthorized(exchange, "Token is invalid (logged out)");
        }

        // 3️⃣ Validate JWT signature and expiration
        if (!jwtService.isTokenValid(token)) {
            return jwtService.unauthorized(exchange, "Invalid or expired token");
        }

        // 4️⃣ Extract user info from JWT claims
        String userId = jwtService.extractUserId(token);
        String email = jwtService.extractEmail(token);

        // 5️⃣ Forward identity info to downstream microservices via headers
        exchange.getRequest().mutate()
                .header("X-User-Id", userId)
                .header("X-User-Email", email)
                .build();

        // 6️⃣ Continue filter chain
        return chain.filter(exchange);
    }
}
