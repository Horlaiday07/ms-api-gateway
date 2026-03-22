package com.remit.mellonsecure.gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import jakarta.annotation.PostConstruct;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Component
public class JwtAuthGlobalFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthGlobalFilter.class);
    private static final List<String> JWT_REQUIRED_PATHS = List.of("/api/payout/", "/api/admin/");

    @Value("${jwt.secret}")
    private String secret;

    private SecretKey signingKey;

    @PostConstruct
    public void init() {
        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        this.signingKey = Keys.hmacShaKeyFor(keyBytes);
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().value();

        if (!requiresJwt(path)) {
            return chain.filter(exchange);
        }

        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("Missing or invalid Authorization header for path={}, correlationId={}",
                    path, getCorrelationId(exchange));
            return unauthorized(exchange.getResponse());
        }

        String token = authHeader.substring(7);

        try {
            Claims claims = Jwts.parser()
                    .verifyWith(signingKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            String username = claims.getSubject();
            String merchantId = (String) claims.get("merchantId");
            String role = (String) claims.get("role");

            ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                    .header("X-Merchant-Id", merchantId != null ? merchantId : "")
                    .header("X-Username", username)
                    .header("X-Role", role != null ? role : "MERCHANT")
                    .build();

            return chain.filter(exchange.mutate().request(mutatedRequest).build());
        } catch (ExpiredJwtException e) {
            log.warn("JWT expired for path={}", path);
            return unauthorized(exchange.getResponse());
        } catch (Exception e) {
            log.warn("Invalid JWT for path={}: {}", path, e.getMessage());
            return unauthorized(exchange.getResponse());
        }
    }

    private boolean requiresJwt(String path) {
        return JWT_REQUIRED_PATHS.stream().anyMatch(path::startsWith);
    }

    private Mono<Void> unauthorized(ServerHttpResponse response) {
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        return response.setComplete();
    }

    private String getCorrelationId(ServerWebExchange exchange) {
        return exchange.getRequest().getHeaders().getFirst("X-Merchant-Id");
    }

    @Override
    public int getOrder() {
        return -100;
    }
}
