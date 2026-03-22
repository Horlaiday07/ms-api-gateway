package com.remit.mellonsecure.gateway.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class RoleAuthGlobalFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(RoleAuthGlobalFilter.class);

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().value();

        if (path.startsWith("/api/admin/")) {
            String role = exchange.getRequest().getHeaders().getFirst("X-Role");
            if (!"ADMIN".equals(role)) {
                log.warn("Access denied: role={} for path={}, requires ADMIN", role, path);
                return forbidden(exchange.getResponse());
            }
        }

        if (path.startsWith("/api/payout/")) {
            String role = exchange.getRequest().getHeaders().getFirst("X-Role");
            if (role == null || (!"ADMIN".equals(role) && !"MERCHANT".equals(role))) {
                log.warn("Access denied: role={} for path={}, requires ADMIN or MERCHANT", role, path);
                return forbidden(exchange.getResponse());
            }
        }

        return chain.filter(exchange);
    }

    private Mono<Void> forbidden(ServerHttpResponse response) {
        response.setStatusCode(HttpStatus.FORBIDDEN);
        return response.setComplete();
    }

    @Override
    public int getOrder() {
        return -90;
    }
}
