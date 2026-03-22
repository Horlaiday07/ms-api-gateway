package com.remit.mellonsecure.gateway.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
public class XMerchantIdValidationFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(XMerchantIdValidationFilter.class);
    private static final String X_MERCHANT_ID = "X-Merchant-Id";
    private static final List<String> REQUIRED_PATHS = List.of("/api/auth", "/api/payout", "/api/admin");
    private static final List<String> EXEMPT_PATHS = List.of("/api/ipn");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().value();

        if (EXEMPT_PATHS.stream().anyMatch(p -> path.equals(p) || path.startsWith(p + "/"))) {
            return chain.filter(exchange);
        }

        if (!REQUIRED_PATHS.stream().anyMatch(p -> path.equals(p) || path.startsWith(p + "/"))) {
            return chain.filter(exchange);
        }

        String merchantId = exchange.getRequest().getHeaders().getFirst(X_MERCHANT_ID);
        if (merchantId == null || merchantId.isBlank()) {
            log.warn("Missing or empty X-Merchant-Id header for path={}", path);
            return badRequest(exchange.getResponse());
        }

        return chain.filter(exchange);
    }

    private Mono<Void> badRequest(ServerHttpResponse response) {
        response.setStatusCode(HttpStatus.BAD_REQUEST);
        response.getHeaders().add("X-Error", "X-Merchant-Id header is required and must not be empty");
        return response.setComplete();
    }

    @Override
    public int getOrder() {
        return -85;
    }
}
