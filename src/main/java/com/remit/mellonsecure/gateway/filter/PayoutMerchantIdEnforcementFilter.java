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

/**
 * Last-line-of-defense filter that runs right before proxying to downstream.
 * Ensures X-Merchant-Id is present for /api/payout and /api/admin paths.
 * Runs after JwtAuth (which adds the header) and XMerchantIdValidation.
 */
@Component
public class PayoutMerchantIdEnforcementFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(PayoutMerchantIdEnforcementFilter.class);
    private static final String X_MERCHANT_ID = "X-Merchant-Id";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().value();

        if (!isPayoutOrAdminPath(path)) {
            return chain.filter(exchange);
        }

        String merchantId = exchange.getRequest().getHeaders().getFirst(X_MERCHANT_ID);
        if (merchantId == null || merchantId.isBlank()) {
            log.warn("Blocking request: X-Merchant-Id missing before proxy for path={}", path);
            return badRequest(exchange.getResponse());
        }

        log.debug("X-Merchant-Id validated before proxy: path={}", path);
        return chain.filter(exchange);
    }

    private boolean isPayoutOrAdminPath(String path) {
        return path.equals("/api/payout") || path.startsWith("/api/payout/")
                || path.equals("/api/v1/payout") || path.startsWith("/api/v1/payout/")
                || path.equals("/api/admin") || path.startsWith("/api/admin/");
    }

    private Mono<Void> badRequest(ServerHttpResponse response) {
        response.setStatusCode(HttpStatus.BAD_REQUEST);
        response.getHeaders().add("X-Error", "X-Merchant-Id header is required and must not be empty");
        return response.setComplete();
    }

    @Override
    public int getOrder() {
        return 10_000; // After all security filters (-200 to -85), before NettyRoutingFilter
    }
}
