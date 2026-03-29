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

/**
 * Validates headers required upstream by {@code PayoutSecurityFilter} on the payout service:
 * {@code X-Merchant-Id}, {@code X-API-KEY}, and when signing is used {@code X-SIGNATURE} + {@code X-TIMESTAMP}.
 * All of these are forwarded to the downstream service by Spring Cloud Gateway.
 */
@Component
public class XMerchantIdValidationFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(XMerchantIdValidationFilter.class);

    private static final String X_MERCHANT_ID = "X-Merchant-Id";
    private static final String X_API_KEY = "X-API-KEY";
    private static final String X_SIGNATURE = "X-SIGNATURE";
    private static final String X_TIMESTAMP = "X-TIMESTAMP";

    private static final List<String> REQUIRED_PATHS = List.of("/api/auth", "/api/payout", "/api/v1/payout", "/api/admin");
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
            return badRequest(exchange.getResponse(), "X-Merchant-Id header is required and must not be empty");
        }

        if (isPayoutPath(path)) {
            String apiKey = exchange.getRequest().getHeaders().getFirst(X_API_KEY);
            if (apiKey == null || apiKey.isBlank()) {
                log.warn("Missing or empty X-API-KEY for payout path={}", path);
                return badRequest(exchange.getResponse(), "X-API-KEY header is required for payout requests");
            }

            String signature = exchange.getRequest().getHeaders().getFirst(X_SIGNATURE);
            String timestamp = exchange.getRequest().getHeaders().getFirst(X_TIMESTAMP);
            boolean hasSig = signature != null && !signature.isBlank();
            boolean hasTs = timestamp != null && !timestamp.isBlank();
            if (hasSig != hasTs) {
                log.warn("X-SIGNATURE and X-TIMESTAMP must both be present for signed payout requests: path={}", path);
                return badRequest(exchange.getResponse(),
                        "X-SIGNATURE and X-TIMESTAMP must both be present when request signing is used");
            }
        }

        return chain.filter(exchange);
    }

    private static boolean isPayoutPath(String path) {
        return (path.equals("/api/payout") || path.startsWith("/api/payout/"))
                || (path.equals("/api/v1/payout") || path.startsWith("/api/v1/payout/"));
    }

    private Mono<Void> badRequest(ServerHttpResponse response, String message) {
        response.setStatusCode(HttpStatus.BAD_REQUEST);
        response.getHeaders().add("X-Error", message);
        return response.setComplete();
    }

    @Override
    public int getOrder() {
        return -85;
    }
}
