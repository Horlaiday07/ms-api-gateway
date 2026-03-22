package com.remit.mellonsecure.gateway.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Component
public class RequestLoggingGlobalFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(RequestLoggingGlobalFilter.class);
    private static final String CORRELATION_ID_HEADER = "X-Correlation-Id";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getPath().value();
        String method = request.getMethod().name();
        String id = request.getHeaders().getFirst(CORRELATION_ID_HEADER);
        final String correlationId = id != null ? id : UUID.randomUUID().toString();
        String merchantId = request.getHeaders().getFirst("X-Merchant-Id");

        log.info("Incoming request: method={}, path={}, correlationId={}, merchantId={}",
                method, path, correlationId, mask(merchantId));

        ServerHttpRequest mutatedRequest = request.mutate()
                .header(CORRELATION_ID_HEADER, correlationId)
                .build();

        return chain.filter(exchange.mutate().request(mutatedRequest).build())
                .doOnSuccess(v -> log.info("Request completed: path={}, correlationId={}", path, correlationId))
                .doOnError(t -> log.error("Request failed: path={}, correlationId={}, error={}",
                        path, correlationId, t.getMessage()));
    }

    private String mask(String value) {
        if (value == null || value.isEmpty()) return "-";
        if (value.length() <= 4) return "****";
        return value.substring(0, 2) + "***";
    }

    @Override
    public int getOrder() {
        return -200;
    }
}
