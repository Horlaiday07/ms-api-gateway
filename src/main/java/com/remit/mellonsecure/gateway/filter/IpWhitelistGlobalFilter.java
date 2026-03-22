package com.remit.mellonsecure.gateway.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
@ConfigurationProperties(prefix = "ip")
public class IpWhitelistGlobalFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(IpWhitelistGlobalFilter.class);

    private List<String> whitelist = List.of("127.0.0.1", "::1");

    public void setWhitelist(List<String> whitelist) {
        this.whitelist = whitelist != null ? whitelist : List.of("127.0.0.1", "::1");
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().value();

        if (!path.startsWith("/api/ipn/")) {
            return chain.filter(exchange);
        }

        String clientIp = extractClientIp(exchange.getRequest());

        if (whitelist.contains(clientIp)) {
            log.debug("IP allowed: {} for path={}", clientIp, path);
            return chain.filter(exchange);
        }

        log.warn("IP blocked: {} for path={}, whitelist={}", clientIp, path, whitelist);
        return forbidden(exchange.getResponse());
    }

    private String extractClientIp(ServerHttpRequest request) {
        HttpHeaders headers = request.getHeaders();
        String xForwardedFor = headers.getFirst("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        if (request.getRemoteAddress() != null) {
            return request.getRemoteAddress().getAddress().getHostAddress();
        }
        return "unknown";
    }

    private Mono<Void> forbidden(ServerHttpResponse response) {
        response.setStatusCode(HttpStatus.FORBIDDEN);
        return response.setComplete();
    }

    @Override
    public int getOrder() {
        return -95;
    }
}
