package com.remit.mellonsecure.gateway.handler;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.server.RequestPredicates;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

import java.util.Map;

@Configuration
public class FallbackHandler {

    @Bean
    public RouterFunction<ServerResponse> fallbackRoute() {
        return RouterFunctions.route(
                RequestPredicates.path("/fallback"),
                request -> ServerResponse
                        .status(HttpStatus.SERVICE_UNAVAILABLE)
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue(Map.of(
                                "status", "error",
                                "message", "Service temporarily unavailable. Please try again later."
                        ))
        );
    }
}
