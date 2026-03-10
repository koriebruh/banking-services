package com.koriebruh.accountservice.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.koriebruh.accountservice.dto.ApiResponse;
import com.koriebruh.accountservice.dto.ApiResponseFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * Strict CorrelationIdFilter for Microservices.
 * Rejects requests that do not contain the mandatory X-Correlation-ID header.
 *
 * <p><b>Flow:</b>
 * <ol>
 *   <li>Extract X-Correlation-ID from request header.</li>
 *   <li>If absent or blank → respond 400 with structured {@link ApiResponse} error body.</li>
 *   <li>If present → echo to response header, propagate to Reactor Context, and clear MDC on finish.</li>
 * </ol>
 *
 * <p><b>Security:</b>
 * Enforces that all inbound requests carry a correlation ID, preventing silent failures
 * in distributed tracing. Missing headers likely indicate a misconfigured upstream caller.
 */
@Slf4j
@Component
@Order(1)
@RequiredArgsConstructor
public class CorrelationIdFilter implements WebFilter {

    public static final String CORRELATION_ID_HEADER  = "X-Correlation-ID";
    public static final String CORRELATION_ID_MDC_KEY = "correlationId";

    private final ApiResponseFactory apiResponseFactory;
    private final ObjectMapper objectMapper;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String correlationId = exchange.getRequest().getHeaders().getFirst(CORRELATION_ID_HEADER);

        if (correlationId == null || correlationId.isBlank()) {
            log.warn("[CorrelationIdFilter] Rejected request — missing {} header. path={}",
                    CORRELATION_ID_HEADER,
                    exchange.getRequest().getPath());
            return writeErrorResponse(exchange);
        }

        // Echo correlation ID back to response headers (useful for debugging)
        exchange.getResponse().getHeaders().set(CORRELATION_ID_HEADER, correlationId);

        // Propagate to Reactor Context and sync to MDC per signal
        return chain.filter(exchange)
                .contextWrite(ctx -> ctx.put(CORRELATION_ID_MDC_KEY, correlationId))
                .doOnEach(signal -> {
                    if (signal.getContextView().hasKey(CORRELATION_ID_MDC_KEY)) {
                        MDC.put(CORRELATION_ID_MDC_KEY, signal.getContextView().get(CORRELATION_ID_MDC_KEY));
                    }
                })
                .doFinally(signalType -> MDC.clear());
    }

    /**
     * Writes a structured 400 Bad Request JSON response using {@link ApiResponseFactory}.
     * Correlation ID is omitted (null) since the header was not provided by the caller.
     */
    private Mono<Void> writeErrorResponse(ServerWebExchange exchange) {
        try {
            ApiResponse<Void> body = apiResponseFactory.error(
                    "Missing required header: " + CORRELATION_ID_HEADER,
                    null // correlationId intentionally null — caller did not provide it
            );

            byte[] bytes = objectMapper.writeValueAsBytes(body);
            DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);

            exchange.getResponse().setStatusCode(HttpStatus.BAD_REQUEST);
            exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

            return exchange.getResponse().writeWith(Mono.just(buffer));
        } catch (Exception e) {
            log.error("[CorrelationIdFilter] Failed to serialize error response", e);
            exchange.getResponse().setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
            return exchange.getResponse().setComplete();
        }
    }
}