package com.koriebruh.authservice.filter;

import org.slf4j.MDC;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.UUID;

/**
 * Reactive WebFilter that manages Correlation IDs for every incoming request.
 *
 * <p>Compatible with Spring WebFlux (non-blocking/reactive stack).
 * Uses {@link WebFilter} instead of {@code jakarta.servlet.Filter},
 * which is only available in the traditional servlet-based MVC stack.
 *
 * <p>If the client or API gateway sends an {@code X-Correlation-ID} header,
 * it is reused; otherwise a new UUID is generated.
 *
 * <p>Note: MDC is thread-local and does NOT work natively with reactive streams.
 * We propagate the correlation ID via the response header and Reactor context instead.
 * For full MDC support in logs, use the {@code reactor.util.context.Context} approach
 * or integrate with Micrometer Tracing (recommended for production).
 */
@Component
@Order(1)
public class CorrelationIdFilter implements WebFilter {

    /** Header name used to pass the Correlation ID between services. */
    public static final String CORRELATION_ID_HEADER = "X-Correlation-ID";

    /** MDC key — used for contextual logging where applicable. */
    public static final String CORRELATION_ID_MDC_KEY = "correlationId";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        // Reuse existing ID from upstream (gateway/client), or generate a new one
        String correlationId = exchange.getRequest().getHeaders().getFirst(CORRELATION_ID_HEADER);
        if (correlationId == null || correlationId.isBlank()) {
            correlationId = UUID.randomUUID().toString();
        }

        final String finalCorrelationId = correlationId;

        // Echo the ID back in the response header so clients can reference it for support
        exchange.getResponse().getHeaders().set(CORRELATION_ID_HEADER, finalCorrelationId);

        // NOTE: MDC is thread-local and unreliable in reactive pipelines.
        // We store the correlation ID in Reactor Context for proper propagation.
        return chain.filter(exchange)
                .contextWrite(ctx -> ctx.put(CORRELATION_ID_MDC_KEY, finalCorrelationId))
                .doOnEach(signal -> {
                    // Attach to MDC only when a signal is emitted (best-effort for logging)
                    if (signal.getContextView().hasKey(CORRELATION_ID_MDC_KEY)) {
                        MDC.put(CORRELATION_ID_MDC_KEY, signal.getContextView().get(CORRELATION_ID_MDC_KEY));
                    }
                })
                .doFinally(signal -> MDC.clear()); // Always clear MDC after request completes
    }
}