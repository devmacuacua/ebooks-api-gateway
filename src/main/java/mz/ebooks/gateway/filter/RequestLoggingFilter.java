package mz.ebooks.gateway.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Global filter that logs every request with method, path, response status and duration.
 *
 * <p>Log format (INFO level):
 * <pre>
 *   [GATEWAY] GET /api/catalog/books → 200 OK (42 ms)
 * </pre>
 *
 * <p>The filter runs at the lowest possible precedence so that it wraps all other filters,
 * giving an accurate end-to-end duration measurement from gateway receipt to response flush.
 */
@Slf4j
@Component
public class RequestLoggingFilter implements GlobalFilter, Ordered {

    @Override
    public int getOrder() {
        // Highest precedence number = outermost wrapper = measures the full pipeline
        return Ordered.LOWEST_PRECEDENCE;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String method = request.getMethod() != null ? request.getMethod().name() : "UNKNOWN";
        String path = request.getPath().value();
        String query = request.getURI().getRawQuery();
        String fullPath = query != null && !query.isBlank() ? path + "?" + query : path;

        long startTime = System.currentTimeMillis();

        return chain.filter(exchange)
                .doFinally(signalType -> {
                    long duration = System.currentTimeMillis() - startTime;
                    ServerHttpResponse response = exchange.getResponse();
                    int statusCode = response.getStatusCode() != null
                            ? response.getStatusCode().value()
                            : 0;

                    if (statusCode >= 500) {
                        log.error("[GATEWAY] {} {} → {} ({} ms)", method, fullPath, statusCode, duration);
                    } else if (statusCode >= 400) {
                        log.warn("[GATEWAY] {} {} → {} ({} ms)", method, fullPath, statusCode, duration);
                    } else {
                        log.info("[GATEWAY] {} {} → {} ({} ms)", method, fullPath, statusCode, duration);
                    }
                });
    }
}
