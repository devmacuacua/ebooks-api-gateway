package mz.ebooks.gateway.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Map;

/**
 * Circuit-breaker fallback endpoints.
 *
 * <p>Spring Cloud Gateway routes that have a CircuitBreaker filter configured forward
 * to these endpoints when the downstream service is unavailable or the circuit is open.
 * Every handler returns HTTP 503 with a JSON payload that includes a machine-readable
 * {@code service} field so clients can handle each service's downtime independently.
 */
@Slf4j
@RestController
@RequestMapping("/fallback")
public class FallbackController {

    // -------------------------------------------------------------------------
    // Auth Service
    // -------------------------------------------------------------------------

    @GetMapping("/auth")
    public Mono<ResponseEntity<Map<String, Object>>> authFallback() {
        log.warn("Circuit breaker open — auth-service unavailable");
        return Mono.just(buildResponse("auth-service",
                "Serviço de autenticação temporariamente indisponível"));
    }

    // -------------------------------------------------------------------------
    // Catalog Service
    // -------------------------------------------------------------------------

    @GetMapping("/catalog")
    public Mono<ResponseEntity<Map<String, Object>>> catalogFallback() {
        log.warn("Circuit breaker open — catalog-service unavailable");
        return Mono.just(buildResponse("catalog-service",
                "Catálogo temporariamente indisponível"));
    }

    // -------------------------------------------------------------------------
    // Commerce Service
    // -------------------------------------------------------------------------

    @GetMapping("/commerce")
    public Mono<ResponseEntity<Map<String, Object>>> commerceFallback() {
        log.warn("Circuit breaker open — commerce-service unavailable");
        return Mono.just(buildResponse("commerce-service",
                "Serviço de encomendas temporariamente indisponível"));
    }

    // -------------------------------------------------------------------------
    // Reading / DRM Service
    // -------------------------------------------------------------------------

    @GetMapping("/reading")
    public Mono<ResponseEntity<Map<String, Object>>> readingFallback() {
        log.warn("Circuit breaker open — reading-service unavailable");
        return Mono.just(buildResponse("reading-service",
                "Leitor temporariamente indisponível"));
    }

    // -------------------------------------------------------------------------
    // Helper
    // -------------------------------------------------------------------------

    private ResponseEntity<Map<String, Object>> buildResponse(String service, String message) {
        Map<String, Object> body = Map.of(
                "status", HttpStatus.SERVICE_UNAVAILABLE.value(),
                "error", "Service Unavailable",
                "service", service,
                "message", message,
                "timestamp", Instant.now().toString()
        );
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(body);
    }
}
