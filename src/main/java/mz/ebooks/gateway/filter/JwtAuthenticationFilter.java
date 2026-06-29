package mz.ebooks.gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;

/**
 * Global JWT authentication filter.
 *
 * <p>Validates Bearer tokens on all routes except explicitly whitelisted public endpoints.
 * On success it forwards {@code X-User-Id} and {@code X-User-Role} headers downstream so
 * individual services don't need to re-validate the token.
 * On failure it short-circuits with HTTP 401 before the request ever reaches a downstream service.
 *
 * <p>Token blacklist is stored in Redis under the key {@code blacklist:{token}}.
 */
@Slf4j
@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    /** Exact paths that never require a token, regardless of HTTP method. */
    private static final Set<String> OPEN_PATHS = Set.of(
            "/api/auth/login",
            "/api/auth/register",
            "/api/auth/verify-email",
            "/api/auth/forgot-password",
            "/api/auth/reset-password",
            "/api/auth/google",
            "/api/auth/facebook",
            // Payment callbacks arrive from external providers without a JWT
            "/api/commerce/payments/webhooks/stripe",
            "/api/commerce/payments/callbacks/mpesa",
            "/api/commerce/payments/callbacks/emola"
    );

    /** Path prefixes that are open for any HTTP method (payment redirects). */
    private static final List<String> ANY_METHOD_OPEN_PREFIXES = List.of(
            "/api/commerce/payments/capture/paypal"
    );

    /** Paths that are public only for GET requests. */
    private static final List<String> GET_ONLY_OPEN_PREFIXES = List.of(
            "/api/catalog/books",
            "/api/media",
            "/api/partner/widget/"
    );

    private final ReactiveStringRedisTemplate redisTemplate;
    private final SecretKey signingKey;

    public JwtAuthenticationFilter(
            ReactiveStringRedisTemplate redisTemplate,
            @Value("${app.jwt.secret}") String jwtSecret) {

        this.redisTemplate = redisTemplate;
        // JJWT 0.12.x expects at least 256 bits (32 bytes) for HMAC-SHA256
        byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        this.signingKey = Keys.hmacShaKeyFor(keyBytes);
    }

    @Override
    public int getOrder() {
        // Run before rate-limiter and routing filters
        return -100;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getPath().value();
        HttpMethod method = request.getMethod();

        if (isPublicEndpoint(path, method)) {
            return chain.filter(exchange);
        }

        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("Missing or malformed Authorization header for path: {}", path);
            return unauthorized(exchange, "Token de autenticação ausente ou inválido");
        }

        String token = authHeader.substring(7);

        // First check blacklist in Redis, then validate signature
        String blacklistKey = "blacklist:" + token;
        return redisTemplate.hasKey(blacklistKey)
                .flatMap(blacklisted -> {
                    if (Boolean.TRUE.equals(blacklisted)) {
                        log.warn("Attempt to use blacklisted token for path: {}", path);
                        return unauthorized(exchange, "Token revogado. Faça login novamente.");
                    }
                    return validateAndForward(exchange, chain, token, path);
                });
    }

    private Mono<Void> validateAndForward(
            ServerWebExchange exchange,
            GatewayFilterChain chain,
            String token,
            String path) {

        try {
            Claims claims = Jwts.parser()
                    .verifyWith(signingKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            String userId = claims.getSubject();
            String role = claims.get("role", String.class);
            if (role == null) {
                role = claims.get("roles", String.class);
            }
            String name = claims.get("name", String.class);

            log.debug("JWT valid — userId={} role={} path={}", userId, role, path);

            // Mutate request to add downstream identity headers
            ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                    .header("X-User-Id", userId != null ? userId : "")
                    .header("X-User-Role", role != null ? role : "")
                    .header("X-User-Name", name != null ? name : "")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .build();

            return chain.filter(exchange.mutate().request(mutatedRequest).build());

        } catch (JwtException | IllegalArgumentException ex) {
            log.warn("JWT validation failed for path {}: {}", path, ex.getMessage());
            return unauthorized(exchange, "Token inválido ou expirado");
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private boolean isPublicEndpoint(String path, HttpMethod method) {
        if (OPEN_PATHS.contains(path)) {
            return true;
        }
        // Prefixes open regardless of HTTP method (e.g. PayPal capture redirect)
        for (String prefix : ANY_METHOD_OPEN_PREFIXES) {
            if (path.startsWith(prefix)) {
                return true;
            }
        }
        // Allow GET-only public paths (prefix match)
        if (HttpMethod.GET.equals(method)) {
            for (String prefix : GET_ONLY_OPEN_PREFIXES) {
                if (path.startsWith(prefix)) {
                    return true;
                }
            }
        }
        return false;
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().add(HttpHeaders.CONTENT_TYPE, "application/json");

        String body = "{\"status\":401,\"error\":\"Unauthorized\",\"message\":\"" + message + "\"}";
        var buffer = response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }
}
