package mz.ebooks.gateway.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.server.reactive.ServerHttpRequest;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;
import java.util.Objects;

/**
 * Rate-limiter configuration.
 *
 * <p>The {@link KeyResolver} bean determines the bucket key for the Redis-backed
 * token-bucket algorithm provided by {@code spring-cloud-starter-gateway}.
 *
 * <p>Key resolution strategy (in priority order):
 * <ol>
 *   <li><b>Authenticated users</b> — the {@code X-User-Id} header that the
 *       {@link mz.ebooks.gateway.filter.JwtAuthenticationFilter} adds after
 *       successful JWT validation. This ensures authenticated users share a
 *       bucket per account, not per IP (useful behind NAT / proxies).</li>
 *   <li><b>Anonymous requests</b> — the client's real IP address, resolved
 *       through common proxy headers ({@code X-Forwarded-For},
 *       {@code X-Real-IP}) before falling back to the remote address.</li>
 * </ol>
 *
 * <p>The bucket capacities themselves are configured in {@code application.yml}
 * under {@code spring.cloud.gateway.default-filters.RequestRateLimiter}.
 */
@Slf4j
@Configuration
public class RateLimiterConfig {

    /**
     * Primary {@link KeyResolver} bean used by the {@code RequestRateLimiter} filter.
     *
     * <p>Must be named {@code userKeyResolver} or referenced explicitly in the route
     * filter args ({@code key-resolver: "#{@userKeyResolver}"}). Because this is the
     * only {@link KeyResolver} bean it will be picked up automatically by Spring Cloud
     * Gateway as the default resolver.
     */
    @Bean
    public KeyResolver userKeyResolver() {
        return exchange -> {
            ServerHttpRequest request = exchange.getRequest();

            // 1. Prefer the authenticated user identifier injected by JwtAuthenticationFilter
            String userId = request.getHeaders().getFirst("X-User-Id");
            if (userId != null && !userId.isBlank()) {
                log.debug("Rate-limit key (user): {}", userId);
                return Mono.just("user:" + userId);
            }

            // 2. Fall back to the real client IP, respecting reverse-proxy headers
            String forwardedFor = request.getHeaders().getFirst("X-Forwarded-For");
            if (forwardedFor != null && !forwardedFor.isBlank()) {
                // X-Forwarded-For may contain a comma-separated list; the leftmost is the client IP
                String clientIp = forwardedFor.split(",")[0].trim();
                log.debug("Rate-limit key (X-Forwarded-For): {}", clientIp);
                return Mono.just("ip:" + clientIp);
            }

            String realIp = request.getHeaders().getFirst("X-Real-IP");
            if (realIp != null && !realIp.isBlank()) {
                log.debug("Rate-limit key (X-Real-IP): {}", realIp);
                return Mono.just("ip:" + realIp);
            }

            // 3. Last resort: remote socket address
            InetSocketAddress remoteAddress = request.getRemoteAddress();
            String fallbackIp = (remoteAddress != null)
                    ? Objects.requireNonNullElse(remoteAddress.getAddress().getHostAddress(), "unknown")
                    : "unknown";

            log.debug("Rate-limit key (remote): {}", fallbackIp);
            return Mono.just("ip:" + fallbackIp);
        };
    }
}
