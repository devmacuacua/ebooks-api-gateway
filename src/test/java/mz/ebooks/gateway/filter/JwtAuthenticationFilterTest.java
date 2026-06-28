package mz.ebooks.gateway.filter;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterTest {

    private static final String SECRET = "gateway-test-secret-that-is-at-least-32-bytes-long!!";

    @Mock ReactiveStringRedisTemplate redisTemplate;
    @Mock GatewayFilterChain chain;

    private JwtAuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        filter = new JwtAuthenticationFilter(redisTemplate, SECRET);
        // lenient: some tests expect chain.filter() to never be called
        lenient().when(chain.filter(any())).thenReturn(Mono.empty());
    }

    // ── open paths bypass JWT ─────────────────────────────────────────────────

    @ParameterizedTest
    @ValueSource(strings = {
            "/api/auth/login",
            "/api/auth/register",
            "/api/auth/verify-email",
            "/api/auth/forgot-password",
            "/api/auth/reset-password",
    })
    void openPaths_allowRequestWithoutToken(String path) {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post(path).build()
        );

        StepVerifier.create(filter.filter(exchange, chain))
                .expectComplete()
                .verify();

        verify(chain).filter(any());
        assertThat(exchange.getResponse().getStatusCode()).isNotEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void paymentWebhooks_allowWithoutToken() {
        for (String path : new String[]{
                "/api/commerce/payments/webhooks/stripe",
                "/api/commerce/payments/callbacks/mpesa",
                "/api/commerce/payments/callbacks/emola"
        }) {
            MockServerWebExchange exchange = MockServerWebExchange.from(
                    MockServerHttpRequest.post(path).build()
            );
            StepVerifier.create(filter.filter(exchange, chain)).expectComplete().verify();
        }
        verify(chain, times(3)).filter(any());
    }

    @Test
    void catalogGetRequest_isAllowed_withoutToken() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/catalog/books?page=0").build()
        );

        StepVerifier.create(filter.filter(exchange, chain))
                .expectComplete()
                .verify();

        verify(chain).filter(any());
    }

    @Test
    void catalogPostRequest_requiresToken() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/api/catalog/books").build()
        );

        StepVerifier.create(filter.filter(exchange, chain))
                .expectComplete()
                .verify();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        verify(chain, never()).filter(any());
    }

    // ── missing / malformed Authorization header ──────────────────────────────

    @Test
    void missingAuthHeader_returns401() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/users/me").build()
        );

        StepVerifier.create(filter.filter(exchange, chain))
                .expectComplete()
                .verify();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        verify(chain, never()).filter(any());
    }

    @Test
    void malformedAuthHeader_returns401() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/users/me")
                        .header(HttpHeaders.AUTHORIZATION, "Basic dXNlcjpwYXNz")
                        .build()
        );

        StepVerifier.create(filter.filter(exchange, chain))
                .expectComplete()
                .verify();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    // ── blacklisted token ─────────────────────────────────────────────────────

    @Test
    void blacklistedToken_returns401() {
        String token = generateToken("user-id", "CUSTOMER");
        when(redisTemplate.hasKey("blacklist:" + token)).thenReturn(Mono.just(true));

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/users/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .build()
        );

        StepVerifier.create(filter.filter(exchange, chain))
                .expectComplete()
                .verify();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        verify(chain, never()).filter(any());
    }

    // ── valid token ───────────────────────────────────────────────────────────

    @Test
    void validToken_forwardsUserIdentityHeaders() {
        String token = generateToken("user-42", "CUSTOMER");
        when(redisTemplate.hasKey(anyString())).thenReturn(Mono.just(false));

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/users/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .build()
        );

        StepVerifier.create(filter.filter(exchange, chain))
                .expectComplete()
                .verify();

        verify(chain).filter(argThat(ex -> {
            HttpHeaders headers = ex.getRequest().getHeaders();
            return "user-42".equals(headers.getFirst("X-User-Id"))
                    && "CUSTOMER".equals(headers.getFirst("X-User-Role"));
        }));
    }

    @Test
    void validAdminToken_forwardsAdminRole() {
        String token = generateToken("admin-1", "ADMIN");
        when(redisTemplate.hasKey(anyString())).thenReturn(Mono.just(false));

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.delete("/api/catalog/books/some-id")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .build()
        );

        StepVerifier.create(filter.filter(exchange, chain))
                .expectComplete()
                .verify();

        verify(chain).filter(argThat(ex ->
                "ADMIN".equals(ex.getRequest().getHeaders().getFirst("X-User-Role"))
        ));
    }

    // ── invalid / expired token ───────────────────────────────────────────────

    @Test
    void invalidToken_returns401() {
        when(redisTemplate.hasKey(anyString())).thenReturn(Mono.just(false));

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/users/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer not.a.valid.jwt")
                        .build()
        );

        StepVerifier.create(filter.filter(exchange, chain))
                .expectComplete()
                .verify();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void expiredToken_returns401() {
        SecretKey key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
        String expiredToken = Jwts.builder()
                .subject("u-expired")
                .claim("role", "CUSTOMER")
                .expiration(new Date(System.currentTimeMillis() - 1000))
                .signWith(key)
                .compact();

        when(redisTemplate.hasKey(anyString())).thenReturn(Mono.just(false));

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/users/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + expiredToken)
                        .build()
        );

        StepVerifier.create(filter.filter(exchange, chain))
                .expectComplete()
                .verify();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    // ── helper ────────────────────────────────────────────────────────────────

    private String generateToken(String userId, String role) {
        SecretKey key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
        return Jwts.builder()
                .subject(userId)
                .claim("role", role)
                .claim("name", "Test User")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 3_600_000))
                .signWith(key)
                .compact();
    }
}
