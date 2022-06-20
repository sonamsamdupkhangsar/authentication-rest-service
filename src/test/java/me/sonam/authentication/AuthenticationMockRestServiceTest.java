package me.sonam.authentication;

import me.sonam.authentication.handler.AuthTransfer;
import me.sonam.authentication.handler.AuthenticationHandler;
import me.sonam.authentication.handler.AuthenticationService;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.server.*;
import org.springframework.web.reactive.function.server.support.ServerRequestWrapper;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * this will test routing to the #{@link AuthenticationHandler}
 * service is mocked.
 */
@ExtendWith(MockitoExtension.class)
public class AuthenticationMockRestServiceTest {
    private static final Logger LOG = LoggerFactory.getLogger(AuthenticationMockRestServiceTest.class);

    private final ServerRequest mockServerRequest = mock(ServerRequest.class);
    private final ServerRequestWrapper mockServerRequestWrapper = new ServerRequestWrapper(
            mockServerRequest);

    private WebTestClient webTestClient;

    @InjectMocks
    private AuthenticationHandler handler;

    @Mock
    private AuthenticationService service;

    @Before
    public void setUp() {
        LOG.info("setup mock");
        MockitoAnnotations.openMocks(this);
        RouterFunction<ServerResponse> routerFunction = RouterFunctions
                .route(RequestPredicates.POST("/authenticate"),
                        handler::authenticate);
        this.webTestClient = WebTestClient.bindToRouterFunction(routerFunction).build();
    }

    @Test
    public void authenticate() {
        when(service.authenticate(Mockito.any())).thenReturn(Mono.just("jwtKey"));

        assertThat(webTestClient).isNotNull();

        LOG.info("authenticate");
        webTestClient.post().uri("/authenticate")
                .bodyValue(new AuthTransfer("yakuser", "pass", "apikey"))
                .exchange().expectStatus().isOk()
                .expectBody(String.class)
                .consumeWith(stringEntityExchangeResult -> LOG.info("result: {}", stringEntityExchangeResult.getResponseBody()));
    }
}
