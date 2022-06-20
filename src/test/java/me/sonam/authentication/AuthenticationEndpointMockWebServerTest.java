package me.sonam.authentication;

import me.sonam.authentication.handler.AuthTransfer;
import me.sonam.authentication.handler.AuthenticationHandler;
import me.sonam.authentication.repo.AuthenticationRepository;
import me.sonam.authentication.repo.entity.Authentication;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.Before;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.server.RequestPredicates;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * This will test the Authentication endpoints
 * to test the '/authenticate' and '/create' endpoints.
 * For '/authenticate' endpoint it will test that service using a MockWebServer for
 * returning a mocked jwt response.  See {@link Router} for endpoints.
 */
@EnableAutoConfiguration
@ExtendWith(SpringExtension.class)
@SpringBootTest( webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(MockitoExtension.class)
public class AuthenticationEndpointMockWebServerTest {
    private static final Logger LOG = LoggerFactory.getLogger(AuthenticationEndpointMockWebServerTest.class);

    private static String jwtEndpoint = "http://localhost:{port}/create/{username}/{audience}/{expireField}/{expireIn}";

    @Value("${apiKey}")
    private String apiKey;

    private static MockWebServer mockWebServer;

    private AuthenticationHandler handler;

    @Autowired
    private AuthenticationRepository authenticationRepository;

    @Autowired
    private WebTestClient webTestClient;

    @Before
    public void setUp() {
        LOG.info("setup mock");
        MockitoAnnotations.openMocks(this);
        RouterFunction<ServerResponse> routerFunction = RouterFunctions
                .route(RequestPredicates.PUT("/authenticate"),
                        handler::authenticate);
        this.webTestClient = WebTestClient.bindToRouterFunction(routerFunction).build();
    }


    @BeforeAll
    static void setupMockWebServer() throws IOException {
        mockWebServer = new MockWebServer();
        mockWebServer.start();

        LOG.info("host: {}, port: {}", mockWebServer.getHostName(), mockWebServer.getPort());
    }

    /**
     * this method will update the 'jwt-rest-service' endpoint address to the mockWebServer port
     * so that it can be mocked.
     * @param r
     * @throws IOException
     */
    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) throws IOException {
        r.add("jwt-rest-service", () -> jwtEndpoint.replace("{port}",  mockWebServer.getPort()+""));
        LOG.info("updated jwt-rest-service property");
    }


    @Test
    public void createAuthenticationApiKeyFail() {
        AuthTransfer authTransfer = new AuthTransfer("user1", "pass", "123WrongApiKey");

        EntityExchangeResult<String> result = webTestClient.post().uri("/create")
                .bodyValue(authTransfer)
                .exchange().expectStatus().isBadRequest().expectBody(String.class).returnResult();

        LOG.info("assert result contains authId: {}", result.getResponseBody());
        assertThat(result.getResponseBody()).isEqualTo("apikey check fail");
    }

    @Test
    public void createAuthenticationAuthAlreadyExists() {
        Authentication authentication = new Authentication("user2", "yakpass", UUID.randomUUID(), UUID.randomUUID(),
                UUID.randomUUID(), true, LocalDateTime.now(), true);

        authenticationRepository.save(authentication).subscribe(authentication1 -> LOG.info("subscribe to cauase save"));


        AuthTransfer authTransfer = new AuthTransfer("user2", "pass", apiKey);

        EntityExchangeResult<String> result = webTestClient.post().uri("/create")
                .bodyValue(authTransfer)
                .exchange().expectStatus().isBadRequest().expectBody(String.class).returnResult();

        LOG.info("assert result contains authId: {}", result.getResponseBody());
        assertThat(result.getResponseBody()).isEqualTo("authenticationId already exists");
    }

    @Test
    void authenticate() throws InterruptedException {
        LOG.info("save a authentication object so that we have a valid user with the password");
        Authentication authentication = new Authentication("user3", "yakpass", UUID.randomUUID(), UUID.randomUUID(),
                UUID.randomUUID(), true, LocalDateTime.now(), true);
        authenticationRepository.save(authentication).subscribe(authentication1 -> LOG.info("subscribe to save"));

        final String jwt= "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJzb25hbSIsImlzcyI6InNvbmFtLmNsb3VkIiwiYXVkIjoic29uYW0uY2xvdWQiLCJqdGkiOiJmMTY2NjM1OS05YTViLTQ3NzMtOWUyNy00OGU0OTFlNDYzNGIifQ.KGFBUjghvcmNGDH0eM17S9pWkoLwbvDaDBGAx2AyB41yZ_8-WewTriR08JdjLskw1dsRYpMh9idxQ4BS6xmOCQ";

        mockWebServer.enqueue(new MockResponse().setResponseCode(200).setBody(jwt));


        LOG.info("call authenticate rest endpoint in this application");
        webTestClient.post().uri("/authenticate")
                .bodyValue(new AuthTransfer("user3", "yakpass", apiKey))
                .exchange().expectStatus().isOk()
                .expectBody(String.class)
                .consumeWith(stringEntityExchangeResult -> LOG.info("result: {}", stringEntityExchangeResult.getResponseBody()));

        LOG.info("start taking request now");
        RecordedRequest request = mockWebServer.takeRequest();
        assertThat(request.getMethod()).isEqualTo("GET");

        //the body is empty for some reason.
        String body = new String(request.getBody().getBuffer().readByteArray());
        LOG.info("path: {}", request.getPath());
        LOG.info("request: {}", body);

        assertThat(request.getPath()).startsWith("/create/");
    }

    /**
     * this will test both endpoints: create authentication and authenticate to create jwt
     */
    @Test
    public void createAuthenticationAndAuthenticate() throws InterruptedException {
        LOG.info("create authTransfer");
        AuthTransfer authTransfer = new AuthTransfer("user4", "pass", apiKey);

        EntityExchangeResult<String> result = webTestClient.post().uri("/create")
                .bodyValue(authTransfer)
                .exchange().expectStatus().isOk().expectBody(String.class).returnResult();

        LOG.info("assert result contains authId: {}", result.getResponseBody());
        assertThat(result.getResponseBody()).isEqualTo("create Authentication success for authId: user4");

        final String jwt= "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJzb25hbSIsImlzcyI6InNvbmFtLmNsb3VkIiwiYXVkIjoic29uYW0uY2xvdWQiLCJqdGkiOiJmMTY2NjM1OS05YTViLTQ3NzMtOWUyNy00OGU0OTFlNDYzNGIifQ.KGFBUjghvcmNGDH0eM17S9pWkoLwbvDaDBGAx2AyB41yZ_8-WewTriR08JdjLskw1dsRYpMh9idxQ4BS6xmOCQ";

        mockWebServer.enqueue(new MockResponse().setResponseCode(200).setBody(jwt));

        LOG.info("call authenticate rest endpoint in this application");
        webTestClient.post().uri("/authenticate")
                .bodyValue(authTransfer)
                .exchange().expectStatus().isOk()
                .expectBody(String.class)
                .consumeWith(stringEntityExchangeResult -> LOG.info("result: {}", stringEntityExchangeResult.getResponseBody()));

        LOG.info("start taking request now");
        RecordedRequest request = mockWebServer.takeRequest();
        assertThat(request.getMethod()).isEqualTo("GET");

        //the body is empty for some reason.
        String body = new String(request.getBody().getBuffer().readByteArray());
        LOG.info("path: {}", request.getPath());
        LOG.info("request: {}", body);

        assertThat(request.getPath()).startsWith("/create/");

        LOG.info("jwt: {}", result.getResponseBody());


        LOG.info("now use a bad username to authenticate locally");
        authTransfer.setAuthenticationId("invaliduser");
        result = webTestClient.post().uri("/authenticate")
                .bodyValue(authTransfer)
                .exchange().expectStatus().isBadRequest().expectBody(String.class).returnResult();

        LOG.info("response: {}", result.getResponseBody());
        assertThat(result.getResponseBody()).isEqualTo("no authentication found with username or password");

    }

}
