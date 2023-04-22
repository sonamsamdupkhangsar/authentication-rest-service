package me.sonam.authentication;

import me.sonam.authentication.handler.AuthTransfer;
import me.sonam.authentication.handler.AuthenticationHandler;
import me.sonam.authentication.handler.AuthenticationPassword;
import me.sonam.authentication.repo.AuthenticationRepository;
import me.sonam.authentication.repo.entity.Authentication;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.Before;
import org.junit.jupiter.api.AfterEach;
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
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.util.Pair;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.FluxExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * This will test the Authentication endpoints
 * to test the '/authenticate' and '/create' endpoints.
 * For '/authenticate' endpoint it will test that service using a MockWebServer for
 * returning a mocked jwt response.  See {@link Router} for endpoints.
 */
@EnableAutoConfiguration
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes=Application.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(MockitoExtension.class)
public class AuthenticationEndpointMockWebServerTest {
    private static final Logger LOG = LoggerFactory.getLogger(AuthenticationEndpointMockWebServerTest.class);

    private static String jwtEndpoint = "http://localhost:{port}/jwts/accesstoken";

    private static String applicationClientRoleServiceHost = "http://localhost:{port}/applications";
    private static MockWebServer mockWebServer;

    private AuthenticationHandler handler;

    @Autowired
    private AuthenticationRepository authenticationRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private WebTestClient webTestClient;

    @MockBean
    ReactiveJwtDecoder jwtDecoder;

    @AfterEach
    public void cleanRepo() {
        authenticationRepository.deleteAll().subscribe();
    }

    @Before
    public void setUp() {
        LOG.info("setup mock");
        MockitoAnnotations.openMocks(this);
       /* RouterFunction<ServerResponse> routerFunction = RouterFunctions
                .route(RequestPredicates.PUT("/authenticate"),
                        handler::authenticate);
        this.webTestClient = WebTestClient.bindToRouterFunction(routerFunction).build();*/
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
        r.add("jwt-service.root", () -> "http://localhost:"+mockWebServer.getPort());
        r.add("application-rest-service.root", () -> "http://localhost:"+mockWebServer.getPort());
        LOG.info("updated jwt-service and application-rest-service.root properties");
    }

    @Test
    public void createAuthenticationAuthAlreadyExists() {
        Authentication authentication = new Authentication("user2", "yakpass", UUID.randomUUID(),
                UUID.randomUUID(), false, LocalDateTime.now(), true);

        authenticationRepository.save(authentication).subscribe(authentication1 -> LOG.info("subscribe to cause save"));
        //AuthenticationPassword authenticationPassword = new AuthenticationPassword("user2", "pass", "clientId-123");

        Map<String, String> map = new HashMap<>();
        map.put("authenticationId", "user2");
        map.put("password", "pass");
        map.put("clientId", "clientId-123");
        map.put("userId", UUID.randomUUID().toString());
        EntityExchangeResult<Map> result = webTestClient.post().uri("/authentications")
                .bodyValue(map)
                .exchange().expectStatus().isCreated().expectBody(Map.class).returnResult();

        LOG.info("assert result contains authId: {}", result.getResponseBody());
        assertThat(result.getResponseBody().get("message")).isEqualTo("Authentication created successfully for authenticationId: user2");
    }

    @Test
    public void createAuthenticationWithActiveAlreadyExists() {
        Authentication authentication = new Authentication("user2", "yakpass", UUID.randomUUID(),
                UUID.randomUUID(), true, LocalDateTime.now(), true);

        authenticationRepository.save(authentication).subscribe(authentication1 -> LOG.info("subscribe to cause save"));


        AuthenticationPassword authenticationPassword = new AuthenticationPassword("user2", "pass", "clientId-123");

        EntityExchangeResult<Map> result = webTestClient.post().uri("/authentications")
                .bodyValue(authenticationPassword)
                .exchange().expectStatus().isBadRequest().expectBody(Map.class).returnResult();

        LOG.info("assert result contains authId: {}", result.getResponseBody());
        assertThat(result.getResponseBody().get("error")).isEqualTo("Authentication is already active with authenticationId");
    }

    @Test
    void authenticate() throws InterruptedException {
        LOG.info("save a authentication object so that we have a valid user with the password");
        Authentication authentication = new Authentication("user3", passwordEncoder.encode("yakpass"), UUID.randomUUID(),
                UUID.randomUUID(), true, LocalDateTime.now(), true);
        authenticationRepository.save(authentication).subscribe(authentication1 -> LOG.info("subscribe to save"));

        final String jwt= "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJzb25hbSIsImlzcyI6InNvbmFtLmNsb3VkIiwiYXVkIjoic29uYW0uY2xvdWQiLCJqdGkiOiJmMTY2NjM1OS05YTViLTQ3NzMtOWUyNy00OGU0OTFlNDYzNGIifQ.KGFBUjghvcmNGDH0eM17S9pWkoLwbvDaDBGAx2AyB41yZ_8-WewTriR08JdjLskw1dsRYpMh9idxQ4BS6xmOCQ";
        final String jwtTokenMsg = " {\"token\":\""+jwt+"\"}";
        // first it will call send hmac to get accesstoken 'jwt/accesstoken'
        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json").setResponseCode(200).setBody(jwtTokenMsg));

        //groupNames=admin1touser, employee
        final String clientRoleGroups = "{\"userRole\":\"user\",\"groupNames\":\"admin1touser\",\"employee\"}";
        // then return this for client role groups api call
        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json").setResponseCode(200).setBody(clientRoleGroups));
        // then return this jwt token again when authentication api calls the jwt-rest-service to get the jwt token
        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json").setResponseCode(200).setBody(jwtTokenMsg));

        LOG.info("call authenticate rest endpoint in this application");
        EntityExchangeResult<Map> result = webTestClient.post().uri("/authentications/authenticate")
                .bodyValue(new AuthTransfer("user3", "yakpass", UUID.randomUUID(),"clientId-123"))
                .exchange().expectStatus().isOk()
                .expectBody(Map.class).returnResult();

        assertThat(result.getResponseBody().get("message")).isEqualTo("Authentication successful");
        LOG.info("response: {}", result.getResponseBody());
        assertThat(result.getResponseBody()).isNotEmpty();
        LOG.info("start taking request now");

        RecordedRequest request = mockWebServer.takeRequest();
        assertThat(request.getMethod()).isEqualTo("POST");
        assertThat(request.getPath()).startsWith("/jwts/accesstoken");

        request = mockWebServer.takeRequest();
        assertThat(request.getMethod()).isEqualTo("GET");
        assertThat(request.getPath()).startsWith("/applications/clients");

        request = mockWebServer.takeRequest();
        assertThat(request.getMethod()).isEqualTo("POST");
        assertThat(request.getPath()).startsWith("/jwts/accesstoken");

        //the body is empty for some reason.
        String body = new String(request.getBody().getBuffer().readByteArray());
        LOG.info("1st request for getting clientRoleGroups with path: {}", request.getPath());
        LOG.info("request: {}", body);
        assertThat(body).isNotEmpty();
    }


    @Test
    void authenticateBadPassword() throws InterruptedException {
        LOG.info("save a authentication object so that we have a valid user with the password");
        Authentication authentication = new Authentication("user3", passwordEncoder.encode("yakpass"), UUID.randomUUID(),
                UUID.randomUUID(), true, LocalDateTime.now(), true);
        authenticationRepository.save(authentication).subscribe(authentication1 -> LOG.info("subscribe to save"));

        LOG.info("call authenticate rest endpoint in this application");
        EntityExchangeResult<Map> result = webTestClient.post().uri("/authentications/authenticate")
                .bodyValue(new AuthTransfer("user3", "yakpass2", UUID.randomUUID(),"clientId-123"))
                .exchange().expectStatus().isBadRequest()
                .expectBody(Map.class).returnResult();

        LOG.info("response: {}", result.getResponseBody());
        assertThat(result.getResponseBody().get("error")).isEqualTo("no authentication found with username and password");
    }


    @Test
    void authenticateActiveFalse() throws InterruptedException {
        LOG.info("save a authentication object so that we have a valid user with the password");
        Authentication authentication = new Authentication("user3", "yakpass",  UUID.randomUUID(),
                UUID.randomUUID(), false, LocalDateTime.now(), true);
        authenticationRepository.save(authentication).subscribe(authentication1 -> LOG.info("subscribe to save"));

        final String jwt= "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJzb25hbSIsImlzcyI6InNvbmFtLmNsb3VkIiwiYXVkIjoic29uYW0uY2xvdWQiLCJqdGkiOiJmMTY2NjM1OS05YTViLTQ3NzMtOWUyNy00OGU0OTFlNDYzNGIifQ.KGFBUjghvcmNGDH0eM17S9pWkoLwbvDaDBGAx2AyB41yZ_8-WewTriR08JdjLskw1dsRYpMh9idxQ4BS6xmOCQ";


        LOG.info("call authenticate rest endpoint in this application");
        EntityExchangeResult<Map> result = webTestClient.post().uri("/authentications/authenticate")
                .bodyValue(new AuthTransfer("user3", "yakpass", UUID.randomUUID(), "clientId-123"))
                .exchange().expectStatus().isBadRequest()
                .expectBody(Map.class).returnResult();
                //.consumeWith(stringEntityExchangeResult -> LOG.info("result: {}", stringEntityExchangeResult.getResponseBody()));

        assertThat(result.getResponseBody().get("error")).isEqualTo("Authentication not active, activate your acccount first");
        LOG.info("start taking request now");
    }


    /**
     * this will test both endpoints: create authentication and authenticate to create jwt
     */
    @Test
    public void createAuthenticationAndAuthenticate() throws InterruptedException {
        LOG.info("create authTransfer");
        AuthTransfer authTransfer = new AuthTransfer("user4", "pass", UUID.randomUUID(), "clientId-123");

        EntityExchangeResult<Map> result = webTestClient.post().uri("/authentications")
                .bodyValue(authTransfer)
                .exchange().expectStatus().isCreated().expectBody(Map.class).returnResult();

        LOG.info("assert result contains authId: {}", result.getResponseBody());
        assertThat(result.getResponseBody().get("message")).isEqualTo("Authentication created successfully for authenticationId: user4");

        authenticationRepository.updateAuthenticationActiveTrue("user4").subscribe(integer -> LOG.info("set authentication to Active"));

        final String jwt= "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJzb25hbSIsImlzcyI6InNvbmFtLmNsb3VkIiwiYXVkIjoic29uYW0uY2xvdWQiLCJqdGkiOiJmMTY2NjM1OS05YTViLTQ3NzMtOWUyNy00OGU0OTFlNDYzNGIifQ.KGFBUjghvcmNGDH0eM17S9pWkoLwbvDaDBGAx2AyB41yZ_8-WewTriR08JdjLskw1dsRYpMh9idxQ4BS6xmOCQ";
        final String jwtTokenMsg = " {\"token\":\""+jwt+"\"}";
        // this is for returning a jwt token on hmac generation
        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json").setResponseCode(200).setBody(jwtTokenMsg));

        final String clientRoleGroups = "{\"userRole\":\"user\",\"groupNames\":[\"admin1touser\",\"employee\"]}";
        // return this response for role groups for clients call
        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json").setResponseCode(200).setBody(clientRoleGroups));
        // this is for generating the jwt token when jwt-rest-service is called at /jwt/accesstoken
        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json").setResponseCode(200).setBody(jwtTokenMsg));

        LOG.info("call authenticate rest endpoint in this application");
        result = webTestClient.post().uri("/authentications/authenticate")
                .bodyValue(authTransfer)
                .exchange().expectStatus().isOk()
                .expectBody(Map.class).returnResult();

        assertThat(result.getResponseBody()).isNotEmpty();

        LOG.info("start taking request now");
        RecordedRequest request = mockWebServer.takeRequest();
        assertThat(request.getMethod()).isEqualTo("POST");
        assertThat(request.getPath()).isEqualTo("/jwts/accesstoken");

        request = mockWebServer.takeRequest();
        assertThat(request.getMethod()).isEqualTo("GET");
        assertThat(request.getPath()).startsWith("/applications/clients");

        request = mockWebServer.takeRequest();
        assertThat(request.getMethod()).isEqualTo("POST");
        assertThat(request.getPath()).isEqualTo("/jwts/accesstoken");

        //the body is empty for some reason.
        String body = new String(request.getBody().getBuffer().readByteArray());
        LOG.info("path: {}", request.getPath());
        LOG.info("request: {}", body);


        assertThat(request.getPath().startsWith("/clients/clientId/users/"));

        //request = mockWebServer.takeRequest();
        LOG.info("2nd request is to get JWT from jwt-rest-service with path: {}", request.getPath());
        //assertThat(request.getMethod()).isEqualTo("POST");
        //assertThat(request.getPath()).startsWith("/jwts/accesstoken");


        LOG.info("jwt: {}", result.getResponseBody());


        LOG.info("now use a bad username to authenticate locally");
        authTransfer.setAuthenticationId("invaliduser");
        result = webTestClient.post().uri("/authentications/authenticate")
                .bodyValue(authTransfer)
                .exchange().expectStatus().isBadRequest().expectBody(Map.class).returnResult();

        LOG.info("response: {}", result.getResponseBody());
        assertThat(result.getResponseBody().get("error")).isEqualTo("authentication does not exist with authId");

    }

    @Test
    public void setActive() throws InterruptedException {
        final String authenticationId = "adminAuth";
        Jwt jwt = jwt(authenticationId);
        when(this.jwtDecoder.decode(anyString())).thenReturn(Mono.just(jwt));

        Authentication adminAuth = new Authentication(authenticationId, "yakpass",  UUID.randomUUID(),
                UUID.randomUUID(), false, LocalDateTime.now(), true);
        authenticationRepository.save(adminAuth).subscribe(authentication1 -> LOG.info("subscribe to save"));


        Authentication authentication = new Authentication("user3", "yakpass", UUID.randomUUID(),
                UUID.randomUUID(), false, LocalDateTime.now(), true);
        authenticationRepository.save(authentication).subscribe(authentication1 -> LOG.info("subscribe to save"));

        LOG.info("call activate");
        EntityExchangeResult<Map> result = webTestClient.put().uri("/authentications/activate/"+"user3")
                .headers(addJwt(jwt))
                .exchange().expectStatus().isOk()
                .expectBody(Map.class)
                .returnResult();

        LOG.info("response: {}", result.getResponseBody());
        assertThat(result.getResponseBody().get("message")).isEqualTo("activated: user3");

        authenticationRepository.findById("user3").subscribe(authentication1
                -> LOG.info("is active true?: {}", authentication1.getActive()));
    }

    @Test
    public void setActiveNotExisting() throws InterruptedException {
        LOG.info("call activate");
        final String authenticationId = "adminAuth";
        Jwt jwt = jwt(authenticationId);
        when(this.jwtDecoder.decode(anyString())).thenReturn(Mono.just(jwt));

        Authentication adminAuth = new Authentication(authenticationId, "yakpass", UUID.randomUUID(),
                UUID.randomUUID(), false, LocalDateTime.now(), true);
        authenticationRepository.save(adminAuth).subscribe(authentication1 -> LOG.info("subscribe to save"));

        //activate endpoint is called by account-rest-service, so account-rest-service will use its own jwt
        EntityExchangeResult<Map> result = webTestClient.put().uri("/authentications/activate/"+"user3")
                .headers(addJwt(jwt))
                .exchange().expectStatus().isOk()
                .expectBody(Map.class)
                .returnResult();

        LOG.info("response: {}", result.getResponseBody());
        assertThat(result.getResponseBody().get("message")).isEqualTo("activated: user3");

    }


    @Test
    void deleteWhenActiveFalse() throws InterruptedException {
        LOG.info("save a authentication object so that we have a valid user with the password");
        final String authId = "deleteWhenActiveFalse";

        Jwt jwt = jwt(authId);
        when(this.jwtDecoder.decode(anyString())).thenReturn(Mono.just(jwt));

        Authentication authentication = new Authentication(authId, "yakpass",
                UUID.randomUUID(),
                UUID.randomUUID(), false, LocalDateTime.now(), true);
        authenticationRepository.save(authentication).subscribe(authentication1 -> LOG.info("subscribe to save"));

        //allow self to delete as well
        LOG.info("call delete rest endpoint in this application");
        EntityExchangeResult<Map> result = webTestClient.delete().uri("/authentications")
                .headers(addJwt(jwt))
                .exchange().expectStatus().isOk()
                .expectBody(Map.class).returnResult();

        assertThat(result.getResponseBody().get("message")).isEqualTo("deleted: "+authId);
        authenticationRepository.existsById(authId).subscribe(aBoolean ->
                LOG.info("exists should be false: {}", aBoolean));
    }

    @Test
    void deleteWhenActiveTrue() throws InterruptedException {
        LOG.info("save a authentication object so that we have a valid user with the password");
        final String authId = "deleteWhenActiveTrue";
        Jwt jwt = jwt(authId);
        when(this.jwtDecoder.decode(anyString())).thenReturn(Mono.just(jwt));

        Authentication authentication = new Authentication(authId, "yakpass",
                UUID.randomUUID(),
                UUID.randomUUID(), true, LocalDateTime.now(), true);
        authenticationRepository.save(authentication).subscribe(authentication1 -> LOG.info("subscribe to save"));

        LOG.info("call delete rest endpoint in this application");
        EntityExchangeResult<Map> result = webTestClient.delete().uri("/authentications")
                .headers(addJwt(jwt))
                .exchange().expectStatus().isBadRequest()
                .expectBody(Map.class).returnResult();

        assertThat(result.getResponseBody().get("error")).isEqualTo("authentication is active, cannot delete");
        authenticationRepository.existsById(authId).subscribe(aBoolean ->
                LOG.info("exists should be true: {}", aBoolean));
    }


    @Test
    public void updateNotAuthenticatedPassword() {
        Authentication authentication = new Authentication("user3", "yakpass",UUID.randomUUID(),
                UUID.randomUUID(), true, LocalDateTime.now(), true);
        authenticationRepository.save(authentication).subscribe(authentication1 -> LOG.info("subscribe to save"));

        final String authId = "user3";
        Jwt jwt = jwt(authId);
        when(this.jwtDecoder.decode(anyString())).thenReturn(Mono.just(jwt));

        Map<String, String> map = AuthenticationHandler.getMap(
                Pair.of("authenticationId", "user3"),
                Pair.of("password", "newPass"));
        LOG.info("call authentication/password update");
       webTestClient.put().uri("/authentications/noauth/password")
                .bodyValue(map)
                .headers(addJwt(jwt))
                .headers(httpHeaders -> httpHeaders.setContentType(MediaType.APPLICATION_JSON))
                .exchange().expectStatus().isOk()
                .expectBody(Map.class)
                .consumeWith(stringEntityExchangeResult -> LOG.info("result: {}", stringEntityExchangeResult.getResponseBody()));

        authenticationRepository.findById("user3").as(StepVerifier::create)
                .expectNextMatches(authentication1 -> {
                    LOG.info("password is newPass?  {}", authentication1.getPassword());
                    return  authentication1.getPassword().equals("newPass");
                })
                .expectComplete().verify();
    }

    @Test
    public void updatePassword() {
        Authentication authentication = new Authentication("user3", "yakpass",UUID.randomUUID(),
                UUID.randomUUID(), true, LocalDateTime.now(), true);
        authenticationRepository.save(authentication).subscribe(authentication1 -> LOG.info("subscribe to save"));

        final String authId = "user3";
        Jwt jwt = jwt(authId);
        when(this.jwtDecoder.decode(anyString())).thenReturn(Mono.just(jwt));

        Map<String, String> map = AuthenticationHandler.getMap(
                Pair.of("password", "newPass"));

        LOG.info("call authentication/password update");
        webTestClient.put().uri("/authentications/password")
                .bodyValue(map)
                .headers(addJwt(jwt))
                .headers(httpHeaders -> httpHeaders.setContentType(MediaType.APPLICATION_JSON))
                .exchange().expectStatus().isOk()
                .expectBody(Map.class)
                .consumeWith(stringEntityExchangeResult -> LOG.info("result: {}", stringEntityExchangeResult.getResponseBody()));

        authenticationRepository.findById("user3").as(StepVerifier::create)
                .expectNextMatches(authentication1 -> {
                    LOG.info("password is newPass?  {}", authentication1.getPassword());
                    return  authentication1.getPassword().equals("newPass");
                })
                .expectComplete().verify();
    }

    private Jwt jwt(String subjectName) {
        return new Jwt("token", null, null,
                Map.of("alg", "none"), Map.of("sub", subjectName));
    }

    private Consumer<HttpHeaders> addJwt(Jwt jwt) {
        return headers -> headers.setBearerAuth(jwt.getTokenValue());
    }
}
