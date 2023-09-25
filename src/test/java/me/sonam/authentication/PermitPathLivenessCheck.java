package me.sonam.authentication;


import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;

@EnableAutoConfiguration
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes=Application.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(MockitoExtension.class)
public class PermitPathLivenessCheck {
    private static final Logger LOG = LoggerFactory.getLogger(PermitPathLivenessCheck.class);
    @Autowired
    private WebTestClient webTestClient;
    @MockBean
    private ReactiveJwtDecoder jwtDecoder;

    @Test
    public void liveness() {
          EntityExchangeResult<String> entityExchangeResult = webTestClient.get().uri("/authentications/api/health/liveness")
                .exchange().expectStatus().isOk()
                .expectBody(String.class).returnResult();

          LOG.info("response: {}, httpStatus: {}", entityExchangeResult.getResponseBody(), entityExchangeResult.getStatus());
    }

}
