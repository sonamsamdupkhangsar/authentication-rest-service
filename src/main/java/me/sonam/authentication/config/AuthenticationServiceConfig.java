package me.sonam.authentication.config;

import me.sonam.authentication.handler.SimpleAuthenticationService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.web.reactive.function.client.WebClient;

@Profile({"eureka", "non-eureka"})
@Configuration
public class AuthenticationServiceConfig {

    @Bean
    public SimpleAuthenticationService simpleAuthenticationService(
            @Qualifier("serviceWebClientBuilder") WebClient.Builder serviceWebClientBuilder) {
        return new SimpleAuthenticationService(serviceWebClientBuilder);
    }
}
