package me.sonam.authentication.config;

import me.sonam.authentication.handler.SimpleAuthenticationService;
import me.sonam.authentication.webclient.RoleWebClient;
import me.sonam.security.headerfilter.ReactiveRequestContextHolder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class BeanConfig {
    @Value("${role-rest-service.context}")
    private String roleEndpoint;

    @Value("${tokenExpireSeconds:1}")
    private int tokenExpireSeconds;

    @Autowired
    @Qualifier("serviceWebClientBuilder")
    private WebClient.Builder serviceWebClientBuilder;

    @Bean
    public RoleWebClient roleWebClient() {
        return new RoleWebClient(serviceWebClientBuilder, roleEndpoint);
    }

    @Bean
    public ReactiveRequestContextHolder reactiveRequestContextHolder(
            @Qualifier("tokenWebClientBuilder") WebClient.Builder tokenWebClientBuilder) {
        return new ReactiveRequestContextHolder(tokenWebClientBuilder, tokenExpireSeconds);
    }

    @Bean
    public SimpleAuthenticationService simpleAuthenticationService(
            @Qualifier("serviceWebClientBuilder") WebClient.Builder serviceWebClientBuilder) {
        return new SimpleAuthenticationService(serviceWebClientBuilder);
    }
}
