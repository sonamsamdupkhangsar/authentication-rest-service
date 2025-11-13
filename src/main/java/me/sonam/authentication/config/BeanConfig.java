package me.sonam.authentication.config;

import me.sonam.authentication.webclient.RoleWebClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class BeanConfig {
    @Value("${role-rest-service.context}")
    private String roleEndpoint;

    @Autowired
    private WebClient.Builder webClientBuilder;

    @Bean
    public RoleWebClient roleWebClient() {
        return new RoleWebClient(webClientBuilder, roleEndpoint);
    }
}
