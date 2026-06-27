package me.sonam.authentication.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.web.reactive.function.client.WebClient;

@Profile("non-eureka")
@Configuration
public class DirectWebClientConfig {
    private static final Logger LOG = LoggerFactory.getLogger(DirectWebClientConfig.class);

    @Bean("serviceWebClientBuilder")
    public WebClient.Builder serviceWebClientBuilder() {
        LOG.info("creating direct service WebClient for non-Eureka service discovery");
        return WebClient.builder();
    }

    @Bean("tokenWebClientBuilder")
    public WebClient.Builder tokenWebClientBuilder() {
        LOG.info("creating direct token WebClient for non-Eureka service discovery");
        return WebClient.builder();
    }
}
