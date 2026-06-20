package me.sonam.authentication;

import me.sonam.authentication.handler.SimpleAuthenticationService;
import me.sonam.security.headerfilter.ReactiveRequestContextHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.web.reactive.function.client.WebClient;

@Profile("localdevtest")
@Configuration
public class WebClientConfig {
    private static final Logger LOG = LoggerFactory.getLogger(WebClientConfig.class);
    @Value("${tokenExpireSeconds:1}")
    private int tokenExpireSeconds;

    @Bean("serviceWebClientBuilder")
    public WebClient.Builder serviceWebClientBuilder() {
        LOG.info("returning non load balanced service webclient builder");
        return WebClient.builder();
    }

    @Bean
    public ReactiveRequestContextHolder reactiveRequestContextHolder() {
        return new ReactiveRequestContextHolder(serviceWebClientBuilder(), tokenExpireSeconds);
    }

    @Bean
    public SimpleAuthenticationService userAccountService() {
        return new SimpleAuthenticationService(serviceWebClientBuilder());
    }
}
