package me.sonam.authentication.config;

import me.sonam.authentication.handler.SimpleAuthenticationService;
import me.sonam.security.headerfilter.ReactiveRequestContextHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.web.reactive.function.client.WebClient;

@Profile("!localdevtest")
@Configuration
public class WebClientConfig {
    private static final Logger LOG = LoggerFactory.getLogger(WebClientConfig.class);
    @Value("${tokenExpireSeconds:1}")
    private int tokenExpireSeconds;

    // Used for normal downstream service calls through Spring load balancing.
    @LoadBalanced
    @Bean("serviceWebClientBuilder")
    public WebClient.Builder serviceWebClientBuilder() {
        LOG.info("returning load balanced service webclient builder");
        return WebClient.builder();
    }

    // Used only by ReactiveRequestContextHolder when requesting access tokens from authorization server.
    @LoadBalanced
    @Bean("tokenWebClientBuilder")
    @Profile("!local-https")
    public WebClient.Builder loadBalancedTokenWebClientBuilder() {
        LOG.info("returning load balanced token webclient builder");
        return WebClient.builder();
    }

    @Bean("tokenWebClientBuilder")
    @Profile("local-https")
    public WebClient.Builder localHttpsTokenWebClientBuilder() {
        LOG.info("returning non-load-balanced token webclient builder for local-https profile");
        return WebClient.builder();
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
