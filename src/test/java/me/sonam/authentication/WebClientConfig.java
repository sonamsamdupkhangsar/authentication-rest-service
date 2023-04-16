package me.sonam.authentication;

import me.sonam.authentication.handler.SimpleAuthenticationService;
import me.sonam.security.headerfilter.ReactiveRequestContextHolder;
import me.sonam.security.jwt.PublicKeyJwtDecoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.web.reactive.function.client.WebClient;

@Profile("localdevtest")
@Configuration
public class WebClientConfig {
    private static final Logger LOG = LoggerFactory.getLogger(WebClientConfig.class);
    @Bean
    public WebClient.Builder webClientBuilder() {
        LOG.info("returning load balanced webclient part 2");
        return WebClient.builder();
    }
    @Bean
    public PublicKeyJwtDecoder publicKeyJwtDecoder() {
        return new PublicKeyJwtDecoder(webClientBuilder());
    }

    @Bean
    public ReactiveRequestContextHolder reactiveRequestContextHolder() {
        return new ReactiveRequestContextHolder(webClientBuilder());
    }

    @Bean
    public SimpleAuthenticationService userAccountService() {
        return new SimpleAuthenticationService(webClientBuilder());
    }
}
