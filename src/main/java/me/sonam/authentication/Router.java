package me.sonam.authentication;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import me.sonam.authentication.handler.AuthenticationHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springdoc.core.annotations.RouterOperation;
import org.springdoc.core.annotations.RouterOperations;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;

import static org.springframework.web.reactive.function.server.RequestPredicates.*;

/**
 * Set AccountService methods route for checking active and to actiate acccount
 */
@Configuration
public class Router {
    private static final Logger LOG = LoggerFactory.getLogger(Router.class);

    @Bean
    public RouterFunction<ServerResponse> route(AuthenticationHandler handler) {
        LOG.info("building authenticate router function");
        return RouterFunctions.route(POST("/authentications/authenticate").and(accept(MediaType.APPLICATION_JSON)),
                handler::authenticate)
                .andRoute(POST("/authentications").and(accept(MediaType.APPLICATION_JSON)),
                        handler::createAuthentication)
                .andRoute(PUT("/authentications/activate/{authenticationId}").and(accept(MediaType.APPLICATION_JSON)),
                        handler::activateAuthentication)
                .andRoute(PUT("/authentications/password").and(accept(MediaType.APPLICATION_JSON)),
                        handler::updatePassword)
                .andRoute(DELETE("/authentications").and(accept(MediaType.APPLICATION_JSON)),
                        handler::delete);
    }
}
