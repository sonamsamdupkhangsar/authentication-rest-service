package me.sonam.authentication.handler;

import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
import java.util.UUID;

public interface AuthenticationService {
    /**
     * this service will authenticate username/password with apikey
     * @param authTransferMono contains the usernam,password
     * @return
     */
    // no jwt required
    Mono<Map<String, String>> authenticate(Mono<AuthenticationPassword> authTransferMono);
    // no jwt required
    Mono<String> createAuthentication(Mono<AuthTransfer> authTransferMono);
    // internal
    Mono<String> activateAuthentication(String authenticationId);
    // requires jwt
    Mono<String> updatePassword(String authenticationId, String password);
    // requires jwt
    Mono<String> delete();
    Mono<String> deleteByAuthenticationId(String authenticationId);
}
