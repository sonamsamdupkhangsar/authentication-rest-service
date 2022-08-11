package me.sonam.authentication.handler;

import reactor.core.publisher.Mono;

import java.util.UUID;

public interface AuthenticationService {
    /**
     * this service will authenticate username/password with apikey
     * @param authTransferMono contains the usernam,password
     * @return
     */
    // no jwt required
    Mono<String> authenticate(Mono<AuthTransfer> authTransferMono);
    // no jwt required
    Mono<String> createAuthentication(Mono<AuthTransfer> authTransferMono);
    // requires jwt
    Mono<String> updatePassword(Mono<String> passwordMono, String authenticationId);
    // requires jwt
    Mono<String> updateRoleId(Mono<String> uuidString, String authenticationId);
}
