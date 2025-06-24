package me.sonam.authentication.repo;


import me.sonam.authentication.repo.entity.Authentication;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface AuthenticationRepository extends ReactiveCrudRepository<Authentication, String> {
    Mono<Integer> deleteByUserId(UUID userId);
    Mono<Void> deleteByAuthenticationIdIgnoreCase(String authenticationId);
    Mono<Authentication> findByUserId(UUID userId);
    Mono<Boolean> existsByAuthenticationIdIgnoreCase(String authenticationId);
    Mono<Authentication> findByAuthenticationIdIgnoreCase(String authenticationId);
    Mono<Integer> deleteByAuthenticationIdIgnoreCaseAndActiveFalse(String authenticationId);
    Mono<Boolean> existsByIdAndActiveTrue(String var1);
    Mono<Boolean> existsByAuthenticationIdIgnoreCaseAndActiveTrue(String authenticationId);
    Mono<Authentication> findByAuthenticationIdIgnoreCaseAndPassword(String authenticationId, String password);

    @Query("update authentication set password= :password where lower(authentication_Id) = lower(:authenticationId)")
    Mono<Integer> updatePassword(@Param("authenticationId") String authenticationId, @Param("password") String password);

    @Query("update authentication a set a.role_id= :roleId where lower(a.authentication_Id) = lower(:authenticationId)")
    Mono<Integer> updateRoleId(@Param("roleId") UUID roleId, @Param("authenticationId") String authenticationId);

    @Query("update authentication set active=true where lower(authentication_Id) = lower(:authenticationId)")
    Mono<Integer> updateAuthenticationActiveTrue(@Param("authenticationId") String authenticationId);

}
