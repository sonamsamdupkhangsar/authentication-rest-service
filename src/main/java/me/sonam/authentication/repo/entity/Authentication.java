package me.sonam.authentication.repo.entity;


import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * represents a Account record in Account table.
 */
public class Authentication implements Persistable<String> {
    @Id
    private String authenticationId;
    private String password;
    private UUID userId;
    private UUID signinSourceId;
    private Boolean active;
    private LocalDateTime accessDateTime;

    @Transient
    private boolean isNew;

    public Authentication() {
    }

    public Authentication(String authenticationId, String password, UUID userId,
                          UUID signinSourceId, Boolean active, LocalDateTime accessDateTime, boolean isNew) {
        this.authenticationId = authenticationId;
        this.password = password;
        this.userId = userId;
        this.signinSourceId = signinSourceId;
        this.active = active;
        this.accessDateTime = accessDateTime;
        this.isNew = isNew;
    }

    @Override
    public String getId() {
        return authenticationId;
    }

    @Override
    public boolean isNew() {
        return isNew;
    }

    public String getAuthenticationId() {
        return authenticationId;
    }

    public void setAuthenticationId(String authenticationId) {
        this.authenticationId = authenticationId;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public UUID getUserId() {
        return userId;
    }

    public void setUserId(UUID userId) {
        this.userId = userId;
    }

    public UUID getSigninSourceId() {
        return signinSourceId;
    }

    public void setSigninSourceId(UUID signinSourceId) {
        this.signinSourceId = signinSourceId;
    }

    public Boolean getActive() {
        return active;
    }

    public void setActive(Boolean active) {
        this.active = active;
    }

    public LocalDateTime getAccessDateTime() {
        return accessDateTime;
    }

    public void setAccessDateTime(LocalDateTime accessDateTime) {
        this.accessDateTime = accessDateTime;
    }

    public void setNew(boolean aNew) {
        isNew = aNew;
    }

    @Override
    public String toString() {
        return "Authentication{" +
                "authenticationId='" + authenticationId + '\'' +
                ", password='" + password + '\'' +
                ", userId=" + userId +
                ", signinSourceId=" + signinSourceId +
                ", active=" + active +
                ", accessDateTime=" + accessDateTime +
                ", isNew=" + isNew +
                '}';
    }
}