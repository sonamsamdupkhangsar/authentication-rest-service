package me.sonam.authentication.handler;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.UUID;

/**
 * this is for parsing the data from serverrequest body to this object
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class AuthTransfer {
    @JsonProperty("authenticationId")
    private String authenticationId;
    @JsonProperty("password")
    private String password;
    @JsonProperty("userId")
    private UUID userId;
    @JsonProperty("clientId")
    private String clientId;
    @JsonProperty("organizationId")
    private UUID organizationId;
    @JsonProperty("active")
    private boolean active;

    public AuthTransfer() {

    }
    public AuthTransfer(String authenticationId, String password, UUID userId, String clientId, boolean active) {
        if (authenticationId != null) {
            this.authenticationId = authenticationId.toLowerCase();
        }
        this.password = password;
        this.userId = userId;
        this.clientId = clientId;
        this.active = active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public UUID getOrganizationId() {
        return organizationId;
    }

    public void setOrganizationId(UUID organizationId) {
        this.organizationId = organizationId;
    }

    public String getAuthenticationId() {
        return authenticationId.toLowerCase();
    }

    public void setAuthenticationId(String authenticationId) {
        if (authenticationId != null) {
            this.authenticationId = authenticationId.toLowerCase();
        }
    }
    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public void setUserId(UUID userId) {
        this.userId = userId;
    }
    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public UUID getUserId() {
        return this.userId;
    }

    public String getClientId() {
        return this.clientId;
    }
    public boolean isActive() {
        return this.active;
    }

}
