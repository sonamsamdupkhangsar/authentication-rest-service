package me.sonam.authentication.handler;

import java.util.UUID;

/**
 * this is for parsing the data from serverrequest body to this object
 */
public class AuthTransfer {
    private String authenticationId;
    private String password;
    private UUID userId;

    private String clientId;
    private UUID organizationId;
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
