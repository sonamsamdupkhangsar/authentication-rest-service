package me.sonam.authentication.handler;

import java.util.UUID;

/**
 * this is for parsing the data from serverrequest body to this object
 */
public class AuthenticationPassword {
    private String authenticationId;
    private String password;
    private String clientId;
    private UUID organizationId;

    public AuthenticationPassword() {

    }
    public AuthenticationPassword(String authenticationId, String password, String clientId) {
        this.authenticationId = authenticationId;
        this.password = password;
        this.clientId = clientId;
    }

    public void setOrganizationId(UUID organizationId) {
        this.organizationId = organizationId;
    }

    public String getAuthenticationId() {
        return authenticationId;
    }
    public UUID getOrganizationId() {
        return this.organizationId;
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
    public String getClientId() {
        return this.clientId;
    }

}
