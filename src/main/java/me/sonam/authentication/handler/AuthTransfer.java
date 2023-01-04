package me.sonam.authentication.handler;

import java.util.UUID;

/**
 * this is for parsing the data from serverrequest body to this object
 */
public class AuthTransfer {
    private String authenticationId;
    private String password;
    private UUID userId;

    public AuthTransfer() {

    }
    public AuthTransfer(String authenticationId, String password, UUID userId) {
        this.authenticationId = authenticationId;
        this.password = password;
        this.userId = userId;
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
        return this.userId;
    }

}
