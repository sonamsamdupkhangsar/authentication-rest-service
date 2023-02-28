package me.sonam.authentication.handler;

import java.util.UUID;

/**
 * this is for parsing the data from serverrequest body to this object
 */
public class AuthenticationPassword {
    private String authenticationId;
    private String password;
    private String clientId;

    public AuthenticationPassword() {

    }
    public AuthenticationPassword(String authenticationId, String password, String clientId) {
        this.authenticationId = authenticationId;
        this.password = password;
        this.clientId = clientId;
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
    public String getClientId() {
        return this.clientId;
    }

}
