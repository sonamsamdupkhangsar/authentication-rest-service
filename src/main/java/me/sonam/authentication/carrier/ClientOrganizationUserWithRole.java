package me.sonam.authentication.carrier;

import java.util.Objects;
import java.util.UUID;

public class ClientOrganizationUserWithRole {
    private UUID id; //row id
    private UUID clientId;
    private UUID organizationId;
    private User user;

    public ClientOrganizationUserWithRole(UUID id, UUID clientId, UUID organizationId, User user) {
        this.id = id;
        this.clientId = clientId;
        this.organizationId = organizationId;
        this.user = user;
    }

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public UUID getClientId() {
        return clientId;
    }

    public void setClientId(UUID clientId) {
        this.clientId = clientId;
    }

    public UUID getOrganizationId() {
        return organizationId;
    }

    public void setOrganizationId(UUID organizationId) {
        this.organizationId = organizationId;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public ClientOrganizationUserWithRole() {
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ClientOrganizationUserWithRole that = (ClientOrganizationUserWithRole) o;
        return Objects.equals(clientId, that.clientId) && Objects.equals(organizationId, that.organizationId) && Objects.equals(user, that.user);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clientId, organizationId, user);
    }

    @Override
    public String toString() {
        return "ClientOrganziationUserWithRole{" +
                "clientId=" + clientId +
                ", organizationId=" + organizationId +
                ", user=" + user +
                '}';
    }
}
