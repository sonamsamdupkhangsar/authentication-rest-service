package me.sonam.authentication.carrier;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;

import java.util.Objects;
import java.util.UUID;

/**
 * Roles are associated to a organizationId
 */
public class Role {

    private UUID id;
    private String name;

    private UUID userId;
    @Transient
    private boolean isNew;


    public Role() {}
    public Role(UUID id, String name, UUID userId) {
        if (id != null) {
            this.id = id;
            this.isNew = false;
        }
        else {
            this.id = UUID.randomUUID();
            this.isNew = true;
        }
        this.name = name;
        this.userId = userId;
    }
    public String getName() {
        return this.name;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public void setName(String name) {
        this.name = name;
    }

    public UUID getUserId() {
        return userId;
    }

    public void setUserId(UUID userId) {
        this.userId = userId;
    }

    @Override
    public String toString() {
        return "Role{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", userId=" + userId +
                ", isNew=" + isNew +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Role role = (Role) o;
        return Objects.equals(id, role.id) && Objects.equals(name, role.name) && Objects.equals(userId, role.userId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, name, userId);
    }
}
