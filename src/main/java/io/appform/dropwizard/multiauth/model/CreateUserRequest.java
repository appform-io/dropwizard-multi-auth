package io.appform.dropwizard.multiauth.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Value;
import org.hibernate.validator.constraints.NotEmpty;

import java.util.Set;

/**
 *
 */
@Value
public class CreateUserRequest {
    @NotEmpty
    String id;
    @NotEmpty
    Set<String> roles;

    public CreateUserRequest(@JsonProperty("id") String id, @JsonProperty("roles") Set<String> roles) {
        this.id = id;
        this.roles = roles;
    }
}
