package io.appform.dropwizard.multiauth.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Value;

import java.security.Principal;

/**
 *
 */
@Value
public class ServiceUserPrincipal implements Principal {

    ServiceUser user;
    Token token;

    @Override
    @JsonIgnore
    public String getName() {
        return user.getId();
    }
}
