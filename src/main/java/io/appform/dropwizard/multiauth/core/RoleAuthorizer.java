package io.appform.dropwizard.multiauth.core;

import io.appform.dropwizard.multiauth.model.ServiceUserPrincipal;
import io.dropwizard.auth.Authorizer;
import lombok.extern.slf4j.Slf4j;
import lombok.val;

import javax.inject.Singleton;

/**
 *
 */
@Singleton
@Slf4j
public class RoleAuthorizer implements Authorizer<ServiceUserPrincipal> {
    @Override
    public boolean authorize(ServiceUserPrincipal userPrincipal, String role) {
        val user = userPrincipal.getUser();

        if(!user.getRoles().contains(role)) {
            log.warn("User {} is trying to access unauthorized role: {}", user.getId(), role);
            return false;
        }
        return true;
    }
}
