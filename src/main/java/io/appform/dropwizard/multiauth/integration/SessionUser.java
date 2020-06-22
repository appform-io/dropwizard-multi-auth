package io.appform.dropwizard.multiauth.integration;

import io.appform.dropwizard.multiauth.model.ServiceUserPrincipal;
import lombok.Builder;
import lombok.Data;
import lombok.val;

import java.io.Serializable;

/**
 *
 */
@Data
@Builder
public class SessionUser implements Serializable {
    private static final long serialVersionUID = -7917711435258380077L;

    private final ServiceUserPrincipal user;

    private static ThreadLocal<ServiceUserPrincipal> currentUser = new ThreadLocal<>();

    public static void put(ServiceUserPrincipal user) {
        currentUser.set(user);
    }

    public static ServiceUserPrincipal take() {
        val user = currentUser.get();
        currentUser.remove();
        return user;
    }

}
