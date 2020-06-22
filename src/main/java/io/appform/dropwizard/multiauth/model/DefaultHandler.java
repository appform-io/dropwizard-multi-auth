package io.appform.dropwizard.multiauth.model;

import java.util.Optional;

/**
 *
 */
public interface DefaultHandler {
    Optional<ServiceUserPrincipal> defaultUser();
}
