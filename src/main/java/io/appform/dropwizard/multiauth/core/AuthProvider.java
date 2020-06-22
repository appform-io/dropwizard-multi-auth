package io.appform.dropwizard.multiauth.core;

import io.appform.dropwizard.multiauth.model.Token;

import java.util.Optional;

/**
 *
 */
public interface AuthProvider {

    String redirectionURL(String sessionId);

    Optional<Token> login(String authCode, String sessionId);
}
