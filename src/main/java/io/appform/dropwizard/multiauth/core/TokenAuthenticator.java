package io.appform.dropwizard.multiauth.core;

import io.appform.dropwizard.multiauth.model.AuthStore;
import io.appform.dropwizard.multiauth.model.DefaultHandler;
import io.appform.dropwizard.multiauth.model.ServiceUserPrincipal;
import io.appform.dropwizard.multiauth.configs.AuthConfig;
import io.dropwizard.auth.Authenticator;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.JwtContext;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.util.Optional;

/**
 * Authenticator that will be run
 */
@Slf4j
@Singleton
public class TokenAuthenticator implements Authenticator<JwtContext, ServiceUserPrincipal> {

    private final AuthConfig config;
    private final AuthStore authStore;
    private final DefaultHandler defaultHandler;

    @Inject
    public TokenAuthenticator(
            AuthConfig config,
            final AuthStore authStore,
            final DefaultHandler defaultHandler) {
        this.config = config;
        this.authStore = authStore;
        this.defaultHandler = defaultHandler;
    }

    @Override
    public Optional<ServiceUserPrincipal> authenticate(JwtContext jwtContext) {
        if(!config.isEnabled()) {
            log.debug("Authentication is disabled");
            return defaultHandler.defaultUser();
        }
        log.debug("Auth called");
        final String userId;
        final String tokenId;
        final String serviceName;
        try {
            val claims = jwtContext.getJwtClaims();
            userId = claims.getSubject();
            tokenId = claims.getJwtId();
            serviceName = claims.getAudience().get(0);
        }
        catch (MalformedClaimException e) {
            log.error(String.format("exception in claim extraction %s", e.getMessage()), e);
            return Optional.empty();
        }
        log.debug("authentication_requested userId:{} tokenId:{}", userId, tokenId);
        val token = authStore.getToken(tokenId).orElse(null);
        if (token == null) {
            log.warn("authentication_failed::invalid_session userId:{} tokenId:{}", userId, tokenId);
            return Optional.empty();
        }
        if (!token.getUserId().equals(userId)) {
            log.warn("authentication_failed::user_mismatch userId:{} tokenId:{}", userId, tokenId);
            return Optional.empty();
        }
        val user = authStore.getUser(token.getUserId()).orElse(null);
        if (null == user) {
            log.warn("authentication_failed::invalid_user userId:{} tokenId:{}", userId, tokenId);
            return Optional.empty();
        }
        val expectedServiceName = config.getJwt().getServiceName();
        if(!serviceName.equals(expectedServiceName)) {
            log.warn("authentication_failed::invalid_audience audience provided: {} userid: {} expected: {}",
                     serviceName, userId, expectedServiceName);
            return Optional.empty();
        }
        log.debug("authentication_success userId:{} tokenId:{}", userId, tokenId);
        return Optional.of(new ServiceUserPrincipal(user, token));
    }
}
