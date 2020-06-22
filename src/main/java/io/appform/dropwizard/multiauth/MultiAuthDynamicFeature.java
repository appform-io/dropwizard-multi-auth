package io.appform.dropwizard.multiauth;


import com.google.common.cache.CacheBuilderSpec;
import io.appform.dropwizard.multiauth.configs.AuthConfig;
import io.appform.dropwizard.multiauth.core.RoleAuthorizer;
import io.appform.dropwizard.multiauth.integration.UserAuthorizationFilter;
import io.appform.dropwizard.multiauth.model.DefaultHandler;
import io.appform.dropwizard.multiauth.model.ServiceUserPrincipal;
import io.dropwizard.auth.AuthDynamicFeature;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.auth.CachingAuthorizer;
import io.dropwizard.setup.Environment;
import org.glassfish.jersey.server.filter.RolesAllowedDynamicFeature;

import javax.inject.Inject;
import javax.ws.rs.ext.Provider;

/**
 *
 */
@Provider
public class MultiAuthDynamicFeature extends AuthDynamicFeature {

    @Inject
    public MultiAuthDynamicFeature(
            Environment environment,
            AuthConfig authConfig,
            DefaultHandler defaultHandler) {
        super(new UserAuthorizationFilter(
                authConfig,
                new CachingAuthorizer<>(environment.metrics(),
                                        new RoleAuthorizer(),
                                        CacheBuilderSpec.parse(authConfig.getJwt().getAuthCachePolicy())),
                defaultHandler));
        environment.jersey().register(new AuthValueFactoryProvider.Binder<>(ServiceUserPrincipal.class));
        environment.jersey().register(RolesAllowedDynamicFeature.class);
    }
}
