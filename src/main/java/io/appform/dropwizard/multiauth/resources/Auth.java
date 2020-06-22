package io.appform.dropwizard.multiauth.resources;


import com.google.common.base.Strings;
import io.appform.dropwizard.multiauth.configs.AuthConfig;
import io.appform.dropwizard.multiauth.core.AuthProvider;
import io.appform.dropwizard.multiauth.core.GoogleAuthProvider;
import io.appform.dropwizard.multiauth.core.Utils;
import io.appform.dropwizard.multiauth.model.AuthStore;
import io.appform.dropwizard.multiauth.model.CreateUserRequest;
import io.appform.dropwizard.multiauth.model.ServiceUser;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.hibernate.validator.constraints.NotEmpty;

import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import java.net.URI;
import java.util.Collections;
import java.util.Date;
import java.util.UUID;

/**
 *
 */
@Path("/auth")
@Slf4j
public class Auth {

    private final AuthConfig authConfig;
    private final AuthProvider authProvider;
    private final AuthStore authStore;

    @Inject
    public Auth(AuthConfig authConfig, GoogleAuthProvider authProvider, AuthStore authStore) {
        this.authConfig = authConfig;
        this.authProvider = authProvider;
        this.authStore = authStore;
    }

    @GET
    @Path("/google/login")
    public Response login(@CookieParam("redirection") final Cookie cookieReferrer,
                          @HeaderParam("Referer") final String referrer) {
        final String sessionId = UUID.randomUUID().toString();
        final String redirectionURL = authProvider.redirectionURL(sessionId);
        log.debug("Redirection uri: {}", redirectionURL);
        final String cookieReferrerUrl = null == cookieReferrer ? null : cookieReferrer.getValue();
        val source = Strings.isNullOrEmpty(cookieReferrerUrl) ? referrer : cookieReferrerUrl;
        log.debug("Call source: {} Referrer: {} Redirection: {}", source, referrer, cookieReferrerUrl);
        if(!Strings.isNullOrEmpty(source)) {
            log.debug("Saved: {} against session: {}", source, sessionId);
        }
        return Response.seeOther(URI.create(redirectionURL))
                .cookie(new NewCookie(
                                "gauth-state",
                                sessionId,
                                "/auth/google/callback",
                                null,
                                NewCookie.DEFAULT_VERSION,
                                null,
                                NewCookie.DEFAULT_MAX_AGE,
                                null,
                                false,
                                false))
                .build();
    }

    @GET
    @Path("/google/callback")
    public Response handleGoogleCallback(
            @CookieParam("gauth-state") final Cookie cookieState,
            @Context HttpServletRequest requestContext,
            @QueryParam("state") final String sessionId,
            @QueryParam("code") final String authCode) {
        log.info("Request Ctx: {}", requestContext);
        if (null == cookieState
                || !cookieState.getValue().equals(sessionId)) {
            return Response.seeOther(URI.create("/"))
                    .cookie(new NewCookie(cookieState, null, 0, false))
                    .build();
        }
        val token = authProvider.login(authCode, sessionId).orElse(null);
        if (null == token) {
            return Response.seeOther(URI.create("/auth/google/login")).build();
        }
        return Response.seeOther(URI.create("/"))
                .cookie(new NewCookie("token",
                                      Utils.createJWT(token, authConfig.getJwt()),
                                      "/",
                                      null,
                                      Cookie.DEFAULT_VERSION,
                                      null,
                                      NewCookie.DEFAULT_MAX_AGE,
                                      null,
                                      false,
                                      true),
                        new NewCookie(cookieState, null, 0, false))
                .build();
    }

    @POST
    @Path("logout")
    public Response logout(@CookieParam("token") final Cookie token) {
        if(null == token) {
            log.warn("No cookie found");
            return Response.seeOther(URI.create("/"))
                    .build();
        }
        log.info("Deleting cookie for user...");
        return Response.seeOther(URI.create("/"))
                .cookie(new NewCookie("token",
                                      "",
                                      "/",
                                      null,
                                      Cookie.DEFAULT_VERSION,
                                      null,
                                      NewCookie.DEFAULT_MAX_AGE,
                                      null,
                                      false,
                                      true))
                .build();

    }

    @POST
    @Path("/users")
    @RolesAllowed("AUTH_MANAGEMENT")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response provisionUser(@NotNull @Valid final CreateUserRequest createUserRequest) {
        val user = new ServiceUser(createUserRequest.getId(), createUserRequest.getRoles(), new Date(), new Date());
        return Response.ok(authStore.provisionUser(user)).build();
    }

    @GET
    @Path("/users/{userId}")
    @PermitAll
    @Produces(MediaType.APPLICATION_JSON)
    public Response getUser(@NotNull @NotEmpty @PathParam("userId") final String userId) {
        return Response.ok(authStore.getUser(userId)).build();
    }

    @PUT
    @Path("/users/{userId}/roles/grant/{role}")
    @RolesAllowed("AUTH_MANAGEMENT")
    @Produces(MediaType.APPLICATION_JSON)
    public Response grantRole(@NotNull @NotEmpty @PathParam("userId") final String userId,
                              @NotNull @PathParam("role") final String role) {
        val status = authStore.grantRole(userId, role);
        return updateUserResponse(userId, status);
    }

    @PUT
    @Path("/users/{userId}/roles/revoke/{role}")
    @RolesAllowed("AUTH_MANAGEMENT")
    @Produces(MediaType.APPLICATION_JSON)
    public Response revokeRole(@NotNull @NotEmpty @PathParam("userId") final String userId,
                               @NotNull @PathParam("role") final String role) {
        val status = authStore.revokeRole(userId, role);
        return updateUserResponse(userId, status);
    }

    @POST
    @Path("/tokens/{userId}")
    @RolesAllowed("AUTH_MANAGEMENT")
    @Produces(MediaType.APPLICATION_JSON)
    public Response provisionToken(@NotNull @NotEmpty @PathParam("userId") final String userId) {
        val token = authStore.provisionToken(userId,null).orElse(null);
        if(null == token) {
            return Response.notModified().build();
        }
        return Response
                .ok(Collections.singletonMap("jwt", Utils.createJWT(token, authConfig.getJwt())))
                .build();
    }

    @GET
    @Path("/tokens/{tokenId}")
    @PermitAll
    @Produces(MediaType.APPLICATION_JSON)
    public Response getToken(@NotNull @NotEmpty @PathParam("tokenId") final String tokenId) {
        return Response.ok(authStore.getToken(tokenId))
                .build();
    }

    @DELETE
    @Path("/tokens/{userId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response deleteToken(@NotNull @NotEmpty @PathParam("userId") final String userId,
                                @NotNull @NotEmpty @PathParam("tokenId") final String tokenId) {
        val status = authStore.deleteToken(tokenId);
        if(!status) {
            return Response.notModified().build();
        }
        return Response.ok().build();
    }

    private Response updateUserResponse(String userId, boolean status) {
        if (!status) {
            return Response.notModified()
                    .build();
        }
        return Response.ok()
                .entity(authStore.getUser(userId))
                .build();
    }

}
