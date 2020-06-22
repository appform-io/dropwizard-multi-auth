package io.appform.dropwizard.multiauth.core;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeTokenRequest;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableSet;
import io.appform.dropwizard.multiauth.configs.AuthConfig;
import io.appform.dropwizard.multiauth.model.AuthStore;
import io.appform.dropwizard.multiauth.model.Token;
import io.dropwizard.util.Duration;
import lombok.extern.slf4j.Slf4j;
import lombok.val;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.Date;
import java.util.Optional;

/**
 *
 */
@Slf4j
@Singleton
public class GoogleAuthProvider implements AuthProvider {

    private final HttpTransport transport;
    private final GoogleAuthorizationCodeFlow authorizationCodeFlow;
    private final String redirectionUrl;
    private final AuthConfig authConfig;
    private final ObjectMapper mapper;
    private final AuthStore credentialsStorage;
    private final String callbackPath;

    @Inject
    public GoogleAuthProvider(
            AuthConfig authConfig,
            ObjectMapper mapper,
            AuthStore credentialsStorage,
            String callbackPath) {
        this.authConfig = authConfig;
        this.callbackPath = callbackPath;
        final NetHttpTransport.Builder transportBuilder = new NetHttpTransport.Builder();
        Proxy proxy = Proxy.NO_PROXY;
        val googleAuthConfig = authConfig.getProvider();
        if (googleAuthConfig.getProxyType() != null) {
            switch (googleAuthConfig.getProxyType()) {
                case DIRECT:
                    break;
                case HTTP: {
                    Preconditions.checkArgument(!Strings.isNullOrEmpty(googleAuthConfig.getProxyHost()));
                    proxy = new Proxy(Proxy.Type.HTTP,
                                      new InetSocketAddress(googleAuthConfig.getProxyHost(),
                                                            googleAuthConfig.getProxyPort()));
                    break;
                }
                case SOCKS:
                    Preconditions.checkArgument(!Strings.isNullOrEmpty(googleAuthConfig.getProxyHost()));
                    proxy = new Proxy(Proxy.Type.HTTP,
                                      new InetSocketAddress(googleAuthConfig.getProxyHost(),
                                                            googleAuthConfig.getProxyPort()));
                    break;
                default:
                    throw new IllegalStateException("Unexpected value: " + googleAuthConfig.getProxyType());
            }
        }
        this.transport = transportBuilder.setProxy(proxy)
                .build();
        this.authorizationCodeFlow = new GoogleAuthorizationCodeFlow.Builder(
                transport,
                new JacksonFactory(),
                googleAuthConfig.getClientId(),
                googleAuthConfig.getClientSecret(),
                ImmutableSet.of("https://www.googleapis.com/auth/userinfo.email"))
                .build();
        this.redirectionUrl = (googleAuthConfig.isSecureEndpoint()
                               ? "https"
                               : "http")
                + "://"
                + googleAuthConfig.getServer()
                + "/auth/google/callback";
        this.mapper = mapper;
        this.credentialsStorage = credentialsStorage;
    }

    @Override
    public String redirectionURL(String sessionId) {
        final String url = authorizationCodeFlow.newAuthorizationUrl()
                .setState(sessionId)
                .setRedirectUri(this.redirectionUrl)
//                .setRedirectUri("http://localhost:8080/auth/google")
                .build();
        val googleAuthConfig = authConfig.getProvider();
        return !Strings.isNullOrEmpty(googleAuthConfig.getLoginDomain())
               ? (url + "&hd=" + googleAuthConfig.getLoginDomain())
               : url;
    }

    @Override
    public Optional<Token> login(String authToken, String sessionId) {
        if (Strings.isNullOrEmpty(authToken)) {
            return Optional.empty();
        }
        final GoogleAuthorizationCodeTokenRequest googleAuthorizationCodeTokenRequest
                = authorizationCodeFlow.newTokenRequest(authToken);
        final String email;
        try {
            final GoogleTokenResponse tokenResponse = googleAuthorizationCodeTokenRequest
                    .setRedirectUri(this.redirectionUrl)
                    .execute();
            final Credential credential = authorizationCodeFlow.createAndStoreCredential(tokenResponse, null);
            final HttpRequestFactory requestFactory = transport.createRequestFactory(credential);
            // Make an authenticated request
            final GenericUrl url = new GenericUrl("https://www.googleapis.com/oauth2/v1/userinfo");
            final HttpRequest request = requestFactory.buildGetRequest(url);
            request.getHeaders().setContentType("application/json");
            final String jsonIdentity = request.execute().parseAsString();
            log.debug("Identity: {}", jsonIdentity);
            email = mapper.readTree(jsonIdentity).get("email").asText();
        }
        catch (IOException e) {
            log.error("Error logging in using google:", e);
            return Optional.empty();
        }
        val user = credentialsStorage.getUser(email)
                .orElse(null);
        if (null == user) {
            log.warn("No authorized user found for email: {}", email);
            return Optional.empty();
        }
        final Duration sessionDuration = Utils.sessionDuration(authConfig);
        return credentialsStorage.provisionToken(user.getId(),
                                                 sessionId,
                                                 new Date(new Date().getTime() + sessionDuration.toMilliseconds()));
    }

}
