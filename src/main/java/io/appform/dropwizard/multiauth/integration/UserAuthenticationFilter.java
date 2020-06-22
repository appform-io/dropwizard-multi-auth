package io.appform.dropwizard.multiauth.integration;


import com.google.common.base.Strings;
import io.appform.dropwizard.multiauth.configs.AuthConfig;
import io.appform.dropwizard.multiauth.core.TokenAuthenticator;
import io.appform.dropwizard.multiauth.model.ServiceUserPrincipal;
import io.dropwizard.auth.AuthenticationException;
import io.dropwizard.auth.Authenticator;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.keys.HmacKey;

import javax.annotation.Priority;
import javax.inject.Inject;
import javax.inject.Singleton;
import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Priorities;
import javax.ws.rs.core.HttpHeaders;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * This filter validates the token
 */
@Priority(Priorities.AUTHENTICATION)
@WebFilter("/*")
@Slf4j
@Singleton
public class UserAuthenticationFilter implements Filter {

    private final AuthConfig authConfig;
    private final JwtConsumer consumer;
    private final Authenticator<JwtContext, ServiceUserPrincipal> authenticator;
    private final List<String> allowedPatterns;

    @Inject
    public UserAuthenticationFilter(
            AuthConfig authConfig,
            TokenAuthenticator authenticator,
            List<String> allowedPatterns) {
        this.authConfig = authConfig;
        this.consumer = buildConsumer(authConfig);
        this.authenticator = authenticator;
        this.allowedPatterns = allowedPatterns;
    }

    @Override
    public void init(FilterConfig filterConfig) {

    }

    @Override
    public void doFilter(
            ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if(!authConfig.isEnabled()) {
            log.trace("Auth disabled");
            chain.doFilter(request, response);
            return;
        }
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        final String requestURI = httpRequest.getRequestURI();
        if(allowedPatterns.stream().anyMatch(requestURI::startsWith) || requestURI.startsWith("/auth/google")) {
            chain.doFilter(request, response);
            return;
        }
        val jwt = getTokenFromCookieOrHeader(httpRequest).orElse(null);
        if(null != jwt) {
            try {
                final JwtContext context = consumer.process(jwt);
                val principal = authenticator.authenticate(context).orElse(null);
                if(null != principal) {
                    SessionUser.put(principal);
                    chain.doFilter(request, response);
                    return;
                }
            }
            catch (InvalidJwtException | AuthenticationException e) {
                log.error("Jwt validation failure: ", e);
            }
        }
        val referrer = httpRequest.getHeader("Referer");
        val source = Strings.isNullOrEmpty(referrer) ? requestURI : referrer;
        httpResponse.addCookie(new Cookie("redirection", source));
        httpResponse.sendRedirect("/auth/google/login");
    }

    @Override
    public void destroy() {

    }

    private Optional<String> getTokenFromCookieOrHeader(HttpServletRequest servletRequest) {
        val tokenFromHeader = getTokenFromHeader(servletRequest);
        return tokenFromHeader.isPresent() ? tokenFromHeader : getTokenFromCookie(servletRequest);
    }

    private Optional<String> getTokenFromHeader(HttpServletRequest servletRequest) {
        val header = servletRequest.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null) {
            int space = header.indexOf(' ');
            if (space > 0) {
                final String method = header.substring(0, space);
                if ("Bearer".equalsIgnoreCase(method)) {
                    final String rawToken = header.substring(space + 1);
                    return Optional.of(rawToken);
                }
            }
        }
        return Optional.empty();
    }

    private Optional<String> getTokenFromCookie(HttpServletRequest request) {
        val cookies = request.getCookies();
        if(null != cookies && cookies.length != 0) {
            val token = Arrays.stream(cookies).filter(cookie -> cookie.getName().equals("token")).findAny().orElse(null);
            if(null != token) {
                return Optional.of(token.getValue());
            }
        }
        return Optional.empty();
    }

    private JwtConsumer buildConsumer(AuthConfig authConfig) {
        val jwtConfig = authConfig.getJwt();
        final byte[] secretKey = jwtConfig.getPrivateKey().getBytes(StandardCharsets.UTF_8);
        return new JwtConsumerBuilder()
                .setRequireIssuedAt()
                .setRequireSubject()
                .setExpectedIssuer(jwtConfig.getIssuerId())
                .setVerificationKey(new HmacKey(secretKey))
                .setJwsAlgorithmConstraints(new AlgorithmConstraints(
                        AlgorithmConstraints.ConstraintType.WHITELIST,
                        AlgorithmIdentifiers.HMAC_SHA512))
                .setExpectedAudience(jwtConfig.getServiceName())
                .build();
    }
}
