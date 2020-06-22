package io.appform.dropwizard.multiauth.configs;

import lombok.Data;
import org.hibernate.validator.constraints.NotEmpty;

import javax.validation.constraints.NotNull;
import java.net.Proxy;

/**
 *
 */
@Data
public class MultiAuthConfig {
    private boolean enabled;
    @NotEmpty
    private String clientId;

    @NotEmpty
    @NotNull
    private String clientSecret;

    private String loginDomain;

    @NotNull
    @NotEmpty
    private String server;

    @NotNull
    private boolean secureEndpoint;

    private Proxy.Type proxyType;

    private String proxyHost;

    private int proxyPort;
}
