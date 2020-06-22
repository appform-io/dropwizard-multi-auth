package io.appform.dropwizard.multiauth.configs;

import lombok.Data;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

/**
 *
 */
@Data
public class AuthConfig {
    private boolean enabled;

    @NotNull
    @Valid
    private JwtConfig jwt = new JwtConfig();

    @NotNull
    @Valid
    private MultiAuthConfig provider = new MultiAuthConfig();
}
