package io.appform.dropwizard.multiauth.configs;

import com.google.common.annotations.VisibleForTesting;
import io.dropwizard.util.Duration;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.validator.constraints.NotEmpty;

/**
 *
 */
@Data
@NoArgsConstructor
public class JwtConfig {
    @NotEmpty
    private String privateKey;

    @NotEmpty
    private String issuerId;

    @NotEmpty
    private String serviceName;

    @NotEmpty
    private String authCachePolicy = "maximumSize=10000, expireAfterAccess=10m";

    private Duration sessionDuration = Duration.days(30);

    @VisibleForTesting
    public JwtConfig(String privateKey, String issuerId) {
        this.privateKey = privateKey;
        this.issuerId = issuerId;
    }
}
