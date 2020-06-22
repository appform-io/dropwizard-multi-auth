package io.appform.dropwizard.multiauth.model;

import io.dropwizard.util.Duration;
import lombok.val;

import java.util.Date;
import java.util.HashSet;
import java.util.Optional;
import java.util.UUID;
import java.util.function.UnaryOperator;

/**
 *
 */
public interface AuthStore {
    Optional<ServiceUser> provisionUser(final ServiceUser user);

    Optional<ServiceUser> getUser(final String userId);

    boolean deleteUser(final String id);

    boolean updateUser(final String id, UnaryOperator<ServiceUser> mutator);

    default boolean grantRole(final String userId, final String role) {
        return updateUser(userId, user -> {
            val roles = user.getRoles() == null
                        ? new HashSet<String>()
                        : user.getRoles();
            roles.add(role);
            return new ServiceUser(userId,
                                   roles,
                                   user.getCreated(),
                                   new Date());
        });
    }

    default boolean revokeRole(final String userId, final String role) {
        return updateUser(userId, user -> {
            val roles = user.getRoles() == null
                        ? new HashSet<String>()
                        : user.getRoles();
            roles.remove(role);
            return new ServiceUser(userId,
                                   roles,
                                   user.getCreated(),
                                   new Date());
        });
    }

    default Optional<Token> provisionToken(final String userId, Date expiry) {
        return provisionToken(userId, UUID.randomUUID().toString(), expiry);
    }

    Optional<Token> provisionToken(final String userId, String tokenId, Date expiry);

    Optional<Token> getToken(final String tokenId);

    boolean deleteToken(final String tokenId);

    boolean deleteExpiredTokens(Date date, Duration sessionDuration);
}
