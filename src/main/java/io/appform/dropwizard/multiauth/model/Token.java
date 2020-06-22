package io.appform.dropwizard.multiauth.model;

import lombok.Value;

import java.util.Date;

/**
 *
 */
@Value
public class Token {
    public static final Token DEFAULT = new Token("__DEFAULT_TOKEN__", "__DEFAULT__", null);

    String id;
    String userId;
    Date expiry;
}
