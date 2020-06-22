package io.appform.dropwizard.multiauth.model;

import lombok.Value;

import java.util.Date;
import java.util.Set;

/**
 *
 */
@Value
public class ServiceUser {
    String id;
    Set<String> roles;
    Date created;
    Date updated;
}
