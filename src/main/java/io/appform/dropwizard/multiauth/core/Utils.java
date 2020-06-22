package io.appform.dropwizard.multiauth.core;

import io.appform.dropwizard.multiauth.configs.AuthConfig;
import io.appform.dropwizard.multiauth.configs.JwtConfig;
import io.appform.dropwizard.multiauth.model.Token;
import io.dropwizard.util.Duration;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.HmacKey;

import java.nio.charset.StandardCharsets;

/**
 *
 */
@UtilityClass
public class Utils {

    @SneakyThrows
    public static String createJWT(final Token token, final JwtConfig jwtConfig) {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(jwtConfig.getIssuerId());
        claims.setGeneratedJwtId();
        claims.setIssuedAtToNow();
        claims.setJwtId(token.getId());
        claims.setNotBeforeMinutesInThePast(2);
        claims.setSubject(token.getUserId());
        claims.setAudience(jwtConfig.getServiceName());

        if(null != token.getExpiry()) {
            claims.setExpirationTime(NumericDate.fromMilliseconds(token.getExpiry().getTime()));
        }
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        final byte[] secretKey = jwtConfig.getPrivateKey().getBytes(StandardCharsets.UTF_8);
        jws.setKey(new HmacKey(secretKey));
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA512);
        return jws.getCompactSerialization();
    }

    public static Duration sessionDuration(AuthConfig authConfig) {
        final Duration dynamicSessionDuration = authConfig.getJwt().getSessionDuration();
        return dynamicSessionDuration != null
               ? dynamicSessionDuration
               : Duration.days(30);
    }
}
