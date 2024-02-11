package corp.mkdev.jwt.validator;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.LinkedHashSet;
import java.util.Set;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * Utility class for handling JSON Web Key Set (JWKS) operations.
 *
 * <p>This class provides functionality to fetch and cache public keys from a JWKS endpoint.
 * It is designed to be used in conjunction with JWT (JSON Web Token) validation processes.
 *
 */
public class JwksUtils {

    private final JwksKeySelector<SecurityContext> keySelector;

    /**
     * Returns a set of default JSON Web Signature (JWS) algorithms.
     */
    public static Set<JWSAlgorithm> getDefaultJWSAlgorithms() {
        final Set<JWSAlgorithm> ret = new LinkedHashSet<>();
        ret.add(JWSAlgorithm.EdDSA);
        ret.add(JWSAlgorithm.RS256);
        return ret;
    }

    /**
     * Returns a default JSON Web Key (JWK) source configured with the provided JWKS (JSON Web Key Set) endpoint URL.

     * @param jwksUrl The URL pointing to the JWKS endpoint.
     * @return A JWK source configured with the provided JWKS URL.
     *
     */
    public static JWKSource<SecurityContext> getDefaultJWKSource(final URL jwksUrl) {
        return JWKSourceBuilder
                .create(jwksUrl)
                .build();
    }

    /**
     * Constructs a JwksUtils instance using the provided JWKS endpoint URL.
     *
     * @param jwksUrl The URL pointing to the JWKS endpoint.
     * @throws MalformedURLException If there is an issue parsing the jwksUrl.
     */
    public JwksUtils(final String jwksUrl) throws MalformedURLException {
        this(new URL(jwksUrl));
    }

    public JwksUtils(final URL jwksUrl) {
        this(getDefaultJWSAlgorithms(), getDefaultJWKSource(jwksUrl));
    }

    public JwksUtils(final JWKSource<SecurityContext> jwkSource) {
        this(getDefaultJWSAlgorithms(), jwkSource);
    }

    public JwksUtils(final Set<JWSAlgorithm> jwsAlgs, final JWKSource<SecurityContext> jwkSource) {
        super();
        this.keySelector = new JwksKeySelector<SecurityContext>(jwsAlgs, jwkSource);
    }

    public JwksKeySelector<SecurityContext> getKeySelector() {
        return keySelector;
    }
}
