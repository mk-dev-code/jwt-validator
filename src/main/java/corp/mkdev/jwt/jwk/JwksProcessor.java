package corp.mkdev.jwt.jwk;

import java.net.URL;
import java.security.Key;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * Class for handling JSON Web Key Set (JWKS) operations.
 *
 * <p>This class provides functionality to fetch and cache public keys from a JWKS endpoint.
 * It is designed to be used in conjunction with JWT (JSON Web Token) validation processes.
 *
 */
public class JwksProcessor {

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
     * Returns a set of default JSON Web Signature (JWS) algorithms.
     */
    public static Set<JWSAlgorithm> parseJWSAlgorithms(final String algs) throws IllegalArgumentException {
        if (algs == null || algs.length() == 0) {
            throw new IllegalArgumentException("Argument is null or empty");
        }
        final String separator;
        if (algs.contains(" ")) {
            separator = " ";
        } else {
            separator = ",";
        }
        final Set<JWSAlgorithm> ret = new LinkedHashSet<>();
        final String[] algsSplit = algs.split(separator);
        for (final String alg:algsSplit) {
            ret.add(JWSAlgorithm.parse(alg));
        }
        return ret;
    }

    /**
     * Returns a default JSON Web Key (JWK) source configured with the provided JWKS (JSON Web Key Set) endpoint URL.

     * @param jwksUrl The URL pointing to the JWKS endpoint.
     * @return A JWK source configured with the provided JWKS URL.
     *
     */
    public static JWKSource<SecurityContext> buildDefaultJWKSource(final URL jwksUrl) throws Exception {
        if (jwksUrl == null) {
            throw new IllegalArgumentException("URL is null");
        }
        return JWKSourceBuilder
                .create(jwksUrl)
                .build();
    }

    /**
     * Constructs a JwksUtils instance using the provided JWKS endpoint URL.
     *
     * @param jwksUrl The URL pointing to the JWKS endpoint.
     * @throws Exception If there is an issue parsing the jwksUrl.
     */
    public JwksProcessor(final String jwksUrl) throws Exception {
        this(new URL(jwksUrl));
    }

    public JwksProcessor(final String jwksUrl, final String algs) throws Exception {
        this(new URL(jwksUrl), algs);
    }

    public JwksProcessor(final URL jwksUrl) throws Exception {
        this(getDefaultJWSAlgorithms(), buildDefaultJWKSource(jwksUrl));
    }
    public JwksProcessor(final URL jwksUrl, final String algs) throws Exception {
        this(parseJWSAlgorithms(algs), buildDefaultJWKSource(jwksUrl));
    }

    public JwksProcessor(final JWKSource<SecurityContext> jwkSource) {
        this(getDefaultJWSAlgorithms(), jwkSource);
    }

    public JwksProcessor(final Set<JWSAlgorithm> jwsAlgs, final JWKSource<SecurityContext> jwkSource) {
        super();
        this.keySelector = new JwksKeySelector<SecurityContext>(jwsAlgs, jwkSource);
    }

    public JwksKeySelector<SecurityContext> getKeySelector() {
        return keySelector;
    }

    public List<Key> selectJWSKeys(final JWSHeader jwsHeader) throws KeySourceException {
        return getKeySelector().selectJWSKeys(jwsHeader, null);
    }

    public List<JWK> selectJWSJWK(final JWSHeader jwsHeader) throws KeySourceException {
        return getKeySelector().selectJWSJWK(jwsHeader, null);
    }
}
