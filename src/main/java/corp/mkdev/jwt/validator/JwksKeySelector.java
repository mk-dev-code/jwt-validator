package corp.mkdev.jwt.validator;

import java.security.Key;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;

import net.jcip.annotations.ThreadSafe;

/**
 * A custom JWSKeySelector designed to handle EdDSA keys via the selectJWSJWK method.
 *
 * <p>This key selector is specifically tailored for scenarios where the expected JWS algorithm is EdDSA,
 * and the keys cannot be directly converted to a Java Key instance. As a result, it utilizes the
 * selectJWSJWK method to filter JWK candidates based on the expected algorithm and JOSE object type verifier.
 *
 *@param <C> SecurityContext. Can be null.
 */
@ThreadSafe
public class JwksKeySelector<C extends SecurityContext> extends JWSVerificationKeySelector<C> {

    public JwksKeySelector(final Set<JWSAlgorithm> jwsAlgs, final JWKSource<C> jwkSource) {
        super(jwsAlgs, jwkSource);
    }

    public List<Key> selectJWSKeys(final JWSHeader jwsHeader) throws KeySourceException {
        return selectJWSKeys(jwsHeader, null);
    }

    public List<JWK> selectJWSJWK(final JWSHeader jwsHeader) throws KeySourceException {
        return selectJWSJWK(jwsHeader, null);
    }

    public List<JWK> selectJWSJWK(final JWSHeader jwsHeader, final C context) throws KeySourceException {
        if (!isAllowed(jwsHeader.getAlgorithm())) {
            return Collections.emptyList();
        }
        final JWKMatcher jwkMatcher = createJWKMatcher(jwsHeader);
        if (jwkMatcher == null) {
            return Collections.emptyList();
        }
        return getJWKSource().get(new JWKSelector(jwkMatcher), context);
    }
}
