package corp.mkdev.jwt.validator;

import java.net.URL;
import java.security.KeyPair;
import java.util.Date;
import java.util.List;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.AsymmetricJWK;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.SecretJWK;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;

import corp.mkdev.jwt.jwk.JwksProcessor;

public class JwtValidationService {

    private final JwksProcessor jwksProcessor;

    private final DefaultJWSVerifierFactory jwsVerifierFactory = new DefaultJWSVerifierFactory();

    public JwtValidationService(final URL keyServerUrl, final String algs) throws Exception {
        if (algs == null) {
            this.jwksProcessor = new JwksProcessor(keyServerUrl);
        } else {
            this.jwksProcessor = new JwksProcessor(keyServerUrl, algs);
        }
    }

    public JwtValidationToken validate(final String token) throws Exception {
        if (token == null || token.length() == 0) {
            throw new JwtValidationException("JWT is null or empty");
        }

        JWT jwt = null;
        try {
            jwt = JWTParser.parse(token);
        } catch (final Exception e) {
            throw new JwtValidationException("JWT parse failed", e);
        }
        if (jwt == null) {
            throw new JwtValidationException("Parsed JWT is null");
        }
        if (!(jwt instanceof SignedJWT)) {
            throw new JwtValidationException("JWT is not signed");
        }
        if (jwt.getHeader() == null) {
            throw new JwtValidationException("JWT Header is null");
        }
        if (!(jwt.getHeader() instanceof JWSHeader)) {
            throw new JwtValidationException("JWT Header is not JWSHeader");
        }
        final JWSHeader jwsHeader = (JWSHeader) jwt.getHeader();
        final List<JWK> keyList;
        try {
            keyList = getJwksProcessor().selectJWSJWK(jwsHeader);
        } catch (final Exception e) {
            throw new JwtOperationException("Key fetch failed", e);
        }
        if (keyList == null) {
            throw new JwtValidationException("Key not found");
        }
        for (final JWK jwk:keyList) {
            final JWSVerifier verifier;
            try {
                if (JWSAlgorithm.EdDSA.equals(jwsHeader.getAlgorithm()) && jwk instanceof OctetKeyPair) {
                    verifier = new Ed25519Verifier((OctetKeyPair) jwk.toPublicJWK());
                } else if (jwk instanceof AsymmetricJWK) {
                    final KeyPair kp = ((AsymmetricJWK) jwk).toKeyPair();
                    verifier = jwsVerifierFactory.createJWSVerifier(jwsHeader, kp.getPublic());
                } else if (jwk instanceof SecretJWK) {
                    verifier = jwsVerifierFactory.createJWSVerifier(jwsHeader, ((SecretJWK) jwk).toSecretKey());
                } else {
                    //TODO if needed
                    continue;
                }
            } catch (final Exception e) {
                continue;
            }
            boolean verified;
            try {
                final SignedJWT signedJWT = (SignedJWT) jwt;
                verified = signedJWT.verify(verifier);
            } catch (final Exception e) {
                throw new JwtOperationException("Sign verification error");
            }
            if (!verified) {
                throw new JwtValidationException("Sign verification failed");
            }
            if (jwt.getJWTClaimsSet() == null) {
                return new JwtValidationToken(jwt.getJWTClaimsSet().getSubject());
            }
            final Date exp = jwt.getJWTClaimsSet().getExpirationTime();
            if (exp != null && exp.before(new Date())) {
                throw new JwtValidationException("Expired token");
            }
            return new JwtValidationToken(jwt.getJWTClaimsSet().getSubject(), jwt.getJWTClaimsSet().getClaims());
        }
        throw new JwtValidationException("Signing key not found");
    }

    protected JwksProcessor getJwksProcessor() {
        return jwksProcessor;
    }
}

