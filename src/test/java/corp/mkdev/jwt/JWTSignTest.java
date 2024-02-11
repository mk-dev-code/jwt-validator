package corp.mkdev.jwt;

import static org.junit.Assert.assertNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Unit tests for signing and verifying EdDSA and RSA JWTs.
 */
public class JWTSignTest {

    @Test
    public void testSignAndVerifyEdDSA() throws Exception {

        final String kid=UUID.randomUUID().toString();
        final String subject=UUID.randomUUID().toString();

        final OctetKeyPair jwk = new OctetKeyPairGenerator(Curve.Ed25519)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(kid)
                .issueTime(new Date())
                .generate();

        final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(subject)
                .expirationTime(new Date(System.currentTimeMillis()+60000))
                .build();

        final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA).
                keyID(kid).
                build();

        SignedJWT signedJWT = new SignedJWT(header, claimsSet);

        assertEquals(JWSObject.State.UNSIGNED, signedJWT.getState());
        assertEquals(header, signedJWT.getHeader());
        assertEquals(subject, signedJWT.getJWTClaimsSet().getSubject());
        assertNull(signedJWT.getSignature());

        final Base64URL sigInput = Base64URL.encode(signedJWT.getSigningInput());

        final JWSSigner signer = new Ed25519Signer(jwk);

        signedJWT.sign(signer);

        assertEquals(JWSObject.State.SIGNED, signedJWT.getState());
        assertNotNull(signedJWT.getSignature());

        final String serializedJWT = signedJWT.serialize();

        signedJWT = SignedJWT.parse(serializedJWT);
        assertEquals(serializedJWT, signedJWT.getParsedString());

        assertEquals(JWSObject.State.SIGNED, signedJWT.getState());
        assertNotNull(signedJWT.getSignature());
        assertTrue(sigInput.equals(Base64URL.encode(signedJWT.getSigningInput())));

        final JWSVerifier verifier = new Ed25519Verifier(jwk.toPublicJWK());
        assertTrue(signedJWT.verify(verifier));
    }

    @Test
    public void testSignAndVerifyRSA() throws Exception {

        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);

        final KeyPair kp = kpg.genKeyPair();
        final RSAPublicKey publicKey = (RSAPublicKey) kp.getPublic();
        final RSAPrivateKey privateKey = (RSAPrivateKey) kp.getPrivate();

        final String kid = UUID.randomUUID().toString();
        final String subject = UUID.randomUUID().toString();

        final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject(subject).expirationTime(new Date(System.currentTimeMillis() + 60000)).build();

        final JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(kid).build();

        SignedJWT signedJWT = new SignedJWT(jwsHeader, claimsSet);

        assertEquals(JWSObject.State.UNSIGNED, signedJWT.getState());
        assertEquals(jwsHeader, signedJWT.getHeader());
        assertEquals(subject, signedJWT.getJWTClaimsSet().getSubject());
        assertNull(signedJWT.getSignature());

        final Base64URL sigInput = Base64URL.encode(signedJWT.getSigningInput());

        final JWSSigner signer = new RSASSASigner(privateKey);

        signedJWT.sign(signer);

        assertEquals(JWSObject.State.SIGNED, signedJWT.getState());
        assertNotNull(signedJWT.getSignature());

        final String serializedJWT = signedJWT.serialize();

        signedJWT = SignedJWT.parse(serializedJWT);
        assertEquals(serializedJWT, signedJWT.getParsedString());

        assertEquals(JWSObject.State.SIGNED, signedJWT.getState());
        assertNotNull(signedJWT.getSignature());
        assertTrue(sigInput.equals(Base64URL.encode(signedJWT.getSigningInput())));

        final JWSVerifier verifier = new RSASSAVerifier(publicKey);
        assertTrue(signedJWT.verify(verifier));
    }

}
