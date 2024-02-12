package corp.mkdev.jwt.validator;

import static net.jadler.Jadler.closeJadler;
import static net.jadler.Jadler.initJadler;
import static net.jadler.Jadler.onRequest;
import static net.jadler.Jadler.port;
import static org.junit.Assert.assertNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URL;
import java.util.Arrays;
import java.util.Date;
import java.util.UUID;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class JwtValidationServiceTest {

    private static final String kid = UUID.randomUUID().toString();

    private static URL jwkSetURL;

    private static OctetKeyPair jwkEdDSA;

    @BeforeAll
    public static void setup() throws Exception {
        initJadler();
        jwkEdDSA = new OctetKeyPairGenerator(Curve.Ed25519)
                .algorithm(JWSAlgorithm.EdDSA)
                .keyID(kid)
                .generate();


        final JWKSet jwkSet = new JWKSet(Arrays.asList(jwkEdDSA.toPublicJWK()));

        jwkSetURL = new URL("http://localhost:" + port() + "/jwks.json");
        onRequest()
        .havingMethodEqualTo("GET")
        .havingPathEqualTo("/jwks.json")
        .respond()
        .withStatus(200)
        .withHeader("Content-Type", "application/json")
        .withBody(jwkSet.toJSONObject(true).toString());

    }

    @AfterAll
    public static void cleanup() {
        closeJadler();
    }

    /**
     * Test the {@link JwtValidationService#validate(String)} method in a happy path scenario.
     *
     * <p>This test method verifies that the {@code validate} method of the {@link JwtValidationService}
     * class behaves correctly when provided with a valid JWT. It covers the successful validation
     * of a JWT, ensuring that the method returns without throwing any exceptions.
     * @see JwtValidationService
     * @see JwtValidationService#validate(String)
     */
    @Test
    @Order(1)
    public void testJwtValidatorValidateHappy() throws Exception {
        final String subject="Subject:" + UUID.randomUUID().toString();
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

        final JWSSigner signer = new Ed25519Signer(jwkEdDSA);

        signedJWT.sign(signer);

        assertEquals(JWSObject.State.SIGNED, signedJWT.getState());
        assertNotNull(signedJWT.getSignature());

        final String serializedJWT = signedJWT.serialize();

        signedJWT = SignedJWT.parse(serializedJWT);
        assertEquals(serializedJWT, signedJWT.getParsedString());

        assertEquals(JWSObject.State.SIGNED, signedJWT.getState());
        assertNotNull(signedJWT.getSignature());
        assertTrue(sigInput.equals(Base64URL.encode(signedJWT.getSigningInput())));

        final JwtValidationService jwtValidator=new JwtValidationService(jwkSetURL);

        final JwtValidationToken jwtValidationToken = jwtValidator.validate(serializedJWT);
        assertEquals(subject, jwtValidationToken.getSubject());

    }

    @Test
    @Order(10)
    public void testJwtValidatorValidateNegativeDifferentKeyForSameKeyId() throws Exception {
        final String subject="Subject:" + UUID.randomUUID().toString();
        final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(subject)
                .expirationTime(new Date(System.currentTimeMillis()-60000))
                .build();

        final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA).
                keyID(kid).
                build();

        final SignedJWT signedJWT = new SignedJWT(header, claimsSet);

        final JWSSigner signer = new Ed25519Signer(new OctetKeyPairGenerator(Curve.Ed25519)
            .algorithm(JWSAlgorithm.EdDSA)
            .keyID(kid)
            .generate());
        signedJWT.sign(signer);
        final String serializedJWT = signedJWT.serialize();
        final JwtValidationService jwtValidator=new JwtValidationService(jwkSetURL);
        assertThrows(JwtValidationException.class, ()-> jwtValidator.validate(serializedJWT));
    }

    @Test
    @Order(12)
    public void testJwtValidatorValidateNegativeExpired() throws Exception {
        final String subject="Subject:" + UUID.randomUUID().toString();
        final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(subject)
                .expirationTime(new Date(System.currentTimeMillis()-60000))
                .build();

        final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA).
                keyID(kid).
                build();

        final SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        final JWSSigner signer = new Ed25519Signer(jwkEdDSA);
        signedJWT.sign(signer);
        final String serializedJWT = signedJWT.serialize();
        final JwtValidationService jwtValidator=new JwtValidationService(jwkSetURL);
        assertThrows(JwtValidationException.class, ()-> jwtValidator.validate(serializedJWT));
    }

    //Run last
    @Test
    @Order(100)
    public void testJwtValidatorValidateNegativeKeyServerNotResponding() throws Exception {
        closeJadler();
        final String subject="Subject:" + UUID.randomUUID().toString();
        final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(subject)
                .expirationTime(new Date(System.currentTimeMillis()-60000))
                .build();

        final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA).
                keyID(kid).
                build();

        final SignedJWT signedJWT = new SignedJWT(header, claimsSet);

        final JWSSigner signer = new Ed25519Signer(new OctetKeyPairGenerator(Curve.Ed25519)
            .algorithm(JWSAlgorithm.EdDSA)
            .keyID(kid)
            .generate());
        signedJWT.sign(signer);
        final String serializedJWT = signedJWT.serialize();
        final JwtValidationService jwtValidator=new JwtValidationService(jwkSetURL);
        assertThrows(JwtOperationException.class, ()-> jwtValidator.validate(serializedJWT));
    }
}
