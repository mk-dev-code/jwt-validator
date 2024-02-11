package corp.mkdev.jwt.validator;

import static net.jadler.Jadler.closeJadler;
import static net.jadler.Jadler.initJadler;
import static net.jadler.Jadler.onRequest;
import static net.jadler.Jadler.port;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.proc.SecurityContext;

public class JwksUtilsTest {

    private static final SecurityContext ctx = null;

    private static final String kidRSA = UUID.randomUUID().toString();

    private static final String kidEdDSA = UUID.randomUUID().toString();

    private static URL jwkSetURL;

    private static RSAKey jwkRSA;

    private static OctetKeyPair jwkEdDSA;

    @BeforeAll
    public static void setup() throws Exception {
        initJadler();
        final KeyPairGenerator pairGen = KeyPairGenerator.getInstance("RSA");
        pairGen.initialize(2048);
        KeyPair keyPair = pairGen.generateKeyPair();


        jwkRSA = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .algorithm(JWSAlgorithm.RS256)
                .keyID(kidRSA)
                .build();

        keyPair = pairGen.generateKeyPair();

        jwkEdDSA = new OctetKeyPairGenerator(Curve.Ed25519)
                .algorithm(JWSAlgorithm.EdDSA)
                .keyID(kidEdDSA)
                .generate();


        final JWKSet jwkSet = new JWKSet(Arrays.asList(jwkEdDSA.toPublicJWK(),jwkRSA.toPublicJWK()));

        jwkSetURL = new URL("http://localhost:" + port() + "/jwks.json");
        System.out.println(jwkSet.toJSONObject(true).toString());
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

    @Test
    public void testJwksUtilsConstruction() {
        try {
            final JwksUtils jwksUtils = new JwksUtils(jwkSetURL);
            assertNotNull(jwksUtils.getKeySelector());
        } catch (final Exception e) {
            fail("Exception: " + e.getMessage());
        }
    }

    @Test
    public void testJwksUtilsConstructionWithInvalidUrl() {
        assertThrows(MalformedURLException.class, () -> new JwksUtils("invalid url"));
    }

    @Test
    public void testJwksUtilsAlgEdDSA() throws Exception {
        final JwksUtils jwksUtils = new JwksUtils(jwkSetURL);
        assertTrue(jwksUtils.getKeySelector().isAllowed(JWSAlgorithm.EdDSA));
    }

    @Test
    public void testJwksUtilsAlgRS256() throws Exception {
        final JwksUtils jwksUtils = new JwksUtils(jwkSetURL);
        assertTrue(jwksUtils.getKeySelector().isAllowed(JWSAlgorithm.RS256));
    }

    @Test
    public void testJwksUtilsCheckEdDSA() throws Exception {
        final JwksUtils jwksUtils = new JwksUtils(jwkSetURL);
        assertNotNull(jwksUtils.getKeySelector());

        final JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID(kidEdDSA).build();
        List<JWK> keyList=null;
        try {
            keyList =jwksUtils.getKeySelector().selectJWSJWK(jwsHeader);
        } catch (final Exception e) {
            fail("Exception: " + e.getMessage());
            return;
        }

        assertNotNull(keyList);
        assertTrue(keyList.size()==1);

        final JWK key = keyList.get(0);
        assertNotNull(key);
        assertNotNull(key.getAlgorithm());

        assertEquals("EdDSA", key.getAlgorithm().getName());
        assertInstanceOf(OctetKeyPair.class, key);

        final OctetKeyPair okp = (OctetKeyPair) key;
        assertEquals(okp.getX(), jwkEdDSA.getX());
    }

    @Test
    public void testJwksUtilsCheckRSA() throws Exception {

        final JwksUtils jwksUtils = new JwksUtils(jwkSetURL);
        assertNotNull(jwksUtils.getKeySelector());

        final JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(kidRSA).build();

        List<Key> keyList=null;
        try {
            keyList =jwksUtils.getKeySelector().selectJWSKeys(jwsHeader, ctx);
        } catch (final Exception e) {
            fail("Exception: " + e.getMessage());
            return;
        }
        assertNotNull(keyList);
        assertTrue(keyList.size()==1);

        final Key key = keyList.get(0);
        assertEquals("RSA", key.getAlgorithm());
        assertEquals("X.509", key.getFormat());
        final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key.getEncoded());
        assertNotNull(keySpec);

        final KeyFactory kfRSA = KeyFactory.getInstance("RSA");
        final RSAKey rsaKeyPub = new RSAKey.Builder((RSAPublicKey) kfRSA.generatePublic(keySpec)).build();

        assertEquals(jwkRSA.getModulus(), rsaKeyPub.getModulus());
        assertEquals(jwkRSA.getPublicExponent(), rsaKeyPub.getPublicExponent());
    }

}
