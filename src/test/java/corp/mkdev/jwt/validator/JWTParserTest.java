package corp.mkdev.jwt.validator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;

public class JWTParserTest {

    @Test
    public void testDemoToken() throws Exception {

        final String s = "eyJraWQiOiI1M2FmNGE4YS1hMTNmLTRhYWYtYjJhZS1jNTBiYzRmMTZhZjYiLCJhbGciOiJFZERTQSJ9"
                + "."
                + "eyJzdWIiOiI2NTliZWIyOTRmMTI3NDQ5MDIxZDg4YTUiLCJleHAiOjE3MDQ3MjUzMzMsImlhdCI6MTcwNDcyNTAzMywianRpIjoiNTNmMDA3ZDAtODcxMC00MDI5LTgyOTktMDYwYTc0ZWUwMjMzIn0="
                + "."
                + "4piPxUZ7785I8PXUDb2JSnw03nirwp7CLgnWP3sbjWTHrARJjK-_0uKgCP00WUoAplMun7kcNLZqyD4nCyR7Dg"
                ;

        final JWT jwt = JWTParser.parse(s);
        assertNotNull(jwt);
        assertInstanceOf(SignedJWT.class,jwt);
        assertNotNull(jwt.getHeader());
        assertInstanceOf(JWSHeader.class,jwt.getHeader());
        assertNotNull(jwt.getHeader().getAlgorithm());
        assertEquals(jwt.getHeader().getAlgorithm().getName(), "EdDSA");
        assertEquals(((JWSHeader)jwt.getHeader()).getKeyID(), "53af4a8a-a13f-4aaf-b2ae-c50bc4f16af6");
        assertNotNull(jwt.getJWTClaimsSet());
        assertEquals(jwt.getJWTClaimsSet().getSubject(),"659beb294f127449021d88a5");
    }
}
