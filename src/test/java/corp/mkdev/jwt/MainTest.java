package corp.mkdev.jwt;

import corp.mkdev.jwt.jwk.JwksProcessorTest;
import corp.mkdev.jwt.validator.JwtValidatorTest;

public class MainTest {

    public static void main(final String[] args) throws Exception{
        testValidator();
    }

    protected static void testValidator() throws Exception {
        JwtValidatorTest.setup();
        try {
            new JwtValidatorTest().testJwtValidatorValidateHappy();
        }finally {
            JwtValidatorTest.cleanup();
        }
    }

    protected static void testProcessor() throws Exception {
        JwksProcessorTest.setup();
        try {
            new JwksProcessorTest().testJwksProcessorAlgRS256();
            //new JwksProcessorTest().testJwksProcessorAlgEdDSA();
        }finally {
            JwksProcessorTest.cleanup();
        }
    }
}
