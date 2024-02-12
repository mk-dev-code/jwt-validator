package corp.mkdev.jwt.validator;

import java.net.URL;

public final class JwtValidationServiceFactory {

    private JwtValidationServiceFactory() {
        super();
    }

    public static JwtValidationService build(final String keyServerUrl) throws Exception {
        return build(keyServerUrl, null);
    }

    public static JwtValidationService build(final URL keyServerUrl) throws Exception {
        return build(keyServerUrl, null);
    }

    public static JwtValidationService build(final String keyServerUrl, final String algs) throws Exception {
        return build(new URL(keyServerUrl), algs);
    }

    public static JwtValidationService build(final URL keyServerUrl, final String algs) throws Exception {
        return new JwtValidationService(keyServerUrl, algs);
    }
}

