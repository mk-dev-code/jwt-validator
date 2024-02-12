package corp.mkdev.jwt.validator;

import java.net.URL;

public final class JwtValidationFilterFactory {

    private JwtValidationFilterFactory() {
        super();
    }

    public static JwtValidationFilter build(final String httpHeader, final String keyServerUrl) throws Exception {
        return build(httpHeader, keyServerUrl, null);
    }

    public static JwtValidationFilter build(final String httpHeader, final String keyServerUrl, final String algs) throws Exception {
        return build(httpHeader, new URL(keyServerUrl), algs);
    }

    public static JwtValidationFilter build(final String httpHeader, final URL keyServerUrl, final String algs) throws Exception {
        return new JwtValidationFilter(httpHeader, JwtValidationServiceFactory.build(keyServerUrl, algs));
    }
}

