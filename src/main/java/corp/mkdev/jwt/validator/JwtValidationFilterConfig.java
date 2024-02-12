package corp.mkdev.jwt.validator;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

@Component
public final class JwtValidationFilterConfig {

    @Bean
    JwtValidationFilter buildJwtValidationFiter(
            final @Value("${jwt.validation.header}") String httpHeader,
            final @Value("${jwt.validation.jks.url}") String keyServerUrl,
            final @Value("${jwt.validation.algs}") String algs
            ) throws Exception {
        return JwtValidationFilterFactory.build(httpHeader, keyServerUrl, algs);
    }
}

