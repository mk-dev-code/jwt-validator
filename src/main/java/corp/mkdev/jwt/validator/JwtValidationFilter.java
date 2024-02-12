package corp.mkdev.jwt.validator;

import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JwtValidationFilter extends OncePerRequestFilter {

    private static final Log LOG = LogFactory.getLog(JwtValidationFilter.class);

    private final String httpHeader;

    private final JwtValidationService jwtValidatorService;

    public JwtValidationFilter(final String httpHeader, final JwtValidationService jwtValidatorService) {
        super();
        if (httpHeader == null || httpHeader.length() == 0) {
            throw new IllegalArgumentException("Invalid header");
        }
        if (jwtValidatorService == null) {
            throw new IllegalArgumentException("Invalid Validator Service");
        }
        this.httpHeader = httpHeader;
        this.jwtValidatorService = jwtValidatorService;
        LOG.info("Starting JwtValidationFilter with [HttpHeader:" + httpHeader + "] [JwtValidator:" + jwtValidatorService + "]");
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response, final FilterChain chain)
            throws ServletException, IOException {
        if (request == null) {
            chain.doFilter(request, response);
            return;
        }
        final String jwt = request.getHeader(getHttpHeader());
        if (jwt == null || jwt.length() == 0) {
            chain.doFilter(request, response);
            return;
        }
        try {
            final JwtValidationToken validationToken = jwtValidatorService.validate(jwt);
            SecurityContextHolder.getContext().setAuthentication(validationToken);
            chain.doFilter(request, response);
            return;
        } catch (final JwtValidationException e) {
            LOG.warn("JWT validation failed. RemoteAddr:" + request.getRemoteAddr() + " RemotePort:" + request.getRemotePort() + " Reason:" + e);
            chain.doFilter(request, response);
            return;
        } catch (final Exception e) {
            LOG.warn("JWT validation error. RemoteAddr:" + request.getRemoteAddr() + " RemotePort:" + request.getRemotePort() + " Error:" + e);
            chain.doFilter(request, response);
            return;
        }
    }

    public String getHttpHeader() {
        return httpHeader;
    }

}
