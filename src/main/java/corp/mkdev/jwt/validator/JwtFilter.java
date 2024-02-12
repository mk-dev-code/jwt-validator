package corp.mkdev.jwt.validator;

import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtFilter extends OncePerRequestFilter {

    private static final Log LOG = LogFactory.getLog(JwtFilter.class);

    private final JwtValidationService jwtValidator;

    public JwtFilter(final JwtValidationService jwtValidator) {
        super();
        this.jwtValidator = jwtValidator;
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response, final FilterChain chain)
            throws ServletException, IOException {
        try {
            final JwtValidationToken validationToken = jwtValidator.validate(request);
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
}
