package corp.mkdev.jwt.validator;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class JwtValidationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = 1L;

    private final String subject;

    private final Map<String, Object> claims = new ConcurrentHashMap<String, Object>();


    public JwtValidationToken(final String subject) {
        this(Collections.emptyList(), subject);
    }

    public JwtValidationToken(final String subject, final Map<String, Object> claims) {
        this(Collections.emptyList(), subject, claims);
    }

    public JwtValidationToken(final Collection<? extends GrantedAuthority> authorities, final String subject) {
        this(authorities, subject, null);
    }

    public JwtValidationToken(final Collection<? extends GrantedAuthority> authorities, final String subject, final Map<String, Object> claims) {
        super(authorities);
        this.subject = subject;
        if (claims != null && !claims.isEmpty()) {
            this.claims.putAll(claims);
        }
    }

    @Override
    public boolean isAuthenticated() {
        return (getSubject() != null);
    }

    @Override
    public String getName() {
        return getSubject();
    }

    @Override
    public Object getCredentials() {
        return getClaims();
    }

    @Override
    public Object getDetails() {
        return getClaims();
    }

    @Override
    public Object getPrincipal() {
        return getSubject();
    }

    public String getSubject() {
        return subject;
    }

    public Map<String, Object> getClaims() {
        return claims;
    }

    public Object getClaim(final String claim) {
        return getClaims().get(claim);
    }

    @Override
    public String toString() {
        return "JwtValidationToken [Subject=" + subject + ", Claims=" + claims + "]";
    }

}

