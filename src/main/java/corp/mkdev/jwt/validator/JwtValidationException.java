package corp.mkdev.jwt.validator;

/**
 * Exception thrown to indicate an error during JWT validation.
 * This exception is typically thrown when issues are encountered during the validation
 * process, such as invalid signatures, expired tokens, or missing required claims.
 */
public class JwtValidationException extends Exception {

    private static final long serialVersionUID = 1L;

    public JwtValidationException() {
        super();
    }

    public JwtValidationException(final String message, final Throwable cause, final boolean enableSuppression, final boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

    public JwtValidationException(final String message, final Throwable cause) {
        super(message, cause);
    }

    public JwtValidationException(final String message) {
        super(message);
    }

    public JwtValidationException(final Throwable cause) {
        super(cause);
    }
}
