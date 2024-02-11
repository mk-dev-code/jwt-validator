package corp.mkdev.jwt.validator;

/**
 * Exception thrown to indicate an internal error during JWT validation.
 * This exception is typically thrown when issues are encountered when accessing key server.
 */
public class JwtOperationException extends Exception {

    private static final long serialVersionUID = 1L;

    public JwtOperationException() {
        super();
    }

    public JwtOperationException(final String message, final Throwable cause, final boolean enableSuppression, final boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

    public JwtOperationException(final String message, final Throwable cause) {
        super(message, cause);
    }

    public JwtOperationException(final String message) {
        super(message);
    }

    public JwtOperationException(final Throwable cause) {
        super(cause);
    }
}
