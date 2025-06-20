package com.qiyuesuo.decrypt.hashutils;

public class ConfidentialException
        extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public ConfidentialException() {
    }

    public ConfidentialException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

    public ConfidentialException(String message, Throwable cause) {
        super(message, cause);
    }

    public ConfidentialException(String message) {
        super(message);
    }

    public ConfidentialException(Throwable cause) {
        super(cause);
    }
}
