package com.sap.fontus.exceptions;

public class FontusRuntimeException extends RuntimeException {
    public FontusRuntimeException(String message) {
        super(message);
    }

    public FontusRuntimeException(String message, Throwable cause) {
        super(message, cause);
    }

    public FontusRuntimeException(Throwable cause) {
        super(cause);
    }
}
